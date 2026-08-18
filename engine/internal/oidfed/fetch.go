package oidfed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/safedial"
)

// Fetching Entity Statements, OpenID Federation 1.0 §8.1 and §9.
//
// # Why this file is mostly refusals
//
// Chain building walks a graph an attacker partly controls. We fetch an entity's
// configuration, read `authority_hints` OUT OF IT, and fetch those — so every
// URL after the first is one the previous document chose. That is a
// server-side request forgery primitive by construction, and it is the reason
// this uses safedial rather than http.DefaultClient: the check has to happen at
// DIAL time, because a hostname that resolves publicly when validated and to
// 169.254.169.254 when connected is DNS rebinding, not a parsing problem.
//
// The other refusals bound work rather than access: a hostile or broken
// federation can otherwise present an unbounded graph, and a resolver that walks
// it is a denial of service against itself.

const (
	// MaxStatementBytes bounds one fetched statement. Entity Statements carry a
	// key set and metadata; a megabyte is already implausible.
	MaxStatementBytes = 256 << 10

	// MaxChainDepth bounds how far up a chain may be walked.
	//
	// §6.2.1 defines a max_path_length constraint that a Trust Anchor may impose
	// on its subtree. This is the local ceiling that applies when nobody has
	// imposed one: without it, a cycle of entities that name each other as
	// superiors is walked forever.
	MaxChainDepth = 10

	// FetchTimeout bounds one HTTP request.
	FetchTimeout = 10 * time.Second
)

// Fetcher retrieves Entity Statements over HTTP.
type Fetcher struct {
	// HTTP is SSRF-guarded. Nil uses safedial's client, which is the only
	// correct default here -- see the file comment.
	HTTP *http.Client

	// AllowLoopbackForTesting disables the address and scheme guards.
	//
	// It exists because the guards are correct and therefore untestable against
	// a local server: httptest binds loopback over plain http, and both are
	// refused -- as they should be, since an entity identifier is required to be
	// https (§9) and a loopback fetch is the SSRF this file is written against.
	//
	// Named at this length on purpose. A field called `Insecure` or `SkipVerify`
	// gets set in a config file by somebody solving a different problem; this
	// one cannot be set without writing out what it does.
	AllowLoopbackForTesting bool
}

func (f *Fetcher) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return safedial.Client(FetchTimeout)
}

// EntityConfigurationOf fetches an entity's self-published configuration (§9).
func (f *Fetcher) EntityConfigurationOf(ctx context.Context, entityID string) (Statement, error) {
	u := strings.TrimRight(entityID, "/") + WellKnownPath
	if !f.AllowLoopbackForTesting {
		var err error
		if u, err = ConfigurationURL(entityID); err != nil {
			return Statement{}, err
		}
	}
	st, err := f.get(ctx, u)
	if err != nil {
		return Statement{}, fmt.Errorf("fetching the entity configuration of %s: %w",
			entityID, err)
	}
	// §3.1.1: an Entity Configuration is a statement about itself. Checked here
	// as well as in ValidateChain, because a caller that fetches one directly --
	// to read `authority_hints`, say -- gets the guarantee too.
	if st.Issuer != st.Subject {
		return Statement{}, fmt.Errorf("%s served a statement with iss %q and sub %q; "+
			"an Entity Configuration has them identical", entityID, st.Issuer, st.Subject)
	}
	if st.Issuer != strings.TrimRight(entityID, "/") {
		// The document must be about the entity we asked. Otherwise a superior
		// can hand back somebody else's configuration and we walk their chain.
		return Statement{}, fmt.Errorf("%s served a configuration for %q",
			entityID, st.Issuer)
	}
	return st, nil
}

// SubordinateStatement fetches a superior's statement about a subordinate
// (§8.1).
//
// fetchEndpoint comes from the superior's own Entity Configuration metadata,
// which is why it is passed in rather than derived: the caller has already
// validated that configuration and this function should not re-decide where to
// go from a document it has not checked.
func (f *Fetcher) SubordinateStatement(ctx context.Context, fetchEndpoint, sub string) (Statement, error) {
	if !f.AllowLoopbackForTesting {
		if err := ValidateEntityID(sub); err != nil {
			return Statement{}, err
		}
	}
	u, err := url.Parse(fetchEndpoint)
	if err != nil || (u.Scheme != "https" && !f.AllowLoopbackForTesting) {
		return Statement{}, fmt.Errorf("the federation fetch endpoint %q is not an "+
			"https URL", fetchEndpoint)
	}
	q := u.Query()
	q.Set("sub", sub)
	u.RawQuery = q.Encode()

	st, err := f.get(ctx, u.String())
	if err != nil {
		return Statement{}, fmt.Errorf("fetching the subordinate statement for %s: %w",
			sub, err)
	}
	// It must be about who we asked about. A superior returning a statement for
	// a different subject is how a chain gets rerouted to an entity we never
	// enquired about.
	if st.Subject != strings.TrimRight(sub, "/") {
		return Statement{}, fmt.Errorf("asked for a statement about %q and received "+
			"one about %q", sub, st.Subject)
	}
	return st, nil
}

// get retrieves and parses one Entity Statement.
func (f *Fetcher) get(ctx context.Context, rawURL string) (Statement, error) {
	// Checked before the request as well as at dial time. This catches the
	// obvious cases with a clear message; safedial's Control catches the ones
	// that only appear once DNS has resolved.
	if !f.AllowLoopbackForTesting {
		if err := safedial.CheckURL(rawURL); err != nil {
			return Statement{}, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Statement{}, err
	}
	req.Header.Set("Accept", MediaType)

	resp, err := f.client().Do(req)
	if err != nil {
		return Statement{}, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Statement{}, fmt.Errorf("%s answered %d", rawURL, resp.StatusCode)
	}

	// Bounded before it is read, not after. A body limit applied to an
	// already-buffered response is not a limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxStatementBytes+1))
	if err != nil {
		return Statement{}, err
	}
	if len(body) > MaxStatementBytes {
		return Statement{}, fmt.Errorf("%s returned more than %d bytes",
			rawURL, MaxStatementBytes)
	}

	return ParseStatement(string(body))
}

// ParseStatement decodes a compact JWS into a Statement WITHOUT verifying it.
//
// Verification happens in ValidateChain, against keys that are only known once
// the whole chain is assembled -- so parsing and verifying are necessarily
// separate steps here. The name says "parse" rather than "read" so that a caller
// cannot mistake the result for something trustworthy: nothing in the returned
// Statement has been checked beyond being well-formed JSON in the payload.
// b64Payload decodes a compact JWS payload segment.
func b64Payload(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

func ParseStatement(compact string) (Statement, error) {
	compact = strings.TrimSpace(compact)
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Statement{}, fmt.Errorf("not a compact JWS (%d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Statement{}, fmt.Errorf("the payload is not base64url: %w", err)
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return Statement{}, fmt.Errorf("the claims did not parse: %w", err)
	}
	st.Raw = compact
	return st, nil
}

// AuthorityHintsOf reads the `authority_hints` claim from a parsed statement's
// payload.
//
// Separate from Statement because the claim only appears in Entity
// Configurations, and putting it on the shared struct would invite a caller to
// read it from a Subordinate Statement where it means nothing.
func AuthorityHintsOf(st Statement, allowLoopback bool) ([]string, error) {
	parts := strings.Split(st.Raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		AuthorityHints []string `json:"authority_hints"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	// §3.1.2 forbids the empty array. A statement carrying one is malformed, and
	// treating it as "no superiors" would silently accept a document that says
	// something the specification does not allow it to say.
	if claims.AuthorityHints != nil && len(claims.AuthorityHints) == 0 {
		return nil, fmt.Errorf("authority_hints is the empty array, which section " +
			"3.1.2 forbids")
	}
	// Each hint is an Entity Identifier and is checked as one -- failing here,
	// with the hint named, beats failing later inside a fetch with a transport
	// error that does not say which document sent us there.
	if !allowLoopback {
		for _, h := range claims.AuthorityHints {
			if err := ValidateEntityID(h); err != nil {
				return nil, fmt.Errorf("authority hint %q: %w", h, err)
			}
		}
	}
	return claims.AuthorityHints, nil
}
