// Package clients is the OAuth client registry.
package clients

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"signari.dev/engine/internal/clientauth"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound means no such client_id.
var ErrNotFound = errors.New("client not found")

// Client is the registry view of a relying party.
//
// Note what is NOT here: any notion of a cached snapshot. Per ADR-007, whether a
// client is enabled is a security-negative decision and is read from the database
// on the request path. A disabled client must stop working on the very next
// request, not at the next config refresh.
type Client struct {
	ClientID      string
	OrgID         string
	DisplayName   string
	Type          string // "confidential" | "public"
	SecretHash    string
	Enabled       bool
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	RequirePKCE   bool
	// FirstParty clients skip the consent screen -- see migration 0010. It
	// suppresses only that question; every other check still applies.
	FirstParty bool

	// IssuerAlias, when set, is a REGISTERED legacy issuer this client's tokens
	// are minted under, so an application migrated from another provider keeps
	// working without being reconfigured. Cutover only -- see migration 0015.
	IssuerAlias string

	// MayExchange and ExchangeAudiences gate RFC 8693. Off by default: exchange
	// transfers privilege, so it is granted deliberately or not at all.
	MayExchange       bool
	ExchangeAudiences []string

	// Mutual-TLS, RFC 8705. Exactly one of the first four is set; the database
	// enforces that with a CHECK constraint.
	TLSSubjectDN   string
	TLSSANDNS      string
	TLSSANURI      string
	TLSThumbprint  []byte
	TLSBoundTokens bool

	// AllowHybrid permits response_type "code id_token" for this client.
	//
	// Off unless somebody turned it on. It exists for applications being
	// migrated in that cannot be changed as a precondition of the migration; an
	// estate should end up with it off everywhere.
	AllowHybrid  bool
	PKCEMethods  []string
	IDTokenAlg   string
	RedirectURIs []string
	RefreshTTL   int
}

// RefreshTokenTTLSeconds is the client's configured refresh lifetime, with a
// sane floor so a misconfigured zero does not mint tokens that expire instantly.
func (c *Client) RefreshTokenTTLSeconds() int {
	if c.RefreshTTL <= 0 {
		return 30 * 24 * 3600
	}
	return c.RefreshTTL
}

// Store reads clients. It takes the querier rather than a pool so callers can
// pass a transaction and get a consistent read alongside the rest of a request.
type Store struct{ q pgx.Tx }

// Querier is the subset of pgx we need, satisfied by both *pgx.Conn and pgx.Tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Lookup fetches a client and its registered redirect URIs.
//
// The redirect URIs come back as a set for EXACT comparison. They are not
// patterns. There is no prefix matching, no wildcard, no trailing-slash
// tolerance, and no normalisation beyond what the client registered -- every one
// of those "conveniences" has produced a redirect-bypass CVE somewhere.
func Lookup(ctx context.Context, q Querier, clientID string) (*Client, error) {
	c := &Client{ClientID: clientID}
	var secret *string
	var alias *string
	var tlsDN, tlsDNS, tlsURI *string

	err := q.QueryRow(ctx, `
		SELECT org_id::text, display_name, client_type, client_secret_hash, enabled,
		       grant_types, response_types, scopes, require_pkce, pkce_methods,
		       id_token_signed_alg, refresh_token_ttl_s, first_party, issuer_alias,
		       may_exchange, exchange_audiences,
		       tls_subject_dn, tls_san_dns, tls_san_uri, tls_thumbprint, tls_bound_tokens,
		       allow_hybrid
		FROM core.clients
		WHERE client_id = $1`, clientID).
		Scan(&c.OrgID, &c.DisplayName, &c.Type, &secret, &c.Enabled,
			&c.GrantTypes, &c.ResponseTypes, &c.Scopes, &c.RequirePKCE, &c.PKCEMethods,
			&c.IDTokenAlg, &c.RefreshTTL, &c.FirstParty, &alias,
			&c.MayExchange, &c.ExchangeAudiences,
			&tlsDN, &tlsDNS, &tlsURI, &c.TLSThumbprint, &c.TLSBoundTokens,
			&c.AllowHybrid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up client %q: %w", clientID, err)
	}
	if secret != nil {
		c.SecretHash = *secret
	}
	if alias != nil {
		c.IssuerAlias = *alias
	}
	if tlsDN != nil {
		c.TLSSubjectDN = *tlsDN
	}
	if tlsDNS != nil {
		c.TLSSANDNS = *tlsDNS
	}
	if tlsURI != nil {
		c.TLSSANURI = *tlsURI
	}

	rows, err := q.Query(ctx,
		`SELECT redirect_uri FROM core.client_redirect_uris WHERE client_id = $1`, clientID)
	if err != nil {
		return nil, fmt.Errorf("loading redirect URIs for %q: %w", clientID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		c.RedirectURIs = append(c.RedirectURIs, u)
	}
	return c, rows.Err()
}

// HasRedirectURI reports whether the candidate is registered, by exact string
// equality -- with the one exception both RFC 9700 and RFC 8252 require.
//
// Deliberately not url.Parse-and-compare: two URLs that parse equal can differ
// as strings (percent-encoding case, default ports, an empty query marker), and
// a relying party echoes back the literal string it was configured with. Compare
// what was sent against what was registered, byte for byte.
//
// # The loopback exception
//
// RFC 9700 §4.1.3, having just mandated exact matching: "The only exception is
// native apps using a localhost URI: In this case, the authorization server MUST
// allow variable port numbers as described in Section 7.3 of [RFC8252]."
//
// RFC 8252 §7.3 says why: "The authorization server MUST allow any port to be
// specified at the time of the request for loopback IP redirect URIs, to
// accommodate clients that obtain an available ephemeral port from the operating
// system at the time of the request."
//
// A desktop app cannot know its port before it asks the operating system for
// one. Registering `http://127.0.0.1:1234/cb` and then listening on 51004 is the
// documented, normal behaviour -- and pure string equality refuses it, which
// makes native apps impossible rather than strict.
func (c *Client) HasRedirectURI(candidate string) bool {
	for _, u := range c.RedirectURIs {
		if u == candidate {
			return true
		}
		if loopbackPortMatch(u, candidate) {
			return true
		}
	}
	return false
}

// loopbackPortMatch reports whether two URIs are identical apart from the port,
// and are both http loopback redirects.
//
// Every other component must match exactly.
//
// The load-bearing check is `a.Hostname() != b.Hostname()`: it is what stops a
// client registered for `https://app.example/cb` matching
// `http://127.0.0.1:1/cb`, and a loopback client matching anywhere else. Given
// that equality, testing BOTH sides for loopback is redundant -- if the hosts
// are equal and one is loopback, so is the other. It is kept as a guard for a
// future edit that relaxes the host comparison, and is stated as redundant here
// rather than left to look load-bearing: a mutation test confirmed removing it
// changes no behaviour.
//
// The scheme must be http, because that is the only scheme the exception is
// written for -- RFC 8252 §7.3 constructs these URIs as
// "http://127.0.0.1:{port}/{path}". A https loopback URI is not the native-app
// pattern and gets no latitude.
func loopbackPortMatch(registered, candidate string) bool {
	a, err1 := url.Parse(registered)
	b, err2 := url.Parse(candidate)
	if err1 != nil || err2 != nil {
		return false
	}
	if a.Scheme != "http" || b.Scheme != "http" {
		return false
	}
	if !isLoopbackHost(a.Hostname()) || !isLoopbackHost(b.Hostname()) {
		return false
	}
	// The host must be the SAME loopback host. 127.0.0.1 and ::1 are different
	// addresses, and a client that registered one has not asked for the other.
	if a.Hostname() != b.Hostname() {
		return false
	}
	// Everything except the port, compared exactly. Query and fragment included:
	// the exception is about the port and nothing else.
	return a.Path == b.Path && a.RawQuery == b.RawQuery && a.Fragment == b.Fragment
}

// isLoopbackHost reports whether a hostname is a loopback destination.
//
// RFC 8252 §7.3 scopes its MUST to the loopback IP literals. `localhost` is
// included here for interoperability -- §8.3 calls it "NOT RECOMMENDED" but
// notes it "function[s] similarly", and refusing variable ports there would
// break a large number of real desktop clients while adding no protection: the
// concerns §8.3 raises about localhost (binding to a non-loopback interface,
// host name resolution) are properties of the CLIENT's socket and are unchanged
// by what the authorization server is willing to match.
func isLoopbackHost(h string) bool {
	return h == "127.0.0.1" || h == "::1" || h == "localhost"
}

// AllowsResponseType reports whether the client may use this response_type.
// AllowsResponseType reports whether the client may use this response type.
//
// Both sides are normalised first. response_type is a SET: "id_token code" and
// "code id_token" are the same request, and comparing raw strings accepts one
// spelling and refuses the other for no reason a client can discover from the
// error it gets back.
func (c *Client) AllowsResponseType(rt string) bool {
	want := normaliseSet(rt)
	for _, have := range c.ResponseTypes {
		if normaliseSet(have) == want {
			return true
		}
	}
	return false
}

func normaliseSet(rt string) string {
	parts := strings.Fields(rt)
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// AllowsGrantType reports whether the client may use this grant.
func (c *Client) AllowsGrantType(gt string) bool { return contains(c.GrantTypes, gt) }

// AllowsPKCEMethod reports whether the method is permitted for this client.
func (c *Client) AllowsPKCEMethod(m string) bool { return contains(c.PKCEMethods, m) }

// UnknownScopes returns any requested scope the client is not registered for.
func (c *Client) UnknownScopes(requested []string) []string {
	var bad []string
	for _, s := range requested {
		if !contains(c.Scopes, s) {
			bad = append(bad, s)
		}
	}
	return bad
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

var _ = Store{}

// TLSExpectation is what this client's certificate must satisfy, if any.
func (c *Client) TLSExpectation() clientauth.TLSExpectation {
	return clientauth.TLSExpectation{
		SubjectDN:  c.TLSSubjectDN,
		SANDNS:     c.TLSSANDNS,
		SANURI:     c.TLSSANURI,
		Thumbprint: c.TLSThumbprint,
	}
}
