package ssf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)


// ErrNotVerified means the token failed a check before anything was acted on.
var ErrNotVerified = fmt.Errorf("the security event token did not verify")

// ReceivedEvent is a verified event, ready to act on.
type ReceivedEvent struct {
	JTI string
	// Type and Claims are the FIRST event, for callers handling one.
	Type string
	// Types are every event type in the token, sorted. RFC 8417 permits several
	// entries describing one logical event.
	Types []string
	// AllClaims is every entry, keyed by type.
	AllClaims map[string]map[string]any
	Subject   Subject
	EventTime time.Time
	// Claims is the event body as sent, for the fields CAEP defines per type.
	Claims map[string]any
}

// Source is a transmitter we accept events from.
type Source struct {
	ID            string
	OrgID         string
	Issuer        string
	JWKSURI       string
	Audience      string
	AllowedEvents []string
}

// Allows reports whether this source may send this event type.
//
// An empty list allows nothing. A source configured with no events is a source
// somebody has not finished configuring, and reading that as "everything" is how
// a half-made configuration becomes a live grant.
func (s Source) Allows(eventType string) bool {
	for _, e := range s.AllowedEvents {
		if e == eventType {
			return true
		}
	}
	return false
}

// KeyFetcher retrieves and caches a transmitter's public keys.
//
// Cached because a SET arrives per security event and a JWKS fetch per event
// would make somebody else's outage into our latency. Refreshed on an unknown
// `kid`, because that is what a key rotation looks like from this side --
// bounded, so an attacker cannot force a fetch per forged token.
type KeyFetcher struct {
	HTTP    *http.Client
	Timeout time.Duration

	mu    sync.Mutex
	cache map[string]*cachedKeys
}

type cachedKeys struct {
	set       *jose.JSONWebKeySet
	fetchedAt time.Time
	// lastMiss bounds refresh-on-unknown-kid: without it, a stream of tokens
	// carrying random kids is a way to make us fetch continuously.
	lastMiss time.Time
}

// KeyCacheTTL is how long a fetched key set is reused.
const KeyCacheTTL = 10 * time.Minute

// KeyMissCooldown is the minimum gap between refreshes triggered by an unknown
// key id.
const KeyMissCooldown = 1 * time.Minute

func (f *KeyFetcher) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	t := f.Timeout
	if t <= 0 {
		t = 5 * time.Second
	}
	return &http.Client{Timeout: t}
}

// Keys returns the source's key set, fetching if needed.
func (f *KeyFetcher) Keys(ctx context.Context, jwksURI string, wantKID string) (
	*jose.JSONWebKeySet, error) {

	f.mu.Lock()
	if f.cache == nil {
		f.cache = map[string]*cachedKeys{}
	}
	c := f.cache[jwksURI]
	now := time.Now()

	fresh := c != nil && now.Sub(c.fetchedAt) < KeyCacheTTL
	// A kid we do not hold is what a rotation looks like. Refresh for it, but
	// not more often than the cooldown.
	missing := c != nil && wantKID != "" && !hasKID(c.set, wantKID) &&
		now.Sub(c.lastMiss) > KeyMissCooldown
	if fresh && !missing {
		f.mu.Unlock()
		if c == nil {
			return nil, fmt.Errorf("no keys for %s", jwksURI)
		}
		return c.set, nil
	}
	if missing {
		c.lastMiss = now
	}
	f.mu.Unlock()

	set, err := f.fetch(ctx, jwksURI)
	if err != nil {
		// A fetch failure with a usable cached set is not fatal: the
		// transmitter's outage should not stop us verifying events signed with
		// keys we already hold.
		f.mu.Lock()
		defer f.mu.Unlock()
		if c != nil && c.set != nil {
			return c.set, nil
		}
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.cache[jwksURI] = &cachedKeys{set: set, fetchedAt: now, lastMiss: now}
	return set, nil
}

func (f *KeyFetcher) fetch(ctx context.Context, uri string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", uri, resp.Status)
	}
	var set jose.JSONWebKeySet
	// Bounded: a key set is small, and an unbounded read from somebody else's
	// server is a way to be handed a gigabyte.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", uri, err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("%s returned no keys", uri)
	}
	return &set, nil
}

func hasKID(set *jose.JSONWebKeySet, kid string) bool {
	if set == nil {
		return false
	}
	for _, k := range set.Keys {
		if k.KeyID == kid {
			return true
		}
	}
	return false
}

// Verify checks a Security Event Token against a source and returns the event.
//
// Nothing here touches a database. The caller resolves the subject and acts
// only on what this returns, so an unverified token cannot reach anything.
func Verify(ctx context.Context, f *KeyFetcher, src Source, raw string, now time.Time) (
	ReceivedEvent, error) {

	var out ReceivedEvent

	// Pinned. jose requires the list up front, which is the right shape: it is
	// impossible to forget, and `none` is not on it.
	permitted := []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512, jose.EdDSA,
	}
	tok, err := jose.ParseSigned(raw, permitted)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrNotVerified, err)
	}
	if len(tok.Signatures) != 1 {
		return out, fmt.Errorf("%w: expected exactly one signature", ErrNotVerified)
	}
	h := tok.Signatures[0].Header

	// A token carrying its own key material verifies against itself, which is
	// no verification at all.
	if h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil ||
		h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return out, fmt.Errorf("%w: the token carries its own key material", ErrNotVerified)
	}
	// RFC 8417 §2.3. Without this an ID token from the same issuer is a signed
	// object we might act on.
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !strings.EqualFold(typ, TypSET) {
		return out, fmt.Errorf("%w: typ is %q, want %q", ErrNotVerified, typ, TypSET)
	}

	keys, err := f.Keys(ctx, src.JWKSURI, h.KeyID)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrNotVerified, err)
	}
	var payload []byte
	var verified bool
	for _, k := range keys.Keys {
		if h.KeyID != "" && k.KeyID != h.KeyID {
			continue
		}
		if p, verr := tok.Verify(k); verr == nil {
			payload, verified = p, true
			break
		}
	}
	if !verified {
		return out, fmt.Errorf("%w: no key in %s verifies it", ErrNotVerified, src.JWKSURI)
	}

	var c setClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return out, fmt.Errorf("%w: malformed claims", ErrNotVerified)
	}

	// The issuer must be the one this source is configured with. A valid
	// signature from a key set that also signs for somebody else is not
	// authority to speak as them.
	if c.Issuer != src.Issuer {
		return out, fmt.Errorf("%w: iss is %q, want %q", ErrNotVerified, c.Issuer, src.Issuer)
	}
	if !containsFold(c.Audience, src.Audience) {
		return out, fmt.Errorf("%w: aud %v does not include %q",
			ErrNotVerified, c.Audience, src.Audience)
	}
	if c.JTI == "" {
		// Without a jti there is no replay guard, and a SET that cannot be
		// de-duplicated is one that can be sent a thousand times.
		return out, fmt.Errorf("%w: no jti", ErrNotVerified)
	}
	if c.IssuedAt == 0 {
		return out, fmt.Errorf("%w: no iat", ErrNotVerified)
	}
	// A token minted in the future is a clock problem or a forgery; either way
	// not something to act on. Generous in the other direction: a receiver
	// catching up after an outage legitimately sees old events.
	if time.Unix(c.IssuedAt, 0).After(now.Add(5 * time.Minute)) {
		return out, fmt.Errorf("%w: issued in the future", ErrNotVerified)
	}
	// `exp` in a SET is NOT RECOMMENDED (RFC 8417 §2.2) because an event is
	// historical. But when present it means "MUST NOT be accepted for
	// processing" after that time, and the first version of this ignored it
	// entirely -- so a transmitter that deliberately time-boxed an event found
	// us acting on it afterwards.
	if c.Expiry > 0 && now.After(time.Unix(c.Expiry, 0)) {
		return out, fmt.Errorf("%w: the token expired at %s",
			ErrNotVerified, time.Unix(c.Expiry, 0).UTC().Format(time.RFC3339))
	}

	if len(c.Events) == 0 {
		return out, fmt.Errorf("%w: no events", ErrNotVerified)
	}
	// SEVERAL entries are allowed. RFC 8417 §2.2 forbids using `events` to
	// "express multiple INDEPENDENT logical events" -- it does not forbid
	// several entries describing ONE event from different angles, which is how
	// CAEP profiles convey detail.
	//
	// The first version refused any token with more than one entry, on the
	// reasoning that partially applying a token is a state nobody can reason
	// about. That reasoning was right and the remedy was wrong: it made us
	// reject conforming transmitters. Every entry is returned instead, and the
	// caller applies them in ONE transaction -- which is what makes partial
	// application impossible.
	out.Types = make([]string, 0, len(c.Events))
	for typ := range c.Events {
		out.Types = append(out.Types, typ)
	}
	sort.Strings(out.Types) // deterministic, so logs and tests do not vary
	// Type and Claims name the FIRST entry, so callers handling a single event
	// need not know about the list.
	out.Type = out.Types[0]
	out.Claims = c.Events[out.Type]

	// Every entry must be permitted. A source allowed to report one thing must
	// not smuggle another alongside it.
	for _, typ := range out.Types {
		if !src.Allows(typ) {
			return out, fmt.Errorf("%w: this source may not send %s", ErrNotVerified, typ)
		}
	}
	out.AllClaims = c.Events

	out.JTI = c.JTI
	out.Subject = subjectFrom(out.Claims)
	if t, ok := out.Claims["event_timestamp"].(float64); ok {
		out.EventTime = time.Unix(int64(t), 0)
	} else {
		out.EventTime = time.Unix(c.IssuedAt, 0)
	}
	return out, nil
}

// subjectFrom reads the subject out of an event body.
//
// CAEP puts it in `subject`; some transmitters use the RFC 8417 `sub_id`. Both
// are read, because a receiver that only understands one silently ignores half
// the transmitters in the world.
func subjectFrom(body map[string]any) Subject {
	var s Subject
	for _, key := range []string{"subject", "sub_id"} {
		raw, ok := body[key].(map[string]any)
		if !ok {
			continue
		}
		s.Format, _ = raw["format"].(string)
		s.Issuer, _ = raw["iss"].(string)
		s.Sub, _ = raw["sub"].(string)
		if s.Sub == "" {
			// The `email` format. Read, but the caller decides whether an email
			// is an acceptable way to name somebody -- it is a weaker claim
			// than an issuer-scoped subject.
			if e, _ := raw["email"].(string); e != "" {
				s.Format, s.Sub = "email", e
			}
		}
		if s.Sub != "" {
			return s
		}
	}
	return s
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
