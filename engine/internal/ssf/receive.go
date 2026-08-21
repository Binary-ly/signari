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

	"signari.dev/engine/internal/jsonstrict"
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

	// CriticalSubjectMembers is SSF 1.0 §7.1's `critical_subject_members`: the
	// subject member names this transmitter has declared Critical.
	//
	// §3.6 makes acting on them a MUST: "An SSF Receiver MUST discard any event
	// that contains a Subject with a Critical member that it is unable to
	// process." Empty is the normal case and means no member is critical.
	CriticalSubjectMembers []string
}

// processableSubjectMembers are the members subjectFrom actually reads.
//
// Kept beside the parser it describes, because the §3.6 rule is "a Critical
// member that it is unable to process" -- so the list of what we CAN process is
// half of the check, and a member added to subjectFrom without being added here
// would make us discard events we now understand perfectly well.
var processableSubjectMembers = map[string]bool{
	"format": true, "iss": true, "sub": true, "email": true,
	// §3.3's complex subject, whose `user` member is the one we resolve to an
	// account. The other member names it defines -- device, session,
	// application, tenant, org_unit, group -- are deliberately ABSENT.
	//
	// That absence is the §3.6 safety valve doing its job rather than an
	// omission. We revoke per user, so an event scoped to one session or one
	// device is applied more broadly than it was sent. A transmitter that cannot
	// accept that says so by marking the member Critical, and this receiver then
	// discards the event instead of over-applying it -- which is exactly what
	// §3.6 is for: "unable to process ... a Critical member". Adding them here
	// would silently claim we honour scopes we ignore.
	"user": true,
}

// unprocessableCritical returns the Critical members present in a subject that
// this receiver cannot interpret.
//
// The check is on the RAW subject object, not the parsed Subject: the whole
// point is to notice members we do not model, and a parsed struct has already
// thrown those away.
func (s Source) unprocessableCritical(raw map[string]any) []string {
	// No early return for the empty cases. Ranging over an empty slice already
	// does nothing, and indexing a nil map already reports "not present", so a
	// guard here would be one no test could make fail -- mutation confirmed it.
	// A short-circuit that only restates what the loop does is weight without
	// meaning.
	var bad []string
	for _, name := range s.CriticalSubjectMembers {
		if _, present := raw[name]; !present {
			// §7.1 is conditional: critical members matter only "if present in a
			// Subject Member in an event". A declared member the event does not
			// carry is not a reason to discard anything.
			continue
		}
		if !processableSubjectMembers[name] {
			bad = append(bad, name)
		}
	}
	return bad
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

	// A signed payload that names a claim twice has no single meaning.
	//
	// Unlike the AuthZEN case this is not attacker-craftable: the payload is
	// signed, so producing one needs the transmitter's key, and a transmitter we
	// trust to revoke sessions could do worse things directly. What it would
	// still produce is DIVERGENCE -- we act on Go's reading of a duplicated
	// claim while a SIEM reading the same bytes records another. An audit trail
	// that disagrees with the action it describes is the one failure this
	// product cannot afford, so an ambiguous SET is refused rather than
	// interpreted.
	if err := jsonstrict.NoDuplicateKeys(payload); err != nil {
		return out, fmt.Errorf("%w: %v", ErrNotVerified, err)
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
	// `exp` and a top-level `sub` are both FORBIDDEN in an SSF SET, and both for
	// the same reason.
	//
	// RFC 8417 §2.2 only makes `exp` "NOT RECOMMENDED", and an earlier version
	// of this code cited that and honoured the claim when present -- refusing a
	// SET whose expiry had passed. The Shared Signals Framework profile is
	// stricter, and says why:
	//
	//	§4.1.7  "The "exp" claim MUST NOT be used in SETs. The purpose is
	//	        defense in depth against confusion with other JWTs, as described
	//	        in Sections 4.5 and 4.6 of [RFC8417]."
	//	§4.1.2  "The JWT "sub" claim MUST NOT be present in any SET containing an
	//	        SSF event."
	//
	// The second sits under §4.1.3, "Distinguishing SETs from other Kinds of
	// JWTs -- Of particular concern is the possibility that SETs are confused
	// for other kinds of JWTs."
	//
	// So these are not stylistic. A JWT carrying `sub` and `exp` is
	// structurally an ID token or an access token, and the profile forbids
	// those claims so that a SET can never be mistaken for one -- or one for a
	// SET. We already check `typ: secevent+jwt`, which is the primary defence;
	// the profile adds these because typ checking is not universal, and defence
	// in depth is the stated purpose.
	//
	// Refused rather than tolerated. A conformant transmitter does not send
	// them, and accepting a non-conformant SET is how the confusion the profile
	// prevents gets in.
	if c.Expiry != 0 {
		return out, fmt.Errorf("%w: the SET carries an `exp` claim, which the "+
			"Shared Signals Framework forbids (section 4.1.7) as defence in "+
			"depth against confusion with other kinds of JWT", ErrNotVerified)
	}
	if c.Subject != nil {
		return out, fmt.Errorf("%w: the SET carries a top-level `sub` claim, "+
			"which the Shared Signals Framework forbids (section 4.1.2). An SSF "+
			"event names its subject in `sub_id`; a JWT with a top-level `sub` "+
			"is shaped like an ID token", ErrNotVerified)
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
	// §3.6: discard rather than act with a scope we do not understand.
	//
	// This runs before the subject is used for anything. A Critical member we
	// cannot read means the event is scoped by something we are ignoring -- a
	// device, a tenant, a session -- and acting on it would apply the right
	// action to the wrong set of things, silently.
	// §3.1.4: "Each Subject Member MUST refer to exactly one Subject Principal."
	// An event that names two different principals cannot satisfy that, and which
	// one a receiver honours would otherwise decide who gets signed out.
	if ambiguousSubject(out.Claims) {
		return out, fmt.Errorf("%w: the event carries both sub_id and subject and "+
			"they name different principals; section 3.1.4 requires a subject to "+
			"refer to exactly one", ErrNotVerified)
	}

	// §3.1.4 again, across the two levels rather than within one: a top-level
	// `sub_id` that contradicts the subject inside the event names two principals
	// for one event, and which of them a receiver honours would decide who gets
	// signed out.
	if inner, ok := rawSubject(out.Claims); ok && len(c.SubID) > 0 {
		if subjectsDiffer(inner, c.SubID) {
			return out, fmt.Errorf("%w: the top-level `sub_id` and the subject "+
				"inside the event name different principals; section 3.1.4 requires "+
				"a subject to refer to exactly one", ErrNotVerified)
		}
	}

	subjectBody := effectiveSubject(out.Claims, c.SubID)
	if raw, ok := rawSubject(subjectBody); ok {
		if bad := src.unprocessableCritical(raw); len(bad) > 0 {
			return out, fmt.Errorf("%w: the subject carries the critical member(s) %v, "+
				"which this receiver cannot interpret; §3.6 requires discarding the "+
				"event rather than acting on a scope it does not understand",
				ErrNotVerified, bad)
		}
	}
	out.Subject = subjectFrom(subjectBody)
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
// rawSubject returns the subject object as sent, before parsing.
// rawSubject returns the subject object as sent.
//
// `sub_id` FIRST, because §3.1 makes it the one that counts: "claim named sub_id
// MUST be used to describe the primary subject of the event". `subject` is
// accepted after it for transmitters written against the earlier CAEP drafts,
// which put the subject inside the event.
//
// The order used to be the other way round, and that is a divergence rather than
// a preference. An event carrying BOTH -- malformed, or crafted -- would be read
// by us as `subject` and by a conformant 1.0 receiver as `sub_id`, so two
// receivers act on two different principals from the same signed token. See
// ambiguousSubject, which now refuses that case outright.
func rawSubject(body map[string]any) (map[string]any, bool) {
	for _, key := range []string{"sub_id", "subject"} {
		if raw, ok := body[key].(map[string]any); ok {
			return raw, true
		}
	}
	return nil, false
}

// ambiguousSubject reports whether an event names its subject twice, differently.
//
// Both keys carrying the SAME subject is what this engine itself emits, for
// interoperability with pre-1.0 receivers, and is fine. Both carrying different
// subjects is not: which one a receiver acts on becomes an implementation
// detail, and the whole point of an event naming a principal is that every
// receiver agrees which principal it is.
func ambiguousSubject(body map[string]any) bool {
	a, aok := body["sub_id"].(map[string]any)
	b, bok := body["subject"].(map[string]any)
	if !aok || !bok {
		return false
	}
	return subjectsDiffer(a, b)
}

// subjectsDiffer compares two subject objects member by member.
//
// Shared by the two places a subject can be named twice: `sub_id` beside
// `subject` inside one event, and the top-level `sub_id` beside either of those.
// §3.1.4 -- "Each Subject Member MUST refer to exactly one Subject Principal" --
// covers both, and a receiver that enforces it in one place and not the other
// lets the same contradiction through the other door.
//
// Every member present in EITHER object, not a fixed list of member names. The
// fixed list was `format, iss, sub, email, phone_number, uri`, which is the
// members of RFC 9493's simple formats and no others -- so two subjects whose
// identity lives anywhere else compared as the same principal and the §3.1.4
// check above passed on a SET naming two different people:
//
//	§3.3 complex   -- identity is in `user`/`device`/`session`/`tenant`/...
//	§3.2.6 aliases -- identity is in `identifiers`
//	opaque         -- identity is in `id`
//	did            -- identity is in `url`
//
// A complex subject naming alice beside one naming mallory agreed on `format`
// ("complex") and was absent from all five other keys, so the loop compared six
// pairs of nothings and reported no difference. The union has no such blind spot
// and needs no maintenance when a new identifier format is registered, which is
// the actual failure here: the list had to be revisited every time RFC 9493 grew
// and nothing made that obligation visible.
//
// fmt.Sprint rather than reflect.DeepEqual, deliberately: it keeps the existing
// tolerance for a transmitter that sends 1 where another sends "1", and Go prints
// map keys in sorted order, so nested members compare stably.
func subjectsDiffer(a, b map[string]any) bool {
	seen := make(map[string]bool, len(a)+len(b))
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if seen[k] {
				continue
			}
			seen[k] = true
			if fmt.Sprint(a[k]) != fmt.Sprint(b[k]) {
				return true
			}
		}
	}
	return false
}

// effectiveSubject picks the object that names who the event is about.
//
// SSF 1.0 §3.1 puts the subject at the TOP LEVEL of the SET -- "claim named
// sub_id MUST be used to describe the primary subject of the event" -- and
// §3.1.1 requires it "even for these existing event types", meaning CAEP and
// RISC. Our own transmitter was fixed to emit it there. The receiver was not
// brought along: it read `c.Events[type]` and nothing else, so a conformant
// transmitter -- this server talking to itself included -- sent an event that
// verified perfectly and named nobody. A session-revocation event that names
// nobody revokes nothing, silently, which is the single outcome this subsystem
// exists to prevent.
//
// The event body still WINS when it carries a subject. Most transmitters in the
// field still use the pre-1.0 in-event shape, and `subjectFrom` already argues
// the point about `sub_id` versus `subject`: "a receiver that only understands
// one silently ignores half the transmitters in the world." Preferring the top
// level would have moved the blind spot rather than removed it.
func effectiveSubject(body map[string]any, top map[string]any) map[string]any {
	if _, ok := rawSubject(body); ok {
		return body
	}
	if len(top) == 0 {
		return body
	}
	return map[string]any{"sub_id": top}
}

func subjectFrom(body map[string]any) Subject {
	var s Subject
	// Same order as rawSubject, and for the same reason.
	for _, key := range []string{"sub_id", "subject"} {
		raw, ok := body[key].(map[string]any)
		if !ok {
			continue
		}
		// §3.3: a Complex Subject carries `"format": "complex"` and its identity
		// one level down, in Simple Subject Members named `user`, `device`,
		// `session`, `tenant` and so on. Read flat, every field below is absent
		// and the result is an empty Subject that resolves to nobody -- so the
		// event is recorded as `no_matching_user` and revokes nothing.
		//
		// `user` specifically, and nothing else. §3.3.1 says the members are
		// attributes of ONE principal -- "As a whole, the Complex Subject MUST
		// refer to exactly one Subject Principal" -- so this is not a choice
		// between candidates; it is the member that names the account, which is
		// the only thing this receiver can act on. Falling back to `device` or
		// `tenant` when `user` is absent would revoke somebody's sessions on the
		// strength of a string collision between a device id and a user id.
		//
		// Members are Simple by definition, so there is no nesting to recurse
		// into: one level down is the whole of it.
		if fmt.Sprint(raw["format"]) == "complex" {
			u, ok := raw["user"].(map[string]any)
			if !ok {
				continue
			}
			raw = u
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
