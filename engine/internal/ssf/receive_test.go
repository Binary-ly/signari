package ssf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Verifying somebody else's Security Event Tokens.
//
// Every case here is an attack that, if it got through, would let an
// unauthenticated caller end other people's sessions. The endpoint is
// unauthenticated by design -- the signature IS the credential -- so these are
// the only thing standing between a POST and a mass sign-out.

type transmitter struct {
	key    *ecdsa.PrivateKey
	kid    string
	server *httptest.Server
}

func newTransmitter(t *testing.T) *transmitter {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := &transmitter{key: key, kid: "tx-1"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: tr.kid, Algorithm: string(jose.ES256), Use: "sig",
	}}}
	tr.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(tr.server.Close)
	return tr
}

// sign builds a SET. Every parameter is separable so a test can break exactly
// one thing and leave the rest correct -- otherwise a refusal proves nothing
// about which check did the refusing.
func (tr *transmitter) sign(t *testing.T, typ string, claims map[string]any,
	key *ecdsa.PrivateKey, kid string) string {

	t.Helper()
	if key == nil {
		key = tr.key
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).
			WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func goodClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://transmitter.test",
		"jti": "jti-1",
		"iat": now.Unix(),
		"aud": []string{"https://signari.test"},
		"events": map[string]any{
			EventSessionRevoked: map[string]any{
				"subject": map[string]any{
					"format": "iss_sub", "iss": "https://transmitter.test",
					"sub": "user-42",
				},
				"event_timestamp": now.Unix(),
			},
		},
	}
}

func (tr *transmitter) source() Source {
	return Source{
		ID: "src-1", OrgID: "org-1",
		Issuer: "https://transmitter.test", JWKSURI: tr.server.URL,
		Audience:      "https://signari.test",
		AllowedEvents: []string{EventSessionRevoked, EventCredentialChange},
	}
}

func TestAGenuineEventVerifies(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	raw := tr.sign(t, TypSET, goodClaims(now), nil, tr.kid)

	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now)
	if err != nil {
		t.Fatalf("a genuine event was refused: %v", err)
	}
	if got.Type != EventSessionRevoked {
		t.Fatalf("type = %q", got.Type)
	}
	if got.Subject.Sub != "user-42" || got.Subject.Format != "iss_sub" {
		t.Fatalf("subject = %+v", got.Subject)
	}
	if got.JTI != "jti-1" {
		t.Fatalf("jti = %q", got.JTI)
	}
}

// Each case breaks exactly one thing.
func TestVerificationRefusesEveryForgery(t *testing.T) {
	tr := newTransmitter(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	cases := []struct {
		name string
		// build returns the token and, optionally, an altered source.
		build func() (string, Source)
		want  string
		why   string
	}{
		{
			name: "signed with a key we do not trust",
			build: func() (string, Source) {
				return tr.sign(t, TypSET, goodClaims(now), other, tr.kid), tr.source()
			},
			want: "no key",
			why:  "anyone with a keypair could end anybody's sessions",
		},
		{
			name: "typ is not secevent+jwt",
			build: func() (string, Source) {
				return tr.sign(t, "JWT", goodClaims(now), nil, tr.kid), tr.source()
			},
			want: "typ is",
			why:  "an ID token from the same issuer would be a signed object we act on",
		},
		{
			name: "issuer does not match the source",
			build: func() (string, Source) {
				c := goodClaims(now)
				c["iss"] = "https://somebody-else.test"
				return tr.sign(t, TypSET, c, nil, tr.kid), tr.source()
			},
			want: "iss is",
			why:  "a key set that signs for two issuers is not authority to be both",
		},
		{
			name: "audience is somebody else",
			build: func() (string, Source) {
				c := goodClaims(now)
				c["aud"] = []string{"https://another-receiver.test"}
				return tr.sign(t, TypSET, c, nil, tr.kid), tr.source()
			},
			want: "does not include",
			why:  "a token addressed elsewhere is not ours to act on, however valid",
		},
		{
			name: "no jti",
			build: func() (string, Source) {
				c := goodClaims(now)
				delete(c, "jti")
				return tr.sign(t, TypSET, c, nil, tr.kid), tr.source()
			},
			want: "no jti",
			why:  "without one there is no replay guard, so one capture signs somebody out forever",
		},
		{
			name: "issued in the future",
			build: func() (string, Source) {
				c := goodClaims(now)
				c["iat"] = now.Add(time.Hour).Unix()
				return tr.sign(t, TypSET, c, nil, tr.kid), tr.source()
			},
			want: "future",
			why:  "a clock problem or a forgery; neither is something to act on",
		},
		{
			name: "an event type this source may not send",
			build: func() (string, Source) {
				src := tr.source()
				src.AllowedEvents = []string{EventCredentialChange}
				return tr.sign(t, TypSET, goodClaims(now), nil, tr.kid), src
			},
			want: "may not send",
			why:  "a source allowed to report device compliance must not also revoke sessions",
		},
		{
			name: "a source configured with no events at all",
			build: func() (string, Source) {
				src := tr.source()
				src.AllowedEvents = nil
				return tr.sign(t, TypSET, goodClaims(now), nil, tr.kid), src
			},
			want: "may not send",
			why:  "an unfinished configuration must not read as permission for everything",
		},
		{
			// RFC 8417 §2.2 forbids expressing multiple INDEPENDENT logical
			// events, but a receiver cannot tell "independent" from "related"
			// by inspection -- that constraint binds the transmitter. What a
			// receiver CAN enforce is that every entry is permitted, which is
			// covered by TestSeveralEntriesDescribingOneEventAreAccepted.
			name: "no events at all",
			build: func() (string, Source) {
				c := goodClaims(now)
				c["events"] = map[string]any{}
				return tr.sign(t, TypSET, c, nil, tr.kid), tr.source()
			},
			want: "no events",
			why:  "a token asserting nothing is malformed, not a no-op",
		},
		{
			name:  "not a token at all",
			build: func() (string, Source) { return "not.a.token", tr.source() },
			want:  "",
			why:   "garbage must not reach the database",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, src := c.build()
			_, err := Verify(context.Background(), &KeyFetcher{}, src, raw, now)
			if err == nil {
				t.Fatalf("ACCEPTED. %s", c.why)
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// A token carrying its own key material verifies against itself.
func TestATokenCannotSupplyItsOwnKey(t *testing.T) {
	tr := newTransmitter(t)
	rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: rogue.Public(), KeyID: "rogue", Algorithm: string(jose.ES256)}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: rogue},
		(&jose.SignerOptions{}).WithType(jose.ContentType(TypSET)).
			WithHeader("jwk", jwk))
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(goodClaims(time.Now()))
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, time.Now())
	if err == nil {
		t.Fatal("a token supplying its own key was accepted; it verified against " +
			"itself, which is no verification at all")
	}
	// The MESSAGE matters, not just the refusal.
	//
	// Mutation testing caught this: with the guard removed the token is still
	// refused, because it is signed by a key that is not in the source's JWKS
	// and we only ever verify against keys we fetched. So the original
	// assertion passed for the wrong reason and proved nothing about the guard.
	//
	// Asserting the reason makes the guard load-bearing: remove it and the
	// refusal comes from somewhere else, and this fails. The guard is
	// defence-in-depth -- it protects against a future change that consults the
	// header for keys, which is how alg confusion gets reintroduced.
	if !strings.Contains(err.Error(), "own key material") {
		t.Fatalf("err = %q, want the embedded-key guard to be what refused it. "+
			"If this fails because the refusal came from elsewhere, the guard "+
			"has been removed and nothing is checking for jku/x5u/jwk", err)
	}
}

// The subject is read from either shape, because a receiver that understands
// only one silently ignores half the transmitters in the world.
func TestSubjectIsReadFromEitherShape(t *testing.T) {
	for _, key := range []string{"subject", "sub_id"} {
		body := map[string]any{key: map[string]any{
			"format": "iss_sub", "iss": "https://t.test", "sub": "u-1",
		}}
		if got := subjectFrom(body); got.Sub != "u-1" {
			t.Errorf("%s: subject = %+v", key, got)
		}
	}
	// The email format is read, but keeps its format so the caller can decide
	// whether an email is an acceptable way to name somebody.
	got := subjectFrom(map[string]any{"subject": map[string]any{
		"format": "email", "email": "alice@example.com",
	}})
	if got.Format != "email" || got.Sub != "alice@example.com" {
		t.Errorf("email subject = %+v", got)
	}
}

// A source with an empty event list allows nothing.
func TestAnEmptyEventListAllowsNothing(t *testing.T) {
	var s Source
	if s.Allows(EventSessionRevoked) {
		t.Fatal("a source with no configured events allowed one")
	}
	s.AllowedEvents = []string{EventSessionRevoked}
	if !s.Allows(EventSessionRevoked) {
		t.Fatal("a configured event was not allowed")
	}
	if s.Allows(EventCredentialChange) {
		t.Fatal("an unconfigured event was allowed")
	}
}

// A SET carrying `exp` at all is refused, whether or not it has passed.
//
// This test used to assert the weaker rule: expired refused, future accepted.
// That followed RFC 8417 §2.2 alone, which only makes `exp` NOT RECOMMENDED.
// The Shared Signals Framework profile is stricter, §4.1.7:
//
//	"The "exp" claim MUST NOT be used in SETs. The purpose is defense in depth
//	against confusion with other JWTs, as described in Sections 4.5 and 4.6 of
//	[RFC8417]."
//
// The reason is what changes the rule. If `exp` existed to time-box an event,
// honouring it would be enough. It exists to keep a SET from being shaped like
// an ID token -- so its PRESENCE is the problem, and a SET with a comfortable
// future expiry is exactly as confusable as an expired one.
func TestASETCarryingExpIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	for _, exp := range []struct {
		name string
		at   int64
	}{
		{"already passed", now.Add(-time.Minute).Unix()},
		{"an hour away", now.Add(time.Hour).Unix()},
		{"far in the future", now.Add(24 * 365 * time.Hour).Unix()},
	} {
		t.Run(exp.name, func(t *testing.T) {
			c := goodClaims(now)
			c["exp"] = exp.at
			_, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
				tr.sign(t, TypSET, c, nil, tr.kid), now)
			if err == nil {
				t.Fatal("a SET carrying `exp` was accepted; §4.1.7 forbids the " +
					"claim outright as a cross-JWT confusion defence")
			}
			if !strings.Contains(err.Error(), "4.1.7") {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}

	// No exp at all is the ordinary, conformant case.
	c := goodClaims(now)
	delete(c, "exp")
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, c, nil, tr.kid), now); err != nil {
		t.Fatalf("a SET with no exp was refused, but that is what the profile "+
			"requires: %v", err)
	}
}

// §4.1.2: "The JWT "sub" claim MUST NOT be present in any SET containing an SSF
// event."
//
// It sits under §4.1.3, "Distinguishing SETs from other Kinds of JWTs -- Of
// particular concern is the possibility that SETs are confused for other kinds
// of JWTs." An SSF event names its subject in `sub_id`; a top-level `sub` is the
// shape of an ID token.
func TestASETCarryingATopLevelSubIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	for _, sub := range []string{"alice@example.com", ""} {
		c := goodClaims(now)
		c["sub"] = sub
		_, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
			tr.sign(t, TypSET, c, nil, tr.kid), now)
		if err == nil {
			t.Fatalf("a SET carrying a top-level `sub` of %q was accepted", sub)
		}
		if !strings.Contains(err.Error(), "4.1.2") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	}

	// An empty string is still a `sub` claim, which is why the field is a
	// pointer: "absent" and "present but empty" are different, and only the
	// first is conformant.
	c := goodClaims(now)
	delete(c, "sub")
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, c, nil, tr.kid), now); err != nil {
		t.Fatalf("a SET with no top-level sub was refused: %v", err)
	}
}

// RFC 8417 §2.2 forbids using `events` to express multiple INDEPENDENT logical
// events. It does not forbid several entries describing ONE event, which is how
// CAEP profiles convey detail.
//
// The first version refused any token with more than one entry, which rejected
// conforming transmitters. The concern behind it -- partial application -- is
// answered by applying every entry in one transaction, not by refusing.
func TestSeveralEntriesDescribingOneEventAreAccepted(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	subject := map[string]any{
		"format": "iss_sub", "iss": "https://transmitter.test", "sub": "user-42",
	}

	c := goodClaims(now)
	c["events"] = map[string]any{
		EventSessionRevoked:   map[string]any{"subject": subject},
		EventCredentialChange: map[string]any{"subject": subject},
	}
	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, c, nil, tr.kid), now)
	if err != nil {
		t.Fatalf("a token with two entries was refused: %v", err)
	}
	if len(got.Types) != 2 {
		t.Fatalf("Types = %v, want both entries", got.Types)
	}
	// Sorted, so logs and tests do not vary between runs.
	if got.Types[0] > got.Types[1] {
		t.Fatalf("Types = %v, want them sorted", got.Types)
	}
	if got.Type != got.Types[0] {
		t.Fatalf("Type = %q, want the first of %v", got.Type, got.Types)
	}
	if len(got.AllClaims) != 2 {
		t.Fatalf("AllClaims has %d entries, want 2", len(got.AllClaims))
	}

	// EVERY entry must be permitted -- a source allowed to report one thing
	// must not smuggle another alongside it.
	//
	// Checked with the disallowed entry in BOTH positions. The first version of
	// this test allowed only session-revoked, and because the types sort
	// alphabetically the disallowed one landed first -- so a mutation that
	// checked only Types[0] passed. Position-dependent coverage is no coverage.
	for _, allowed := range [][]string{
		{EventSessionRevoked},   // credential-change sorts first: disallowed at [0]
		{EventCredentialChange}, // session-revoked sorts second: disallowed at [1]
	} {
		src := tr.source()
		src.AllowedEvents = allowed
		if _, err := Verify(context.Background(), &KeyFetcher{}, src,
			tr.sign(t, TypSET, c, nil, tr.kid), now); err == nil {
			t.Fatalf("with only %v permitted, a token carrying both was "+
				"accepted; the unpermitted entry rode along", allowed)
		}
	}

	// And a token with no events at all is malformed.
	c["events"] = map[string]any{}
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, c, nil, tr.kid), now); err == nil {
		t.Fatal("a token with no events was accepted")
	}
}

// §4.1.8: "The "aud" claim can be a single string or an array of strings."
//
// Three of the specification's own example SETs use the string form —
// Figures 8, 9 and 10 all carry `"aud": "636C69656E745F6964"` — and RFC 7519
// §4.1.3 permits it for every JWT. A receiver that parses `aud` only as an array
// refuses each of them.
//
// The failure is worse than a refusal, because Go reports a type mismatch during
// unmarshalling and the whole claim set is then reported as "malformed claims".
// An operator wiring up a conformant transmitter is told their token is
// malformed, with nothing pointing at the audience, and every event is dropped.
func TestTheAudienceMayBeASingleString(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	c := goodClaims(now)
	c["aud"] = "https://signari.test" // a string, not an array
	raw := tr.sign(t, TypSET, c, nil, tr.kid)

	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now)
	if err != nil {
		t.Fatalf("a SET with a string audience was refused: %v\n"+
			"§4.1.8 permits it and the specification's own examples use it", err)
	}
	if got.Type != EventSessionRevoked {
		t.Fatalf("type = %q", got.Type)
	}
}

// And the string form must still be CHECKED, not merely parsed. A receiver that
// accepts any string audience is worse than one that refuses them all.
func TestAStringAudienceNamingSomebodyElseIsStillRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	c := goodClaims(now)
	c["aud"] = "https://another-receiver.test"
	raw := tr.sign(t, TypSET, c, nil, tr.kid)

	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now); err == nil {
		t.Fatal("a SET addressed to another receiver was accepted because its " +
			"audience happened to be a string")
	}
}

// SSF 1.0 §3.6, with §7.1's `critical_subject_members`:
//
//	"An SSF Receiver MUST discard any event that contains a Subject with a
//	Critical member that it is unable to process."
//
// Found by extracting every MUST from the specification and checking each one —
// the same sweep that found three unmet requirements in OID4VCI. Nothing in the
// receiver mentioned `crit` or `critical_subject_members` at all.
//
// The consequence is scope, not authenticity. Every other check here asks "is
// this event genuine"; this one asks "do I understand what it is about". A
// transmitter marking `device` critical is saying the event concerns one device
// rather than the whole account. Ignoring that member does not fail — it applies
// the right action to the wrong set of things, silently, which is the same
// shape as the token-lifecycle defects found earlier in this codebase.
func TestAnEventWithAnUnprocessableCriticalMemberIsDiscarded(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	src := tr.source()
	src.CriticalSubjectMembers = []string{"device"}

	claims := goodClaims(now)
	subject := claims["events"].(map[string]any)[EventSessionRevoked].(map[string]any)["subject"].(map[string]any)
	subject["device"] = "laptop-7"

	raw := tr.sign(t, TypSET, claims, nil, tr.kid)
	if _, err := Verify(context.Background(), &KeyFetcher{}, src, raw, now); err == nil {
		t.Fatal("an event carrying a critical member this receiver cannot read was " +
			"accepted; the action would be applied to every session the user has, " +
			"not the one device the transmitter scoped it to")
	}
}

// The rule is conditional on the member being PRESENT. A transmitter that
// declares `device` critical must not break every event that does not carry one.
func TestADeclaredCriticalMemberThatIsAbsentChangesNothing(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	src := tr.source()
	src.CriticalSubjectMembers = []string{"device"}

	raw := tr.sign(t, TypSET, goodClaims(now), nil, tr.kid)
	if _, err := Verify(context.Background(), &KeyFetcher{}, src, raw, now); err != nil {
		t.Fatalf("an ordinary event was discarded because the transmitter declares "+
			"a critical member it did not send: %v", err)
	}
}

// A critical member we DO process is not a reason to discard. §3.6 turns on
// "unable to process", not on the label.
func TestACriticalMemberWeUnderstandIsAccepted(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	src := tr.source()
	src.CriticalSubjectMembers = []string{"sub", "iss", "format"}

	raw := tr.sign(t, TypSET, goodClaims(now), nil, tr.kid)
	if _, err := Verify(context.Background(), &KeyFetcher{}, src, raw, now); err != nil {
		t.Fatalf("an event was discarded over critical members the receiver reads "+
			"perfectly well: %v", err)
	}
}

// And with no critical members declared — the overwhelmingly common case — the
// check must be invisible.
func TestNoCriticalMembersDeclaredMeansNoNewRefusals(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now)
	subject := claims["events"].(map[string]any)[EventSessionRevoked].(map[string]any)["subject"].(map[string]any)
	subject["device"] = "laptop-7"
	subject["tenant"] = "acme"

	raw := tr.sign(t, TypSET, claims, nil, tr.kid)
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now); err != nil {
		t.Fatalf("unknown subject members were treated as critical when the "+
			"transmitter declared none: %v", err)
	}
}

// SSF 1.0 §3.1 puts the subject at the TOP LEVEL of the SET:
//
//	§3.1    "claim named sub_id MUST be used to describe the primary subject of
//	        the event."
//	§3.1.1  "MUST include the top-level sub_id claim even for these existing
//	        event types" — that is, for CAEP and RISC events.
//
// Our transmitter was fixed to do exactly this: `setClaims.SubID` exists, is
// tagged `json:"sub_id"`, and its comment records that the subject used to
// travel inside the event object in the pre-1.0 CAEP shape.
//
// The receiver was never brought along. `out.Claims` is `c.Events[out.Type]` —
// the event body — and `subjectFrom` looks for `sub_id` or `subject` inside it.
// The top-level claim is decoded into `c.SubID` and read by nothing.
//
// So a conformant SSF 1.0 transmitter, including this server talking to itself,
// sends a session-revocation event whose subject the receiver cannot see. The
// event verifies — signature, issuer, audience, jti, iat all check out — and
// then names nobody. Nothing is refused and nothing is revoked: the failure is
// a session that stays alive after a transmitter said to kill it, which is the
// one outcome this entire subsystem exists to prevent.
func TestTheTopLevelSubIdIsRead(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now)
	// §3.1's shape: the subject at the top level, and an event body that carries
	// only its own detail. This is what our own transmitter emits.
	claims["sub_id"] = map[string]any{
		"format": "iss_sub", "iss": "https://transmitter.test", "sub": "user-42",
	}
	claims["events"] = map[string]any{
		EventSessionRevoked: map[string]any{"event_timestamp": now.Unix()},
	}

	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now)
	if err != nil {
		t.Fatalf("a conformant SSF 1.0 event was refused: %v", err)
	}
	if got.Subject.Sub != "user-42" || got.Subject.Format != "iss_sub" {
		t.Fatalf("subject = %+v, want user-42/iss_sub from the top-level sub_id. "+
			"The event verified and named nobody, so the revocation it carries "+
			"applies to no session", got.Subject)
	}
}

// The pre-1.0 shape must keep working: most transmitters in the field still put
// the subject inside the event body, and a receiver that understands only the
// new shape ignores half the world — the same objection `subjectFrom` already
// makes about `subject` versus `sub_id`.
func TestTheInEventSubjectStillWins(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, goodClaims(now), nil, tr.kid), now)
	if err != nil {
		t.Fatalf("the pre-1.0 shape was refused: %v", err)
	}
	if got.Subject.Sub != "user-42" {
		t.Fatalf("subject = %+v", got.Subject)
	}
}

// §3.1.4: "Each Subject Member MUST refer to exactly one Subject Principal."
//
// The receiver already enforced this WITHIN an event — `sub_id` beside
// `subject` naming different people is refused. Reading the top-level `sub_id`
// opens a second door to the same contradiction: an event body naming user-A
// under a SET whose top-level subject is user-B.
//
// Which one a receiver honours would otherwise decide who gets signed out, and
// the two plausible precedence rules pick different victims. Refusing is the
// only answer that does not silently make that choice.
func TestATopLevelSubjectContradictingTheEventIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now) // event body names user-42
	claims["sub_id"] = map[string]any{
		"format": "iss_sub", "iss": "https://transmitter.test", "sub": "user-99",
	}

	_, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now)
	if err == nil {
		t.Fatal("a SET naming user-42 inside the event and user-99 at the top " +
			"level was accepted; one of the two gets signed out and which is an " +
			"implementation detail")
	}
	if !strings.Contains(err.Error(), "different principals") {
		t.Errorf("refused, but not as a subject contradiction: %v", err)
	}
}

// The same subject in both places is what a transmitter emits for
// interoperability with pre-1.0 receivers, and must keep working.
func TestTheSameSubjectInBothPlacesIsFine(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	claims := goodClaims(now)
	claims["sub_id"] = map[string]any{
		"format": "iss_sub", "iss": "https://transmitter.test", "sub": "user-42",
	}
	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now)
	if err != nil {
		t.Fatalf("a SET naming the same subject twice was refused: %v", err)
	}
	if got.Subject.Sub != "user-42" {
		t.Fatalf("subject = %+v", got.Subject)
	}
}

// `iss_sub` is issuer-scoped: the same `sub` under a different `iss` is a
// different person. A comparison that looks only at `sub` reads "user-42 at
// transmitter.test" and "user-42 at evil.test" as the same principal, so a
// transmitter could name its own user in the event body and somebody else's at
// the top level and have the pair accepted as consistent.
//
// This applies equally to the within-event check, which has always compared the
// same member list; the mutation that exposed it — compare only `sub` — survived
// every existing test.
func TestSubjectsFromDifferentIssuersAreDifferentPrincipals(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now) // event body: user-42 @ transmitter.test
	claims["sub_id"] = map[string]any{
		"format": "iss_sub", "iss": "https://evil.test", "sub": "user-42",
	}

	_, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now)
	if err == nil {
		t.Fatal("a SET naming user-42 at transmitter.test inside the event and " +
			"user-42 at evil.test at the top level was accepted; iss_sub is " +
			"issuer-scoped, so those are two different people")
	}
	if !strings.Contains(err.Error(), "different principals") {
		t.Errorf("refused, but not as a subject contradiction: %v", err)
	}
}

// The same distinction within one event, which is the older code path.
func TestAnInEventSubjectPairFromDifferentIssuersIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	claims := goodClaims(now)
	claims["events"] = map[string]any{
		EventSessionRevoked: map[string]any{
			"subject": map[string]any{
				"format": "iss_sub", "iss": "https://transmitter.test", "sub": "user-42",
			},
			"sub_id": map[string]any{
				"format": "iss_sub", "iss": "https://evil.test", "sub": "user-42",
			},
			"event_timestamp": now.Unix(),
		},
	}
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now); err == nil {
		t.Fatal("an event naming the same sub under two different issuers was accepted")
	}
}

// SSF 1.0 §3.3 Complex Subject Members — a section no pass had opened, found by
// listing the spec's sections and checking which ones our code and docs cite.
//
//	"A Complex Subject Member has a name and a value that is a JSON object that
//	has a format field, and one or more Simple Subject Members. The name of the
//	format field is "format", and its value is "complex"."
//
// The spec's own example:
//
//	"sub_id": {
//	  "format": "complex",
//	  "user":   {"format": "email",   "email": "bar@example.com"},
//	  "tenant": {"format": "iss_sub", "iss": "...", "sub": "1234"}
//	}
//
// `subjectFrom` read `format`, `iss`, `sub` and `email` off the object directly.
// Against a complex subject all four are absent — the identity is one level
// down — so it returned an empty Subject, `ResolveSSFSubject` matched nobody,
// and the event was recorded as `no_matching_user` while revoking nothing.
//
// §3.3.1 is what makes reading the `user` member correct rather than a guess:
// "All members within a Complex Subject MUST represent attributes of the same
// Subject Principal. As a whole, the Complex Subject MUST refer to exactly one
// Subject Principal." The members are attributes of one principal, not a
// conjunction of separate scopes.
func TestAComplexSubjectNamesItsUser(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now)
	claims["events"] = map[string]any{
		EventSessionRevoked: map[string]any{
			"sub_id": map[string]any{
				"format": "complex",
				"user": map[string]any{
					"format": "iss_sub", "iss": "https://transmitter.test", "sub": "user-42",
				},
				"tenant": map[string]any{
					"format": "iss_sub", "iss": "https://transmitter.test", "sub": "tenant-1",
				},
			},
			"event_timestamp": now.Unix(),
		},
	}

	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now)
	if err != nil {
		t.Fatalf("an event with a §3.3 complex subject was refused: %v", err)
	}
	if got.Subject.Sub != "user-42" || got.Subject.Format != "iss_sub" {
		t.Fatalf("subject = %+v, want user-42/iss_sub from the complex subject's "+
			"`user` member. An empty subject resolves to nobody, so the revocation "+
			"is recorded as no_matching_user and no session ends", got.Subject)
	}
}

// The `email` form of the same shape, since that is what the specification's own
// example uses for `user`.
func TestAComplexSubjectWithAnEmailUser(t *testing.T) {
	got := subjectFrom(map[string]any{"sub_id": map[string]any{
		"format": "complex",
		"user":   map[string]any{"format": "email", "email": "bar@example.com"},
	}})
	if got.Format != "email" || got.Sub != "bar@example.com" {
		t.Errorf("subject = %+v, want the email form from the `user` member", got)
	}
}

// A complex subject naming no user is not something this receiver can act on —
// it identifies a device or a tenant, and we revoke per user. It must resolve to
// nothing, which the caller already records as `no_matching_user`, rather than
// resolving to some other member and revoking the wrong person's sessions.
func TestAComplexSubjectWithNoUserResolvesToNobody(t *testing.T) {
	got := subjectFrom(map[string]any{"sub_id": map[string]any{
		"format": "complex",
		"device": map[string]any{"format": "iss_sub", "iss": "https://t.test", "sub": "dev-9"},
	}})
	if got.Sub != "" {
		t.Errorf("subject = %+v, want empty: this event names a device, and "+
			"treating a device id as a user id revokes somebody's sessions on the "+
			"strength of a string collision", got)
	}
}

// Why reading only `user` is safe, rather than a shortcut.
//
// This receiver revokes per user. An event scoped to one session or one device
// is therefore applied more broadly than it was sent — every session of that
// person's, not the one named. §3.6 is the mechanism a transmitter uses when it
// cannot accept that: mark the member Critical, and a receiver "unable to
// process" it MUST discard the event rather than act on a scope it is ignoring.
//
// So the correctness of reading only `user` depends on the other complex member
// names staying OUT of `processableSubjectMembers`. These two cases are that
// dependency, made into a test: a critical `session` must be refused, and a
// critical `user` must now be accepted because we do read it.
func TestComplexSubjectScopesWeIgnoreAreRefusedWhenCritical(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	complexSubject := func(extra string) map[string]any {
		sub := map[string]any{
			"format": "complex",
			"user": map[string]any{
				"format": "iss_sub", "iss": "https://transmitter.test", "sub": "user-42",
			},
		}
		if extra != "" {
			sub[extra] = map[string]any{
				"format": "iss_sub", "iss": "https://transmitter.test", "sub": "scope-1",
			}
		}
		claims := goodClaims(now)
		claims["events"] = map[string]any{
			EventSessionRevoked: map[string]any{
				"sub_id": sub, "event_timestamp": now.Unix(),
			},
		}
		return claims
	}

	// A session scope we do not honour, declared critical: discard.
	src := tr.source()
	src.CriticalSubjectMembers = []string{"session"}
	_, err := Verify(context.Background(), &KeyFetcher{}, src,
		tr.sign(t, TypSET, complexSubject("session"), nil, tr.kid), now)
	if err == nil {
		t.Error("an event scoped to one session, with `session` marked critical, " +
			"was accepted. We revoke per user, so acting on it ends every session " +
			"that person has — §3.6 says discard instead of applying the right " +
			"action to the wrong set of things")
	}

	// The member we DO read, declared critical: process it.
	src2 := tr.source()
	src2.CriticalSubjectMembers = []string{"user"}
	got, err := Verify(context.Background(), &KeyFetcher{}, src2,
		tr.sign(t, TypSET, complexSubject(""), nil, tr.kid), now)
	if err != nil {
		t.Errorf("a critical `user` member was treated as unprocessable, but that "+
			"is the one member this receiver resolves: %v", err)
	}
	if got.Subject.Sub != "user-42" {
		t.Errorf("subject = %+v", got.Subject)
	}
}

// §3.1.4 once more, for the subject shapes whose identity does not live in any of
// the members the comparison used to name.
//
// `subjectsDiffer` compared a fixed list -- format, iss, sub, email,
// phone_number, uri -- which is RFC 9493's simple formats and nothing else. Two
// §3.3 complex subjects agree on `format` ("complex") and carry no member from
// that list at all, so the comparison examined six pairs of absent values and
// reported that alice and mallory were the same principal. The contradiction
// check above then passed, and a session-revocation event naming two different
// people was accepted.
//
// This is the whole journey rather than the comparison alone: a signed SET,
// through Verify, refused by name. The unit-level version would pass against a
// receiver that computed the difference correctly and then ignored it.
func TestContradictoryComplexSubjectsAreRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now)
	claims["events"] = map[string]any{
		EventSessionRevoked: map[string]any{
			"subject": map[string]any{
				"format": "complex",
				"user":   map[string]any{"format": "email", "email": "alice@example.com"},
			},
			"event_timestamp": now.Unix(),
		},
	}
	claims["sub_id"] = map[string]any{
		"format": "complex",
		"user":   map[string]any{"format": "email", "email": "mallory@example.com"},
	}

	_, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now)
	if err == nil {
		t.Fatal("a SET whose event names alice and whose top-level sub_id names " +
			"mallory was accepted; §3.1.4 requires a subject to refer to exactly " +
			"one principal, and whichever one this receiver acts on, the other is " +
			"either signed out without cause or left signed in without one")
	}
	if !strings.Contains(err.Error(), "different principals") {
		t.Errorf("refused, but not as a subject contradiction: %v", err)
	}
}

// The same blind spot for RFC 9493 §3.2.6 aliases, whose identity is the
// `identifiers` array. Included because the fix must not be a special case for
// `user`: the comparison now covers every member present in either object, and
// this is the second shape that proves it.
func TestContradictoryAliasSubjectsAreRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now)
	claims["events"] = map[string]any{
		EventSessionRevoked: map[string]any{
			"subject": map[string]any{
				"format": "aliases",
				"identifiers": []any{
					map[string]any{"format": "email", "email": "alice@example.com"},
				},
			},
			"event_timestamp": now.Unix(),
		},
	}
	claims["sub_id"] = map[string]any{
		"format": "aliases",
		"identifiers": []any{
			map[string]any{"format": "email", "email": "mallory@example.com"},
		},
	}

	_, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now)
	if err == nil {
		t.Fatal("a SET whose event and top-level sub_id carry different alias " +
			"identifier lists was accepted as naming one principal")
	}
	if !strings.Contains(err.Error(), "different principals") {
		t.Errorf("refused, but not as a subject contradiction: %v", err)
	}
}

// The half that must not break: a member present in one object and absent from
// the other is still a difference, but two objects that agree everywhere -- which
// is what this engine's own transmitter emits, the same map under both keys --
// must still pass. TestTheSameSubjectInBothPlacesIsFine covers the simple format;
// this covers the shape the union comparison newly reaches into.
func TestIdenticalComplexSubjectsInBothPlacesAreAccepted(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	subject := map[string]any{
		"format": "complex",
		"user":   map[string]any{"format": "email", "email": "alice@example.com"},
	}
	claims := goodClaims(now)
	claims["events"] = map[string]any{
		EventSessionRevoked: map[string]any{
			"subject": subject, "event_timestamp": now.Unix(),
		},
	}
	claims["sub_id"] = subject

	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, claims, nil, tr.kid), now); err != nil {
		t.Fatalf("a SET naming the same complex subject in both places was "+
			"refused, so the contradiction check now rejects conformant events: %v", err)
	}
}
