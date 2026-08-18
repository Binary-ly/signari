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
			name: "several events in one token",
			build: func() (string, Source) {
				c := goodClaims(now)
				c["events"] = map[string]any{
					EventSessionRevoked:   map[string]any{"subject": map[string]any{"sub": "a"}},
					EventCredentialChange: map[string]any{"subject": map[string]any{"sub": "b"}},
				}
				return tr.sign(t, TypSET, c, nil, tr.kid), tr.source()
			},
			want: "exactly one event",
			why:  "partially applying a token leaves a state nobody can reason about",
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
