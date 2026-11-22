package extfactor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type answerer struct {
	key  *ecdsa.PrivateKey
	jwks []byte
	now  time.Time
}

func newAnswerer(t *testing.T) *answerer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "k", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return &answerer{key: key, jwks: jwks, now: time.Unix(1_800_000_000, 0)}
}

func (a *answerer) claims() map[string]any {
	return map[string]any{"iss": "https://factor.example", "aud": "https://id.example", "sub": "person",
		"nonce": "n", "amr": []string{"otp"}, "iat": a.now.Unix(), "exp": a.now.Add(time.Minute).Unix()}
}

func (a *answerer) expected() Expected {
	return Expected{Issuer: "https://factor.example", Audience: "https://id.example", Subject: "person",
		JWKS: a.jwks, Declared: []string{"otp", "mfa"}}
}

func sign(t *testing.T, key jose.SigningKey, typ string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (a *answerer) answer(t *testing.T, change func(map[string]any)) string {
	t.Helper()
	claims := a.claims()
	if change != nil {
		change(claims)
	}
	return sign(t, jose.SigningKey{Algorithm: jose.ES256, Key: a.key}, TypResponse, claims)
}

func TestAnAnswerIsBelievedForWhatItSigned(t *testing.T) {
	a := newAnswerer(t)
	got, err := Verify(a.answer(t, nil), a.expected(), a.now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != "n" || len(got.AMR) != 1 || got.AMR[0] != "otp" {
		t.Errorf("verified as %+v", got)
	}
	// An audience may be a list, as in any JWT.
	if _, err := Verify(a.answer(t, func(c map[string]any) {
		c["aud"] = []string{"https://other.example", "https://id.example"}
	}), a.expected(), a.now); err != nil {
		t.Errorf("a list naming this server: %v", err)
	}
}

func TestAnAnswerIsRefusedForEachThingItGetsWrong(t *testing.T) {
	a := newAnswerer(t)
	stranger := newAnswerer(t)
	secret := []byte(strings.Repeat("s", 32))
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"`+TypResponse+`"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"n"}`)) + "."

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"signed with a shared secret", sign(t, jose.SigningKey{Algorithm: jose.HS256, Key: secret}, TypResponse, a.claims()), "asymmetric"},
		{"unsigned", none, "asymmetric"},
		{"signed by somebody else", stranger.answer(t, nil), "not signed by a key"},
		{"another kind of token", sign(t, jose.SigningKey{Algorithm: jose.ES256, Key: a.key}, "JWT", a.claims()), "typ"},
		{"the challenge sent back", sign(t, jose.SigningKey{Algorithm: jose.ES256, Key: a.key}, TypChallenge, a.claims()), "typ"},
		{"another issuer", a.answer(t, func(c map[string]any) { c["iss"] = "https://other.example" }), "iss"},
		{"addressed elsewhere", a.answer(t, func(c map[string]any) { c["aud"] = "https://other.example" }), "addressed"},
		{"about somebody else", a.answer(t, func(c map[string]any) { c["sub"] = "somebody" }), "somebody other"},
		{"no nonce", a.answer(t, func(c map[string]any) { delete(c, "nonce") }), "nonce"},
		{"no exp", a.answer(t, func(c map[string]any) { delete(c, "exp") }), "exp and iat"},
		{"no iat", a.answer(t, func(c map[string]any) { delete(c, "iat") }), "exp and iat"},
		{"expired", a.answer(t, func(c map[string]any) { c["exp"] = a.now.Add(-2 * time.Minute).Unix() }), "expired"},
		{"from the future", a.answer(t, func(c map[string]any) { c["iat"] = a.now.Add(2 * time.Minute).Unix() }), "future"},
		{"proved nothing", a.answer(t, func(c map[string]any) { delete(c, "amr") }), "proved nothing"},
		{"an undeclared amr", a.answer(t, func(c map[string]any) { c["amr"] = []string{"otp", "hwk"} }), `"hwk"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.raw, a.expected(), a.now)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for %q, and %q was expected", err, tc.want)
			}
		})
	}
}

func TestAClockIsForgivenAMinute(t *testing.T) {
	a := newAnswerer(t)
	for name, change := range map[string]func(map[string]any){
		"expired moments ago": func(c map[string]any) { c["exp"] = a.now.Add(-30 * time.Second).Unix() },
		"issued moments on":   func(c map[string]any) { c["iat"] = a.now.Add(30 * time.Second).Unix() },
	} {
		if _, err := Verify(a.answer(t, change), a.expected(), a.now); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestWhatAServiceMayBeRegisteredToClaim(t *testing.T) {
	if err := CheckDeclared([]string{"otp", "hwk", "mfa"}); err != nil {
		t.Errorf("ordinary values: %v", err)
	}
	for name, amr := range map[string][]string{
		"nothing":        nil,
		"a password":     {"pwd"},
		"a federation":   {"otp", "fed"},
		"kerberos":       {"krb"},
		"a passkey user": {"user"},
		"a walk's mark":  {"walk:external_factor/other"},
		"a space":        {"o p"},
		"upper case":     {"OTP"},
	} {
		if err := CheckDeclared(amr); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestOnlyPublicKeysAreRegistered(t *testing.T) {
	a := newAnswerer(t)
	if n, err := CheckKeys(a.jwks); err != nil || n != 1 {
		t.Fatalf("a public key: %d, %v", n, err)
	}
	for name, set := range map[string]jose.JSONWebKeySet{
		"a private key": {Keys: []jose.JSONWebKey{{Key: a.key, KeyID: "k"}}},
		"a shared key":  {Keys: []jose.JSONWebKey{{Key: []byte(strings.Repeat("s", 32)), KeyID: "k"}}},
		"no keys":       {},
	} {
		raw, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckKeys(raw); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := CheckKeys([]byte(`{"keys":`)); err == nil {
		t.Error("a key set that does not parse was accepted")
	}
}
