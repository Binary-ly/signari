package clientauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func signObject(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// §4: a string stays one, a number is a number, and what is structured stays JSON, as
// `claims` and `authorization_details` are read as, but for `resource`, which repeats.
// The JWT's own claims are not parameters, or `exp` would reach the sign-in as one.
// A key marked for encryption is not a key the client signs with, whatever it signed.
func TestAKeyMarkedForEncryptionVerifiesNothing(t *testing.T) {
	k := newKey(t, "k1")
	k.pub.Use, k.pub.Algorithm = "enc", ""
	if _, err := VerifyPrivateKeyJWT(k.sign(t, goodClaims()), testClientID, k.jwks(t), testAudiences, time.Now()); err == nil {
		t.Error("an assertion verified against a key marked for encryption")
	}
	now := time.Now()
	object := signObject(t, k.priv, map[string]any{"iss": "app", "aud": "https://id.test", "client_id": "app",
		"exp": now.Add(time.Minute).Unix(), "scope": "openid"})
	if _, err := VerifyRequestObject(object, "app", k.jwks(t), []string{"https://id.test"}, now); err == nil {
		t.Error("a request object verified against a key marked for encryption")
	}
}

func TestARequestObjectBecomesItsParameters(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public()}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	got, err := VerifyRequestObject(signObject(t, key, map[string]any{
		"iss": "app", "aud": []string{"https://id.test"}, "client_id": "app", "exp": now.Add(time.Minute).Unix(),
		"nbf": now.Unix(), "iat": now.Unix(), "jti": "j1",
		"scope": "openid", "max_age": 600, "resource": []string{"https://a.test", "https://b.test"},
		"claims":                map[string]any{"userinfo": map[string]any{"email": nil}},
		"authorization_details": []any{map[string]any{"type": "payment"}},
	}), "app", string(jwks), []string{"https://id.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"client_id": {"app"}, "scope": {"openid"}, "max_age": {"600"},
		"resource":              {"https://a.test", "https://b.test"},
		"claims":                {`{"userinfo":{"email":null}}`},
		"authorization_details": {`[{"type":"payment"}]`},
	}
	if !reflect.DeepEqual(map[string][]string(got), want) {
		t.Errorf("the parameters are\n%v\nwant\n%v", got, want)
	}
}

// The other half of the claims a request needs: a key with private material in it is a
// mistake to refuse, as it is for an assertion, and a weak key proves nothing.
func TestARequestObjectIsHeldToTheClientsKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "app", "aud": "https://id.test", "client_id": "app"}
	object := signObject(t, key, claims)
	private, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ jwks, want string }{
		{"", "no registered keys"},
		{"not json", "did not parse"},
		{string(private), "private key material"},
	} {
		_, err := VerifyRequestObject(object, "app", c.jwks, []string{"https://id.test"}, time.Now())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("with keys %q it gave %v, want %q", c.jwks, err, c.want)
		}
	}
	if _, err := VerifyRequestObject(strings.Repeat("x", maxRequestObjectBytes+1), "app", string(private), nil, time.Now()); err == nil {
		t.Error("an enormous object was read")
	}
}
