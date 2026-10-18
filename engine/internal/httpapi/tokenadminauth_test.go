package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/oidc"
)

// /introspect and /revoke compared the secret themselves. They consulted no
// failure budget, and they refused every client that authenticates without a
// secret.

func postTokenAdmin(t *testing.T, f *tokenFixture, path, addr string, form url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr + ":443"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestIntrospectionSpendsTheClientAuthenticationBudget(t *testing.T) {
	f := newTokenFixture(t)
	clearOfWindowEdge(t, clientAuthPerPairWindow)
	secret := revocableClient(t, f)
	n := time.Now().UnixNano()
	addr := fmt.Sprintf("198.18.%d.%d", n%250, (n/250)%250+1)

	form := func(s string) url.Values {
		return url.Values{"client_id": {f.clientID}, "client_secret": {s}, "token": {"anything"}}
	}
	if status, body := postTokenAdmin(t, f, oidc.PathIntrospection, addr, form(secret)); status != http.StatusOK {
		t.Fatalf("the right secret was refused before any failure: %d %v", status, body)
	}
	for i := 0; i < clientAuthPerPairLimit; i++ {
		postTokenAdmin(t, f, oidc.PathIntrospection, addr, form("not-the-secret"))
	}
	if status, _ := postTokenAdmin(t, f, oidc.PathIntrospection, addr, form(secret)); status == http.StatusOK {
		t.Fatalf("after %d wrong secrets at /introspect the right one still worked, so "+
			"introspection is an unmetered place to guess a client secret", clientAuthPerPairLimit)
	}
}

func TestAPrivateKeyJWTClientCanIntrospectAndRevoke(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	revocableClient(t, f) // confidential

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: "introspect-1", Algorithm: "ES256", Use: "sig"}}})
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients SET token_endpoint_auth_method = 'private_key_jwt', jwks = $2::jsonb
		 WHERE client_id = $1`, f.clientID, string(set)); err != nil {
		t.Fatalf("registering private_key_jwt: %v", err)
	}

	assertion := func(path string) string {
		t.Helper()
		claims, _ := json.Marshal(map[string]any{
			"iss": f.clientID, "sub": f.clientID, "aud": f.srv.cfg.Issuer + path,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
			"jti": fmt.Sprintf("introspect-%d", time.Now().UnixNano()),
		})
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "introspect-1"))
		if err != nil {
			t.Fatal(err)
		}
		obj, err := signer.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := obj.CompactSerialize()
		return raw
	}

	for _, path := range []string{oidc.PathIntrospection, oidc.PathRevocation} {
		status, body := postTokenAdmin(t, f, path, "198.51.100.40", url.Values{
			"client_id": {f.clientID}, "token": {"anything"},
			"client_assertion_type": {clientauth.AssertionType},
			"client_assertion":      {assertion(path)},
		})
		if status != http.StatusOK {
			t.Errorf("a private_key_jwt client calling %s gave %d %v; it holds no secret, so "+
				"a secret comparison can never let it in", path, status, body)
		}
	}
}
