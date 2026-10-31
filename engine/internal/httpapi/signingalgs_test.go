package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// joseHeader reads the alg of a compact JWT.
func joseHeader(t *testing.T, raw string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.SplitN(raw, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	return h.Alg
}

// A client on ES384, with access tokens on RS512, gets tokens a relying party can check from
// the published keys alone: right alg in each header, an at_hash the length of the ID token's
// own hash, and discovery listing what is active and nothing else (9.04).
func TestAClientGetsTokensSignedAsItWasSet(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	added := []keys.Key{}
	for _, alg := range []keys.Algorithm{keys.ES384, keys.RS512} {
		k, err := keys.Generate(keys.NewKID(), alg)
		if err != nil {
			t.Fatal(err)
		}
		active, err := keys.WithState(k, keys.StateActive)
		if err != nil {
			t.Fatal(err)
		}
		added = append(added, active)
	}
	if err := f.srv.cfg.Keys.Replace(append(f.srv.cfg.Keys.Keys(), added...)...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET id_token_signed_alg = 'ES384',
		access_token_signed_alg = 'RS512' WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}

	get := func(path string, into any) {
		t.Helper()
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		if err := json.NewDecoder(io.Reader(rec.Body)).Decode(into); err != nil {
			t.Fatal(err)
		}
	}
	var meta struct {
		Algs []string `json:"id_token_signing_alg_values_supported"`
	}
	get(oidc.PathDiscovery, &meta)
	for _, want := range []string{"ES384", "RS512"} {
		if !slices.Contains(meta.Algs, want) {
			t.Errorf("discovery lists %v, without %s which has an active key", meta.Algs, want)
		}
	}
	if slices.Contains(meta.Algs, "PS512") {
		t.Errorf("discovery lists %v, with PS512 which has no key", meta.Algs)
	}

	verifier := strings.Repeat("a", 48)
	status, body := f.post(t, f.redeem(f.issueCodeWithScopes(t, verifier, []string{"openid"}), verifier))
	if status != http.StatusOK {
		t.Fatalf("redeeming a code: %d %v", status, body)
	}
	access, _ := body["access_token"].(string)
	idToken, _ := body["id_token"].(string)
	if got := joseHeader(t, access); got != "RS512" {
		t.Errorf("the access token is %s, want RS512", got)
	}
	if got := joseHeader(t, idToken); got != "ES384" {
		t.Errorf("the ID token is %s, want ES384", got)
	}

	// Checked from what is published, as a relying party does.
	var published jose.JSONWebKeySet
	get(oidc.PathJWKS, &published)
	for _, raw := range []string{access, idToken} {
		sig, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES384, jose.RS512})
		if err != nil {
			t.Fatal(err)
		}
		found := published.Key(sig.Signatures[0].Header.KeyID)
		if len(found) != 1 {
			t.Fatalf("%s's key is not in the JWKS", joseHeader(t, raw))
		}
		if _, err := sig.Verify(found[0].Public()); err != nil {
			t.Errorf("%s did not verify from the JWKS: %v", joseHeader(t, raw), err)
		}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(idToken, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		AtHash string `json:"at_hash"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if n := len(claims.AtHash); n != 32 {
		t.Errorf("at_hash is %d characters; the left half of SHA-384 is 32", n)
	}

	// The grants that sign an access token and no ID token go by the same setting.
	secret := revocableClient(t, f)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = ARRAY['client_credentials'],
		scopes = ARRAY['api.read'] WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	status, body = f.post(t, url.Values{"grant_type": {"client_credentials"}, "scope": {"api.read"},
		"client_id": {f.clientID}, "client_secret": {secret}})
	if status != http.StatusOK {
		t.Fatalf("client_credentials: %d %v", status, body)
	}
	if raw, _ := body["access_token"].(string); joseHeader(t, raw) != "RS512" {
		t.Errorf("a client_credentials token is %s, want RS512", joseHeader(t, raw))
	}

	// A client cannot be set to what its instance does not hold.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ps512 := "PS512"
	if err := store.SetClientSettings(ctx, tx, f.clientID, store.ClientSettings{AccessTokenAlg: &ps512}); err == nil {
		t.Error("an algorithm the instance holds no key for was accepted")
	}
}
