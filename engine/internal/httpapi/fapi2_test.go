package httpapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	"signari.dev/engine/internal/store"
)

// fapi2Client is the fixture's client made to meet FAPI 2.0, by private_key_jwt and
// DPoP, as it would be by `set-keys`, `set-dpop` and `set-par`.
type fapi2Client struct {
	*tokenFixture
	key     *ecdsa.PrivateKey
	proofs  *proofKey
	jtis    int
	refresh string
}

func newFAPI2Client(t *testing.T) *fapi2Client {
	t.Helper()
	f := newTokenFixture(t)
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: key.Public(), KeyID: "fapi-256", Algorithm: "ES256", Use: "sig"},
		{Key: other.Public(), KeyID: "fapi-384", Algorithm: "ES384", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients SET client_type = 'confidential', token_endpoint_auth_method = 'private_key_jwt',
		       jwks = $2::jsonb, dpop_bound_access_tokens = true, require_pushed_authorization = true,
		       response_types = ARRAY['code'] WHERE client_id = $1`, f.clientID, string(set)); err != nil {
		t.Fatal(err)
	}
	profile := "fapi2"
	if err := setClientSettings(t, f, store.ClientSettings{SecurityProfile: &profile}); err != nil {
		t.Fatalf("a client that meets the profile: %v", err)
	}
	return &fapi2Client{tokenFixture: f, key: key, proofs: newProofKey(t)}
}

// assertion is a client assertion, by default the only kind the profile takes.
func (c *fapi2Client) assertion(t *testing.T, aud any) string {
	t.Helper()
	return c.signedAssertion(t, aud, jose.ES256, c.key, "fapi-256")
}

func (c *fapi2Client) signedAssertion(t *testing.T, aud any, alg jose.SignatureAlgorithm, key crypto.Signer, kid string) string {
	t.Helper()
	c.jtis++
	claims, err := json.Marshal(map[string]any{"iss": c.clientID, "sub": c.clientID, "aud": aud,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		"jti": fmt.Sprintf("fapi-%d-%d", c.jtis, time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (c *fapi2Client) authenticated(t *testing.T, form url.Values, assertion string) url.Values {
	t.Helper()
	form.Set("client_assertion_type", clientauth.AssertionType)
	form.Set("client_assertion", assertion)
	return form
}

// redeemOne redeems a fresh code with the assertion given, and a proof.
func (c *fapi2Client) redeemOne(t *testing.T, assertion, proof string, scopes ...string) (int, map[string]any) {
	t.Helper()
	verifier := strings.Repeat("f", 48)
	return c.postDPoP(t, c.authenticated(t, c.redeem(c.issueCodeWithScopes(t, verifier, scopes), verifier), assertion), proof)
}

func (c *fapi2Client) nextProof(t *testing.T) string {
	t.Helper()
	c.jtis++
	return c.proofs.proof(t, fmt.Sprintf("fapi-proof-%d-%d", c.jtis, time.Now().UnixNano()))
}

// Set when it meets the profile and refused when it does not, naming what is wrong, and
// nothing through the settings writer can then take it out.
func TestAClientIsHeldToFAPI2OnlyWhenItMeetsIt(t *testing.T) {
	f := newTokenFixture(t)
	profile := "fapi2"
	err := setClientSettings(t, f, store.ClientSettings{SecurityProfile: &profile})
	if !errors.Is(err, store.ErrInvalidClientSetting) {
		t.Fatalf("the fixture's public client: %v", err)
	}
	for _, says := range []string{"confidential", "sender-constrained", "pushed"} {
		if !strings.Contains(err.Error(), says) {
			t.Errorf("the refusal does not say %q: %v", says, err)
		}
	}
	if got, gerr := store.ClientSettingsOf(context.Background(), f.pool, f.clientID); gerr != nil || got.SecurityProfile != "none" {
		t.Errorf("after the refusal: %q, %v", got.SecurityProfile, gerr)
	}

	c := newFAPI2Client(t)
	off, weak := false, "RS256"
	for name, change := range map[string]store.ClientSettings{"PAR off": {RequirePAR: &off}, "RS256": {IDTokenAlg: &weak}} {
		if err := setClientSettings(t, c.tokenFixture, change); !errors.Is(err, store.ErrInvalidClientSetting) {
			t.Errorf("%s on a client held to the profile: %v", name, err)
		}
	}
	none := "none"
	if err := setClientSettings(t, c.tokenFixture, store.ClientSettings{SecurityProfile: &none}); err != nil {
		t.Fatalf("releasing it: %v", err)
	}
}

// At the token endpoint: only its issuer, as a string, in an assertion; only the profile's
// algorithms; a proof of a key every time; and a client that has left its profile by a
// command that has never heard of one is refused.
func TestAFAPI2ClientAtTheTokenEndpoint(t *testing.T) {
	c := newFAPI2Client(t)
	ctx := context.Background()
	issuer := c.srv.cfg.Issuer

	for name, aud := range map[string]any{"the token endpoint": issuer + oidc.PathToken,
		"a list holding the issuer": []string{issuer}} {
		if status, body := c.redeemOne(t, c.assertion(t, aud), c.nextProof(t), "openid"); status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("an assertion addressed to %s: %d %v", name, status, body)
		}
	}

	wide, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: c.key.Public(), KeyID: "fapi-256", Algorithm: "ES256", Use: "sig"},
		{Key: wide.Public(), KeyID: "fapi-384", Algorithm: "ES384", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Exec(ctx, `UPDATE core.clients SET jwks = $2::jsonb WHERE client_id = $1`, c.clientID, string(set)); err != nil {
		t.Fatal(err)
	}
	if status, body := c.redeemOne(t, c.signedAssertion(t, issuer, jose.ES384, wide, "fapi-384"), c.nextProof(t), "openid"); status != http.StatusUnauthorized {
		t.Errorf("an ES384 assertion: %d %v", status, body)
	}

	// A proof by an algorithm the profile does not have.
	wideProof := &proofKey{priv: wide, jwk: jose.JSONWebKey{Key: &wide.PublicKey, Algorithm: "ES384"}}
	if status, body := c.redeemOne(t, c.assertion(t, issuer), wideProof.proofBy(t, jose.ES384, "fapi-es384"), "openid"); status != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("an ES384 proof: %d %v", status, body)
	}

	if status, body := c.redeemOne(t, c.assertion(t, issuer), c.nextProof(t), "openid"); status != http.StatusOK {
		t.Fatalf("a request that meets the profile: %d %v", status, body)
	} else if body["token_type"] != "DPoP" || body["refresh_token"] != nil {
		t.Errorf("the answer: %v", body)
	}

	// Sender-constrained by a certificate, and none on the connection.
	if _, err := c.pool.Exec(ctx, `UPDATE core.clients SET dpop_bound_access_tokens = false, tls_bound_tokens = true
		WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("g", 48)
	status, body := c.post(t, c.authenticated(t, c.redeem(c.issueCodeWithScopes(t, verifier, []string{"openid"}), verifier), c.assertion(t, issuer)))
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Errorf("no key proved at all: %d %v", status, body)
	}
	if _, err := c.pool.Exec(ctx, `UPDATE core.clients SET dpop_bound_access_tokens = true, tls_bound_tokens = false
		WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}

	// Out of the profile by a write that has never heard of one.
	if _, err := c.pool.Exec(ctx, `UPDATE core.clients SET require_pushed_authorization = false WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	if status, body := c.redeemOne(t, c.assertion(t, issuer), c.nextProof(t), "openid"); status != http.StatusBadRequest || body["error"] != "unauthorized_client" {
		t.Errorf("a client out of its profile: %d %v", status, body)
	}
}

// "shall not use refresh token rotation": the same token goes on working and the answer
// carries no other, and it ends as a rotating token does, with its family.
func TestAFAPI2RefreshTokenDoesNotRotate(t *testing.T) {
	c := newFAPI2Client(t)
	issuer := c.srv.cfg.Issuer
	status, body := c.redeemOne(t, c.assertion(t, issuer), c.nextProof(t), "openid", "offline_access")
	if status != http.StatusOK {
		t.Fatalf("redeeming: %d %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token: %v", body)
	}
	spend := func() (int, map[string]any) {
		t.Helper()
		return c.postDPoP(t, c.authenticated(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh},
			"client_id": {c.clientID}}, c.assertion(t, issuer)), c.nextProof(t))
	}
	for i := 1; i <= 3; i++ {
		status, body := spend()
		if status != http.StatusOK {
			t.Fatalf("refresh %d: %d %v", i, status, body)
		}
		if body["refresh_token"] != nil {
			t.Errorf("refresh %d rotated: %v", i, body["refresh_token"])
		}
		if body["access_token"] == nil {
			t.Errorf("refresh %d gave no access token: %v", i, body)
		}
	}
	var live int
	if err := c.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.refresh_tokens rt
		JOIN core.refresh_token_families f ON f.id = rt.family_id
		WHERE f.client_id = $1 AND rt.consumed_at IS NULL`, c.clientID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("%d live refresh tokens, want the one it started with", live)
	}

	if _, err := c.pool.Exec(context.Background(), `UPDATE core.refresh_token_families SET revoked_at = now(),
		revocation_reason = 'test' WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	if status, body := spend(); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("after its family was revoked: %d %v", status, body)
	}
}

// "shall require the redirect_uri parameter in pushed authorization requests", which a
// client with one registered URI may otherwise leave out, and a client out of its profile
// gets nothing to authorize.
func TestAFAPI2PushNamesItsRedirectURI(t *testing.T) {
	c := newFAPI2Client(t)
	issuer := c.srv.cfg.Issuer
	push := func(extra url.Values) *httptest.ResponseRecorder {
		t.Helper()
		form := c.authenticated(t, url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "scope": {"openid"},
			"state": {"s"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}},
			c.assertion(t, issuer))
		for k, v := range extra {
			form[k] = v
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		c.srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	if rec := push(nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "redirect_uri is required") {
		t.Errorf("no redirect_uri: %d %s", rec.Code, rec.Body)
	}
	named := url.Values{"redirect_uri": {"https://rp.test/cb"}}
	if rec := push(named); rec.Code != http.StatusCreated {
		t.Errorf("a push naming it: %d %s", rec.Code, rec.Body)
	}
	form := c.authenticated(t, url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"s"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
		"redirect_uri": {"https://rp.test/cb"}}, c.assertion(t, issuer+"/oauth2/par"))
	req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("an assertion addressed to the endpoint: %d %s", rec.Code, rec.Body)
	}

	if _, err := c.pool.Exec(context.Background(), `UPDATE core.clients SET dpop_bound_access_tokens = false
		WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	if rec := push(named); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unauthorized_client") {
		t.Errorf("a client out of its profile: %d %s", rec.Code, rec.Body)
	}
}
