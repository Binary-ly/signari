package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/dpop"
)

// mintBoundUserinfoToken is an access token for userinfo, bound to the key jkt names.
func (f *tokenFixture) mintBoundUserinfoToken(t *testing.T, jkt string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	// With the fixture's session, which an id_token, minted beside it for openid, needs.
	resp, _, err := f.srv.mintSet(withDPoPThumbprint(ctx, jkt), tx, c, f.orgID, f.userID,
		f.sid, "", []string{"openid", "email"}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken
}

// userinfoProof is a proof for GET /oauth2/userinfo, signed with alg by key.
func userinfoProof(t *testing.T, alg jose.SignatureAlgorithm, key crypto.Signer, token string) string {
	t.Helper()
	return proofFor(t, alg, key, http.MethodGet, tokenTestIssuer+"/oauth2/userinfo", token)
}

// proofFor is a resource's proof for method and uri, signed with alg by key.
func proofFor(t *testing.T, alg jose.SignatureAlgorithm, key crypto.Signer, method, uri, token string) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key.Public()}
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderType, "dpop+jwt").WithHeader("jwk", jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"jti": fmt.Sprintf("fapi-%d", time.Now().UnixNano()), "htm": method,
		"htu": uri, "iat": time.Now().Unix()}
	// ath for a resource, none for the authorization server, which is shown no token.
	if token != "" {
		claims["ath"] = dpop.AccessTokenHash(token)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

// FAPI 2.0 §5.4.1 binds resource servers as well as the token endpoint
// (specs/fapi2.txt:2023-2027): a token whose client is held to the profile is honoured
// behind a proof signed with PS256, ES256 or EdDSA and nothing else. The token endpoint
// held proofs to that and userinfo did not, so the token was good behind RS256 (13.01,
// the FAPI 2.0 plan's dpop-negative-tests).
func TestAProfileClientsTokenIsHonouredOnlyBehindAProfileProof(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	ctx := context.Background()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := (&jose.JSONWebKey{Key: &rsaKey.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	rsaJKT := base64.RawURLEncoding.EncodeToString(sum)
	rsaBound := f.mintBoundUserinfoToken(t, rsaJKT)
	ec := newProofKey(t)
	ecBound := f.mintBoundUserinfoToken(t, ec.thumbprint(t))
	// The credential endpoint, the other resource here that takes a bound token.
	issuance := f.mintBoundIssuanceToken(t, rsaJKT)
	credentialURI := tokenTestIssuer + "/oid4vci/credential"

	ask := func(token, proof string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", proof)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}

	// RS256 is a DPoP algorithm, and an ordinary client may prove with it.
	if code := ask(rsaBound, userinfoProof(t, jose.RS256, rsaKey, rsaBound)); code != http.StatusOK {
		t.Fatalf("an ordinary client's token behind an RS256 proof answered %d", code)
	}
	if code, body := f.askForCredential(t, "DPoP", issuance,
		proofFor(t, jose.RS256, rsaKey, http.MethodPost, credentialURI, issuance)); code != http.StatusOK {
		t.Fatalf("an ordinary client's issuance token behind an RS256 proof answered %d: %.200s", code, body)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET security_profile = 'fapi2' WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `UPDATE core.clients SET security_profile = 'none' WHERE client_id = $1`, f.clientID)
	})
	if code := ask(rsaBound, userinfoProof(t, jose.RS256, rsaKey, rsaBound)); code != http.StatusUnauthorized {
		t.Errorf("a FAPI 2.0 client's token behind an RS256 proof answered %d, want 401", code)
	}
	if code := ask(ecBound, ec.resourceGetProof(t, ecBound)); code != http.StatusOK {
		t.Errorf("a FAPI 2.0 client's token behind an ES256 proof answered %d", code)
	}
	if code, body := f.askForCredential(t, "DPoP", issuance,
		proofFor(t, jose.RS256, rsaKey, http.MethodPost, credentialURI, issuance)); code != http.StatusUnauthorized {
		t.Errorf("a FAPI 2.0 client's issuance token behind an RS256 proof answered %d: %.200s", code, body)
	}
}

// resourceGetProof is resourceProof for a GET of userinfo.
func (p *proofKey) resourceGetProof(t *testing.T, token string) string {
	t.Helper()
	return userinfoProof(t, jose.ES256, p.priv, token)
}
