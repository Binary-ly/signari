package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"crypto/rand"
	"net/http/httptest"
	"strings"

	"encoding/base64"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oidc"
)

// RFC 7009 §2.1:
//
//	"If the particular token is a refresh token and the authorization server
//	supports the revocation of access tokens, then the authorization server
//	SHOULD also invalidate all access tokens based on the same authorization
//	grant."
//
// We support access token revocation, so the cascade applies. It could not
// happen: revocation is recorded per-jti and an access token carried no trace of
// the grant it came from, so revoking the refresh token left every access token
// from that grant working until it expired. A client that calls /revoke and
// receives 200 reasonably believes access has stopped -- §2 tells clients not to
// use the token afterwards, which only means something if the server stopped it.
//
// The fix names the grant on the access token (`gid`) and checks it at every
// place that already checked the per-jti denylist.

// revocableClient makes the fixture's client confidential so it can authenticate
// at /revoke, and returns its secret.
func revocableClient(t *testing.T, f *tokenFixture) string {
	t.Helper()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET client_type = 'confidential', client_secret_hash = $2
		 WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestRevokingARefreshTokenInvalidatesItsAccessTokens(t *testing.T) {
	f := newTokenFixture(t)
	secret := revocableClient(t, f)

	verifier := "verifier-revoke-cascade-aaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil,
		[]string{"openid", "offline_access"})
	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "client_secret": {secret},
		"redirect_uri": {"https://rp.test/cb"}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	accessToken := body["access_token"].(string)
	refreshToken := body["refresh_token"].(string)

	// Live before revocation, or the assertion afterwards proves nothing.
	c, err := f.srv.lookupClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	if resp := f.srv.introspectAccessToken(context.Background(), c, accessToken); resp == nil || !resp.Active {
		t.Fatal("the access token was not active before revocation")
	}

	// Revoke the REFRESH token only.
	req := httptest.NewRequest(http.MethodPost, oidc.PathRevocation,
		strings.NewReader(url.Values{
			"token":         {refreshToken},
			"client_id":     {f.clientID},
			"client_secret": {secret},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revocation gave %d: %s", rec.Code, rec.Body.String())
	}

	if resp := f.srv.introspectAccessToken(context.Background(), c, accessToken); resp != nil && resp.Active {
		t.Fatal("the access token is still active after its refresh token was " +
			"revoked; the client was told 200 and access did not stop")
	}
}

// A grant with no refresh token has no gid, and must be unaffected -- the check
// must not quietly invalidate every token that never had a family.
func TestATokenFromAGrantWithoutARefreshTokenIsUnaffected(t *testing.T) {
	f := newTokenFixture(t)
	verifier := "verifier-revoke-cascade-bbbbbbbbbbbbbbbbbbbb"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})

	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatal("this grant was not supposed to carry a refresh token")
	}

	c, err := f.srv.lookupClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	resp := f.srv.introspectAccessToken(context.Background(), c, body["access_token"].(string))
	if resp == nil || !resp.Active {
		t.Fatal("a token from a grant with no refresh family was reported " +
			"inactive: the cascade check must not fire when there is no grant")
	}
}

// newTestSecret mints a client secret the way the product does.
func newTestSecret(t *testing.T) (secret, hash string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	h, ok := clients.HashSecret(secret)
	if !ok {
		t.Skip("the fast secret hash is unavailable in this build")
	}
	return secret, h
}
