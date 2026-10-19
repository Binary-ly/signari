package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// A certificate-bound token is good only over a connection presenting that
// certificate, RFC 8705 §3 (specs/rfc8705.txt:433-438). The token endpoint
// bound tokens to the connection's certificate and no resource read
// `cnf.x5t#S256`, so the binding was a claim nothing checked: whoever held the
// token used it, certificate or not.

func over(cert *x509.Certificate) *tls.ConnectionState {
	if cert == nil {
		return nil
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

func TestUserinfoHoldsACertificateBoundTokenToItsCertificate(t *testing.T) {
	f := newTokenFixture(t)
	holder, thief := testCert(t, "holder"), testCert(t, "thief")
	k, err := f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
		Issuer: f.srv.cfg.Issuer, Subject: f.userID, Audience: []string{f.clientID},
		Expiry: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
		JTI: fmt.Sprintf("cert-userinfo-%d", now.UnixNano()), ClientID: f.clientID,
		Scope: "openid",
		Cnf:   &tokens.Confirmation{X5TS256: clientauth.CertificateThumbprint(holder)},
	}, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	ask := func(cert *x509.Certificate) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.TLS = over(cert)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("WWW-Authenticate")
	}
	for name, cert := range map[string]*x509.Certificate{"no certificate": nil, "another certificate": thief} {
		code, challenge := ask(cert)
		if code != http.StatusUnauthorized || !strings.Contains(challenge, `error="invalid_token"`) {
			t.Errorf("%s: userinfo answered %d %q, want 401 invalid_token (§3)", name, code, challenge)
		}
	}
	if code, _ := ask(holder); code != http.StatusOK {
		t.Fatalf("userinfo refused the token over its own certificate: %d", code)
	}
}

// mintCertBoundIssuanceToken is mintBoundIssuanceToken for a wallet whose
// client is registered for certificate-bound tokens and connected with cert.
func (f *tokenFixture) mintCertBoundIssuanceToken(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	ctx := context.Background()
	_, hash, err := store.NewPreAuthCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewPreAuthorizedCode(ctx, f.pool, f.orgID, f.userID, f.clientID,
		hash, []string{"IdentityCredential"}, nil, nil, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	stored, err := store.LookupPreAuthorizedCode(ctx, f.pool, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimPreAuthorizedCode(ctx, f.pool, stored.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSBoundTokens = true
	resp, _, err := f.srv.mintSet(withCertThumbprint(ctx, clientauth.CertificateThumbprint(cert)),
		tx, c, f.orgID, f.userID, "", "", []string{}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordPreAuthorizedToken(ctx, tx, stored.ID, resp.jti); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken
}

func TestACertificateBoundIssuanceTokenMintsOnlyOverItsCertificate(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	holder, thief := testCert(t, "wallet"), testCert(t, "thief")
	token := f.mintCertBoundIssuanceToken(t, holder)
	var claims tokens.AccessTokenClaims
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Cnf == nil || claims.Cnf.X5TS256 == "" {
		t.Fatalf("the fixture token is not certificate-bound: %s %v", payload, err)
	}
	ask := func(cert *x509.Certificate) (int, string) {
		wa := newWallet(t)
		_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
		nonce, _ := nb["c_nonce"].(string)
		body := `{"credential_configuration_id":"IdentityCredential",
		          "proofs":{"jwt":[` + mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce)) + `]}}`
		req := httptest.NewRequest(http.MethodPost, "/oid4vci/credential", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.TLS = over(cert)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := ask(thief); code != http.StatusUnauthorized {
		t.Fatalf("a stolen certificate-bound token minted over another certificate: %d %.200s", code, body)
	}
	if code, _ := ask(nil); code != http.StatusUnauthorized {
		t.Fatalf("a certificate-bound token minted with no certificate: %d", code)
	}
	if code, body := ask(holder); code != http.StatusOK {
		t.Fatalf("the wallet's own certificate was refused: %d %.200s", code, body)
	}
}

// The exchange and transaction tokens trade a subject token for a new one, so
// a certificate-bound subject token must come over its certificate too, or the
// exchange is the door the binding does not cover.
func TestACertificateBoundSubjectTokenNeedsItsCertificate(t *testing.T) {
	f := newTokenFixture(t)
	holder, thief := testCert(t, "subject-holder"), testCert(t, "thief")
	subject := &tokens.AccessTokenClaims{
		Cnf: &tokens.Confirmation{X5TS256: clientauth.CertificateThumbprint(holder)},
	}
	ask := func(cert *x509.Certificate) error {
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
		if cert != nil {
			r = r.WithContext(withCertThumbprint(r.Context(), clientauth.CertificateThumbprint(cert)))
		}
		return f.srv.requireSubjectTokenBinding(r, subject)
	}
	if err := ask(nil); err == nil {
		t.Error("a certificate-bound subject token was accepted with no certificate")
	}
	if err := ask(thief); err == nil {
		t.Error("a certificate-bound subject token was accepted over another certificate")
	}
	if err := ask(holder); err != nil {
		t.Errorf("the holder's own certificate was refused: %v", err)
	}
}
