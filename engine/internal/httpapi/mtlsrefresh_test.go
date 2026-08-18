package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
)

// RFC 8705 §4:
//
//	"When the authorization server issues a refresh token to such a client, it
//	SHOULD also bind the refresh token to the respective certificate and check
//	the binding when the refresh token is presented to get new access tokens."
//
// The mutual-TLS twin of the DPoP defect. "Such a client" is §4's public client:
// one presenting a certificate to obtain certificate-BOUND tokens without using
// it to authenticate. §7.1 exempts confidential clients, whose refresh tokens are
// already "indirectly certificate-bound by way of the client ID and the
// associated requirement for (certificate-based) authentication".

func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// postCert is f.post over a connection presenting a client certificate.
func (f *tokenFixture) postCert(t *testing.T, form url.Values, cert *x509.Certificate) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// enableBoundTokens registers the client for certificate-bound tokens.
//
// Off by default, and rightly: flipping binding on breaks every caller that does
// not present the certificate at the resource server. A test that forgot this
// would get plain bearer tokens and prove nothing, which is exactly what the
// first run of this file did.
func (f *tokenFixture) enableBoundTokens(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET tls_bound_tokens = true WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
}

// certConfirmationIn reads RFC 8705 §3.1's cnf.x5t#S256 from a signed token.
func certConfirmationIn(t *testing.T, at string) string {
	t.Helper()
	parts := strings.Split(at, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWS: %q", at)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Cnf struct {
			X5T string `json:"x5t#S256"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Cnf.X5T
}

func (f *tokenFixture) certBoundRefreshToken(t *testing.T, cert *x509.Certificate,
	verifier string) string {

	t.Helper()
	f.enableBoundTokens(t)
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil,
		[]string{"openid", "offline_access"})

	status, body := f.postCert(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}, cert)
	if status != http.StatusOK {
		t.Fatalf("redemption over mTLS gave %d: %v", status, body)
	}
	// A certificate-bound token is still token_type "Bearer" -- RFC 8705 signals
	// the binding with the `cnf.x5t#S256` claim, not the token type, unlike DPoP.
	// Checked because without it the client might not be registered for bound
	// tokens at all, and every assertion below would pass vacuously.
	if thumb := certConfirmationIn(t, body["access_token"].(string)); thumb == "" {
		t.Fatal("the access token carries no cnf.x5t#S256, so this grant is not " +
			"certificate-bound and the test cannot show a binding is enforced")
	}
	rt, ok := body["refresh_token"].(string)
	if !ok {
		t.Fatalf("no refresh token issued: %v", body)
	}
	return rt
}

func TestARefreshTokenCannotBeUsedWithADifferentCertificate(t *testing.T) {
	f := newTokenFixture(t)
	mine := testCert(t, "legitimate-client")
	theirs := testCert(t, "someone-else")

	rt := f.certBoundRefreshToken(t, mine, "verifier-mtls-refresh-aaaaaaaaaaaaaaaaaaaaaa")

	status, body := f.postCert(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {f.clientID},
	}, theirs)

	if status == http.StatusOK {
		t.Fatalf("a certificate-bound refresh token was accepted over a connection "+
			"using a different certificate; the access tokens it mints claim a "+
			"binding to a key the presenter does not hold: %v", body)
	}
}

func TestACertBoundRefreshTokenIsRefusedWithNoCertificate(t *testing.T) {
	f := newTokenFixture(t)
	cert := testCert(t, "legitimate-client")
	rt := f.certBoundRefreshToken(t, cert, "verifier-mtls-refresh-bbbbbbbbbbbbbbbbbbbbbb")

	status, body := f.postCert(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {f.clientID},
	}, nil)

	if status == http.StatusOK {
		t.Fatalf("dropping the client certificate escaped the binding entirely: %v", body)
	}
}

func TestTheBoundCertificateStillRefreshesSuccessfully(t *testing.T) {
	f := newTokenFixture(t)
	cert := testCert(t, "legitimate-client")
	rt := f.certBoundRefreshToken(t, cert, "verifier-mtls-refresh-cccccccccccccccccccccc")

	status, body := f.postCert(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {f.clientID},
	}, cert)
	if status != http.StatusOK {
		t.Fatalf("the bound certificate was refused its own refresh token: %d %v",
			status, body)
	}

	// And across a second rotation, for the reason §4 gives: the check happens
	// "when the refresh token is presented", every time, not once at issuance.
	rotated := body["refresh_token"].(string)
	status, _ = f.postCert(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rotated},
		"client_id": {f.clientID},
	}, testCert(t, "someone-else"))
	if status == http.StatusOK {
		t.Fatal("the successor token accepted a different certificate: the binding " +
			"held for one rotation and was lost at the next")
	}
}
