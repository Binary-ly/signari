package federation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// newClientKey is a key and a certificate for it, as PEM and parsed.
func newClientKey(t *testing.T) (keyPEM, certPEM []byte, key crypto.Signer, cert *x509.Certificate) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "signari-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	if cert, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), k, cert
}

// tokenEndpoint answers a code exchange and keeps what it was sent.
type tokenEndpoint struct {
	form  url.Values
	basic [2]string
	hasB  bool
	peer  []*x509.Certificate
}

func (e *tokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	e.form = r.PostForm
	e.basic[0], e.basic[1], e.hasB = r.BasicAuth()
	if r.TLS != nil {
		e.peer = r.TLS.PeerCertificates
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"a","id_token":"b","token_type":"Bearer"}`))
}

func exchange(t *testing.T, c Config, hc *http.Client, url string) {
	t.Helper()
	c.TokenOverride = url
	c.Preset = Preset{OIDC: true}
	if _, err := c.ExchangeCode(context.Background(), hc, "https://rp.test/cb", "code", "verifier"); err != nil {
		t.Fatalf("the exchange failed: %v", err)
	}
}

// The secret goes one way or the other and never both, so a provider that has
// been told to refuse it in the form never sees it there.
func TestAClientSecretGoesWhereTheMethodSays(t *testing.T) {
	e := &tokenEndpoint{}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)

	c := Config{ClientID: "our client", ClientSecret: "s&cret"}
	exchange(t, c, srv.Client(), srv.URL)
	if e.form.Get("client_secret") != "s&cret" || e.hasB {
		t.Errorf("the default sent form %q, basic %v", e.form.Get("client_secret"), e.hasB)
	}

	c.TokenAuth.Method = AuthSecretBasic
	exchange(t, c, srv.Client(), srv.URL)
	if e.form.Get("client_secret") != "" {
		t.Error("basic left the secret in the form")
	}
	if !e.hasB || e.basic[0] != "our+client" || e.basic[1] != "s%26cret" {
		t.Errorf("basic sent %q, each form-encoded as RFC 6749 section 2.3.1 has it", e.basic)
	}
}

// The assertion can be checked against the public key and nothing else, is for
// this client and this endpoint, and is good for this request; and no secret goes
// with it, which is the point of a provider with none.
func TestAPrivateKeyAssertionIsWhatAProviderChecks(t *testing.T) {
	e := &tokenEndpoint{}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	_, _, key, cert := newClientKey(t)

	c := Config{ClientID: "our-client", ClientSecret: "must-not-travel",
		TokenAuth: TokenAuth{Method: AuthPrivateKeyJWT, Key: key, Certificate: cert}}
	exchange(t, c, srv.Client(), srv.URL)
	if e.form.Get("client_secret") != "" || e.hasB {
		t.Error("a secret travelled with the assertion")
	}
	if e.form.Get("client_assertion_type") != clientAssertionType {
		t.Errorf("the assertion type is %q", e.form.Get("client_assertion_type"))
	}
	signed, err := jose.ParseSigned(e.form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Verify(key.Public())
	if err != nil {
		t.Fatalf("the assertion does not verify: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "our-client" || claims["sub"] != "our-client" || claims["aud"] != srv.URL ||
		claims["jti"] == "" || claims["jti"] == nil {
		t.Errorf("it says %v", claims)
	}
	if left := time.Until(time.Unix(int64(claims["exp"].(float64)), 0)); left <= 0 || left > assertionLifetime {
		t.Errorf("it lasts %s", left)
	}
	want := sha256.Sum256(cert.Raw)
	if got := signed.Signatures[0].Header.ExtraHeaders["x5t#S256"]; got != base64.RawURLEncoding.EncodeToString(want[:]) {
		t.Errorf("the certificate is named %v", got)
	}
	// SHA-1 panics under fips140=only, so there it must be left out and not tried.
	if named := signed.Signatures[0].Header.ExtraHeaders["x5t"] != nil; named == fips140.Enforced() {
		t.Errorf("x5t named %v, with FIPS enforced %v", named, fips140.Enforced())
	}

	first := e.form.Get("client_assertion")
	exchange(t, c, srv.Client(), srv.URL)
	if e.form.Get("client_assertion") == first {
		t.Error("an assertion was used twice")
	}
}

// The certificate is shown to the token endpoint at the connection, and the
// provider sees it; no secret or assertion goes with it.
func TestACertificateIsPresentedAtTheTokenEndpoint(t *testing.T) {
	e := &tokenEndpoint{}
	srv := httptest.NewUnstartedServer(e)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, _, key, cert := newClientKey(t)

	c := Config{ClientID: "our-client", ClientSecret: "must-not-travel",
		TokenAuth: TokenAuth{Method: AuthTLS, Key: key, Certificate: cert}}
	hc := srv.Client()
	before := hc.Transport.(*http.Transport).TLSClientConfig.Certificates
	exchange(t, c, hc, srv.URL)
	if len(e.peer) != 1 || !e.peer[0].Equal(cert) {
		t.Fatalf("the endpoint saw %d certificates", len(e.peer))
	}
	if e.form.Get("client_id") != "our-client" || e.form.Get("client_secret") != "" || e.form.Get("client_assertion") != "" {
		t.Errorf("the form was %v", e.form)
	}
	if len(hc.Transport.(*http.Transport).TLSClientConfig.Certificates) != len(before) {
		t.Error("the certificate was left on the shared client, for every other call to find")
	}
}

func TestAKeyAndCertificateMustBelongTogether(t *testing.T) {
	keyPEM, certPEM, _, _ := newClientKey(t)
	_, otherCert, _, _ := newClientKey(t)
	if _, _, err := ParseClientKey(keyPEM, certPEM); err != nil {
		t.Fatalf("a matching pair was refused: %v", err)
	}
	if _, _, err := ParseClientKey(keyPEM, nil); err != nil {
		t.Fatalf("a key alone was refused: %v", err)
	}
	if _, _, err := ParseClientKey(keyPEM, otherCert); err == nil || !strings.Contains(err.Error(), "not for this key") {
		t.Errorf("another key's certificate answered %v", err)
	}
	if _, _, err := ParseClientKey([]byte("not pem"), nil); err == nil {
		t.Error("rubbish was accepted")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseClientKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil); err == nil {
		t.Error("a curve no assertion here can use was accepted")
	}
}
