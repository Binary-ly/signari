package httpapi

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A signed AuthnRequest is answered once (2.41). The table said it recorded
// signed AuthnRequests and nothing wrote one, so a captured request drew a
// fresh assertion every time it was replayed into a signed-in browser.
func TestASignedAuthnRequestIsAnsweredOnce(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()

	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &spKey.PublicKey, spKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers SET want_authn_requests_signed = true,
		sp_signing_cert = $2 WHERE entity_id = $1`, rf.own, certPEM); err != nil {
		t.Fatal(err)
	}

	signedQuery := func(id string) string {
		t.Helper()
		doc := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0"
 IssueInstant="%s" Destination="https://signin-test.example/saml/sso"
 AssertionConsumerServiceURL="https://sp.test/acs"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
			id, time.Now().UTC().Format(time.RFC3339), rf.own)
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.BestCompression)
		_, _ = w.Write([]byte(doc))
		_ = w.Close()
		q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes())) +
			"&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
		sum := sha256.Sum256([]byte(q))
		sig, err := rsa.SignPKCS1v15(rand.Reader, spKey, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	sso := func(query string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/saml/sso?"+query, nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		m := samlResponseField.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("no SAMLResponse in a %d answer: %.300s", rec.Code, rec.Body.String())
		}
		xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		return string(xml)
	}
	hasAssertion := func(doc string) bool {
		return strings.Contains(doc, "<saml:Assertion") || strings.Contains(doc, ":Assertion ")
	}

	q := signedQuery(fmt.Sprintf("_replay-%d", time.Now().UnixNano()))
	if !hasAssertion(sso(q)) {
		t.Fatal("a signed AuthnRequest did not draw an assertion the first time")
	}
	if replay := sso(q); hasAssertion(replay) || !strings.Contains(replay, "Requester") {
		t.Errorf("the same signed AuthnRequest replayed drew another answer: %.300s", replay)
	}
	if !hasAssertion(sso(signedQuery(fmt.Sprintf("_fresh-%d", time.Now().UnixNano())))) {
		t.Error("a different signed AuthnRequest was refused as a replay")
	}
}
