package httpapi

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
)

var (
	signatureMethodAttr = regexp.MustCompile(`<ds:SignatureMethod Algorithm="([^"]+)"`)
	x509CertificateText = regexp.MustCompile(`<(?:[a-z]+:)?X509Certificate>([^<]+)</`)
)

// certificatesIn returns every X509Certificate a document carries, in order.
func certificatesIn(t *testing.T, doc string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, m := range x509CertificateText.FindAllStringSubmatch(doc, -1) {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(m[1]), ""))
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func holdsKey(certs []*x509.Certificate, pub crypto.PublicKey) bool {
	for _, c := range certs {
		if k, ok := c.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok && k.Equal(pub) {
			return true
		}
	}
	return false
}

// A provider set to ecdsa-sha256 is signed with the active ES256 key, the
// signature verifies in xmlsec1, and its tailored metadata carries that key's
// certificate. Every other reader of the metadata, and the provider once set
// back, gets RSA (3.15). There was no setting: every provider was signed with
// the RS256 key whatever it could verify.
func TestAProviderSetToECDSAIsSignedWithTheES256Key(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	es, err := rf.f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rf.f.srv.cfg.Keys.Active(keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	// The certificate is stored on the key's row, as the fixture does for RS256.
	if _, err := rf.f.pool.Exec(ctx, `
		INSERT INTO core.signing_keys (kid, instance_id, algorithm, state, public_jwk, key_ref)
		SELECT $1, instance_id, 'ES256', 'passive', '{}', 'test:in-memory'
		  FROM core.organizations WHERE id = $2::uuid`, es.KID(), rf.f.orgID); err != nil {
		t.Fatal(err)
	}
	setAlg := func(alg string) {
		t.Helper()
		if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers SET signature_alg = $2
			WHERE entity_id = $1`, rf.own, alg); err != nil {
			t.Fatal(err)
		}
	}
	metadata := func(query string) []*x509.Certificate {
		t.Helper()
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/metadata"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("metadata%s: %d %.200s", query, rec.Code, rec.Body.String())
		}
		return certificatesIn(t, rec.Body.String())
	}

	setAlg("ecdsa-sha256")
	doc := rf.samlResponse(t)
	if m := signatureMethodAttr.FindStringSubmatch(doc); m == nil ||
		m[1] != "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" {
		t.Fatalf("a provider set to ecdsa-sha256 was signed with %v", m)
	}
	certs := certificatesIn(t, doc)
	if len(certs) != 1 || !holdsKey(certs, es.Signer().Public()) {
		t.Fatalf("the signature does not carry the active ES256 key's certificate")
	}
	xmlsec1VerifiesAssertion(t, doc, certs[0])

	if own := metadata("?sp=" + url.QueryEscape(rf.own)); !holdsKey(own, es.Signer().Public()) ||
		holdsKey(own, rs.Signer().Public()) {
		t.Error("the provider's tailored metadata does not carry the ES256 certificate alone")
	}
	if def := metadata(""); !holdsKey(def, rs.Signer().Public()) || holdsKey(def, es.Signer().Public()) {
		t.Error("the default metadata does not carry the RS256 certificate alone")
	}

	setAlg("rsa-sha256")
	doc = rf.samlResponse(t)
	if m := signatureMethodAttr.FindStringSubmatch(doc); m == nil ||
		m[1] != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		t.Fatalf("set back to rsa-sha256, the provider was signed with %v", m)
	}
	if !holdsKey(certificatesIn(t, doc), rs.Signer().Public()) {
		t.Error("set back to rsa-sha256, the signature does not carry the RS256 certificate")
	}
}

// xmlsec1VerifiesAssertion checks the assertion's signature with xmlsec1, the
// reference implementation, against the certificate as a provider holds it.
func xmlsec1VerifiesAssertion(t *testing.T, doc string, cert *x509.Certificate) {
	t.Helper()
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Log("xmlsec1 not installed; the independent check is skipped")
		return
	}
	dir := t.TempDir()
	docPath, certPath := filepath.Join(dir, "response.xml"), filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(docPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--verify", "--trusted-pem", certPath,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response",
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
		"--node-xpath", "//*[local-name()='Assertion']/*[local-name()='Signature']", docPath).CombinedOutput()
	if err != nil {
		t.Fatalf("xmlsec1 rejected the assertion:\n%s", out)
	}
}
