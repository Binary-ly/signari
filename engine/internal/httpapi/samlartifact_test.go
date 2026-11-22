package httpapi

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// spSigner is a service provider's signing key and its certificate, as a
// provider registers it.
type spSigner struct {
	key  *rsa.PrivateKey
	cert []byte
}

func newSPSigner(t *testing.T) spSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "sp.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "sp.test"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return spSigner{key, der}
}

func (s spSigner) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert}))
}

// resolve is what the provider sends to the artifact resolution service: an
// ArtifactResolve, signed by s unless s has no key.
func (s spSigner) resolve(t *testing.T, issuer, artifact string) string {
	t.Helper()
	doc := etree.NewDocument()
	el := doc.CreateElement("samlp:ArtifactResolve")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("ID", fmt.Sprintf("_resolve-%d", time.Now().UnixNano()))
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	el.CreateElement("saml:Issuer").SetText(issuer)
	el.CreateElement("samlp:Artifact").SetText(artifact)
	if s.key != nil {
		ctx, err := dsig.NewSigningContext(s.key, [][]byte{s.cert})
		if err != nil {
			t.Fatal(err)
		}
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		signed, err := ctx.SignEnveloped(el)
		if err != nil {
			t.Fatal(err)
		}
		doc.SetRoot(signed)
	}
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return `<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"><soap11:Body>` +
		out + `</soap11:Body></soap11:Envelope>`
}

// A provider registered to take its response by artifact is sent one through
// the browser, fetches the response with it once, signed as itself, and nobody
// else gets anything (8.08).
func TestAProviderFetchesItsResponseByArtifact(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	sp := newSPSigner(t)
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers SET sp_signing_cert = $2 WHERE entity_id = $1`,
		rf.own, sp.pem()); err != nil {
		t.Fatal(err)
	}
	if _, err := rf.f.pool.Exec(ctx, `
		INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
		SELECT id, 'https://sp.test/artifact', 'HTTP-Artifact', false FROM core.saml_providers WHERE entity_id = $1`,
		rf.own); err != nil {
		t.Fatal(err)
	}

	request := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_art-%d" Version="2.0"
 IssueInstant="%s" Destination="https://signin-test.example/saml/sso"
 AssertionConsumerServiceURL="https://sp.test/artifact"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), rf.own)
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(request))
	_ = w.Close()
	r := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+
		url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))+"&RelayState=kept", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the sign-in answered %d, not a redirect carrying an artifact: %.300s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Error("the response crossed the browser as well")
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("the artifact may be cached: %q", got)
	}
	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || to.Host != "sp.test" || to.Path != "/artifact" {
		t.Fatalf("sent to %q", rec.Header().Get("Location"))
	}
	artifact := to.Query().Get("SAMLart")
	if artifact == "" || to.Query().Get("RelayState") != "kept" {
		t.Fatalf("the redirect carries %q", to.RawQuery)
	}

	resolve := func(body string) (int, string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	carries := func(answer string) bool { return strings.Contains(answer, "<samlp:Response ") }

	// Asked for by somebody else, or unsigned: an empty answer, and the artifact gone.
	if code, answer := resolve(newSPSigner(t).resolve(t, rf.own, artifact)); code != http.StatusOK ||
		carries(answer) || !strings.Contains(answer, "status:Success") {
		t.Errorf("a resolve signed with another key: %d, carrying the response %v", code, carries(answer))
	}
	if _, answer := resolve(sp.resolve(t, rf.own, artifact)); carries(answer) {
		t.Error("the artifact was given out after a refused attempt; it is single-use")
	}

	// A fresh one, fetched properly, once.
	fresh := func(n int) string {
		t.Helper()
		buf.Reset()
		w.Reset(&buf)
		_, _ = w.Write([]byte(strings.Replace(request, `ID="_art-`, fmt.Sprintf(`ID="_art%d-`, n), 1)))
		_ = w.Close()
		r := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+
			url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes())), nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		to, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || to.Query().Get("SAMLart") == "" {
			t.Fatalf("no second artifact: %d %q", rec.Code, rec.Header().Get("Location"))
		}
		return to.Query().Get("SAMLart")
	}
	second := fresh(2)
	if _, answer := resolve(spSigner{}.resolve(t, rf.own, second)); carries(answer) {
		t.Error("an unsigned resolve was given the response")
	}
	third := fresh(3)
	code, answer := resolve(sp.resolve(t, rf.own, third))
	if code != http.StatusOK || !carries(answer) || !strings.Contains(answer, "<samlp:ArtifactResponse ") {
		t.Fatalf("the provider's own resolve: %d\n%.500s", code, answer)
	}
	if !strings.Contains(answer, `Destination="https://sp.test/artifact"`) {
		t.Error("the response inside is not addressed to the artifact URL")
	}
	if _, again := resolve(sp.resolve(t, rf.own, third)); carries(again) {
		t.Error("the artifact was resolved twice")
	}

	// Signed with the right key in another provider's name: nothing.
	if _, answer := resolve(sp.resolve(t, rf.foreign, fresh(4))); carries(answer) {
		t.Error("a resolve naming another provider was given the response")
	}
	// Past its minute: nothing.
	late := fresh(5)
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_artifacts SET expires_at = now() - interval '1 second'
		WHERE provider_id = (SELECT id FROM core.saml_providers WHERE entity_id = $1)`, rf.own); err != nil {
		t.Fatal(err)
	}
	if _, answer := resolve(sp.resolve(t, rf.own, late)); carries(answer) {
		t.Error("an expired artifact was resolved")
	}

	// Not SOAP at all: a fault.
	if code, answer := resolve("<nonsense/>"); code != http.StatusInternalServerError || !strings.Contains(answer, "Fault") {
		t.Errorf("a request that is not an ArtifactResolve: %d %.200s", code, answer)
	}
}
