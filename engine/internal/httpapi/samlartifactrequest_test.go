package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/saml"
)

// sentArtifact is an artifact a service provider issued: its entity id's SHA-1 and the
// index of the service that resolves it (saml-bindings-2.0-os lines 1052-1078).
func sentArtifact(t *testing.T, entityID string, index uint16) string {
	t.Helper()
	handle := make([]byte, 20)
	if _, err := rand.Read(handle); err != nil {
		t.Fatal(err)
	}
	raw := binary.BigEndian.AppendUint16(nil, 0x0004)
	raw = binary.BigEndian.AppendUint16(raw, index)
	raw = append(append(raw, saml.SourceID(entityID)...), handle...)
	return base64.StdEncoding.EncodeToString(raw)
}

// authnRequest is the provider's request, signed by sp when it has a key.
func (s spSigner) authnRequest(t *testing.T, issuer string) string {
	t.Helper()
	doc := etree.NewDocument()
	el := doc.CreateElement("samlp:AuthnRequest")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("ID", fmt.Sprintf("_byart-%d", time.Now().UnixNano()))
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	el.CreateElement("saml:Issuer").SetText(issuer)
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
	return out
}

// artifactAnswer is what a provider's resolution service sends back.
func artifactAnswer(issuer, inResponseTo, message string) string {
	return saml.SOAPEnvelope(`<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_answer-` + fmt.Sprint(time.Now().UnixNano()) +
		`" InResponseTo="` + inResponseTo + `" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) +
		`"><saml:Issuer>` + issuer + `</saml:Issuer><samlp:Status><samlp:StatusCode ` +
		`Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` + message + `</samlp:ArtifactResponse>`)
}

// A provider registered with an artifact resolution service sends its AuthnRequest by
// artifact: it is fetched from there with an ArtifactResolve signed here, and handled as
// the request it is, to a response for the provider (8.08, saml-bindings-2.0-os lines
// 1109-1126). An artifact is fetched once, an answer that is not the provider's own
// request is refused, and a provider requiring signed requests still gets only those.
func TestAProviderSendsItsRequestByArtifact(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	sp := newSPSigner(t)
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers SET sp_signing_cert = $2 WHERE entity_id = $1`,
		rf.own, sp.pem()); err != nil {
		t.Fatal(err)
	}

	// The provider's resolution service: it answers whatever answer says for the
	// ArtifactResolve it is sent, and keeps what it was sent.
	var mu sync.Mutex
	var resolves []*saml.ArtifactResolve
	answer := func(r *saml.ArtifactResolve) string { return "" }
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resolve, err := saml.ReadArtifactResolve(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		resolves = append(resolves, resolve)
		a := answer
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, a(resolve))
	}))
	t.Cleanup(service.Close)
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: service.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safedial.TrustBundle(bundle); err != nil {
		t.Fatal(err)
	}
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.TrustBundle(""); _ = safedial.AllowPrivate("") })
	if _, err := rf.f.pool.Exec(ctx, `
		INSERT INTO core.saml_artifact_resolution (provider_id, endpoint_index, url)
		SELECT id, 1, $2 FROM core.saml_providers WHERE entity_id = $1`, rf.own, service.URL+"/ars"); err != nil {
		t.Fatal(err)
	}

	sso := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	byArtifact := func(artifact string) *httptest.ResponseRecorder {
		return sso("/saml/sso?" + url.Values{"SAMLart": {artifact}, "RelayState": {"kept"}}.Encode())
	}
	answering := func(f func(*saml.ArtifactResolve) string) {
		mu.Lock()
		answer = f
		mu.Unlock()
	}

	// The provider's own request, unsigned, its answer unsigned too.
	answering(func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.own, r.ID, sp.withoutKey().authnRequest(t, rf.own))
	})
	artifact := sentArtifact(t, rf.own, 1)
	rec := byArtifact(artifact)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the artifact was answered %d: %.400s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("what the artifact was exchanged for may be cached: %q", got)
	}
	mu.Lock()
	sent := resolves[len(resolves)-1]
	mu.Unlock()
	if sent.Artifact != artifact || sent.Destination != service.URL+"/ars" || sent.Issuer == "" {
		t.Errorf("the provider was sent %+v", sent)
	}
	var alg string
	if err := rf.f.pool.QueryRow(ctx, `SELECT signature_alg FROM core.saml_providers WHERE entity_id = $1`,
		rf.own).Scan(&alg); err != nil {
		t.Fatal(err)
	}
	key, err := rf.f.srv.samlSigningKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	der, err := rf.f.srv.samlCertificateFor(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := sent.VerifySignature(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))); err != nil {
		t.Errorf("the ArtifactResolve sent is not signed by this identity provider: %v", err)
	}
	next, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || next.Path != "/saml/sso" || next.Query().Get("Binding") != "POST" ||
		next.Query().Get("RelayState") != "kept" || next.Query().Get("SAMLRequest") == "" {
		t.Fatalf("sent on to %q", rec.Header().Get("Location"))
	}
	rec = sso(next.String())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SAMLResponse") ||
		!strings.Contains(rec.Body.String(), "https://sp.test/acs") {
		t.Fatalf("the request fetched by artifact was answered %d: %.400s", rec.Code, rec.Body.String())
	}

	// Once: brought again, it is refused, and the provider is not asked again.
	mu.Lock()
	asked := len(resolves)
	mu.Unlock()
	if rec := byArtifact(artifact); rec.Code != http.StatusBadRequest {
		t.Errorf("an artifact brought twice was answered %d", rec.Code)
	}
	mu.Lock()
	again := len(resolves)
	mu.Unlock()
	if again != asked {
		t.Error("the provider was asked again for an artifact already resolved")
	}

	// Signed out: the request is held across the sign-in still as the POST-encoded one it
	// was handed on as, and answered after it. Parked by the method alone, it came back
	// as the redirect binding and was refused once the password was in (Shibboleth).
	answering(func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.own, r.ID, sp.withoutKey().authnRequest(t, rf.own))
	})
	anon := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(anon, httptest.NewRequest(http.MethodGet,
		"/saml/sso?"+url.Values{"SAMLart": {sentArtifact(t, rf.own, 1)}}.Encode(), nil))
	handedOn := anon.Header().Get("Location")
	anon = httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(anon, httptest.NewRequest(http.MethodGet, handedOn, nil))
	login, err := url.Parse(anon.Header().Get("Location"))
	if err != nil || anon.Code != http.StatusSeeOther {
		t.Fatalf("signed out, the request handed on was answered %d %q", anon.Code, anon.Header().Get("Location"))
	}
	resume, ok := parkedReturn(login.Query().Get("authz"))
	if !ok || !strings.Contains(resume, "Binding=POST") {
		t.Fatalf("the request is held across the sign-in as %q", resume)
	}
	if rec := sso(resume); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Errorf("after the sign-in the request was answered %d: %s", rec.Code, refusalReason(rec.Body.String()))
	}

	refused := func(why string, artifact string, f func(*saml.ArtifactResolve) string) {
		t.Helper()
		answering(f)
		if rec := byArtifact(artifact); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: answered %d", why, rec.Code)
		}
	}
	own := func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.own, r.ID, sp.withoutKey().authnRequest(t, rf.own))
	}
	refused("an artifact naming no provider registered here", sentArtifact(t, "urn:test:nobody", 1), own)
	refused("an index the provider has no service at", sentArtifact(t, rf.own, 2), own)
	refused("an answer with nothing in it", sentArtifact(t, rf.own, 1), func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.own, r.ID, "")
	})
	refused("an answer from another issuer", sentArtifact(t, rf.own, 1), func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.foreign, r.ID, sp.withoutKey().authnRequest(t, rf.own))
	})
	refused("an answer to some other request", sentArtifact(t, rf.own, 1), func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.own, "_not-"+r.ID, sp.withoutKey().authnRequest(t, rf.own))
	})
	refused("a request in another provider's name", sentArtifact(t, rf.own, 1), func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.own, r.ID, sp.withoutKey().authnRequest(t, rf.foreign))
	})
	refused("a logout where a sign-in was expected", sentArtifact(t, rf.own, 1), func(r *saml.ArtifactResolve) string {
		return artifactAnswer(rf.own, r.ID, strings.Replace(strings.Replace(sp.withoutKey().authnRequest(t, rf.own),
			"samlp:AuthnRequest", "samlp:LogoutRequest", 1), "</samlp:AuthnRequest>", "</samlp:LogoutRequest>", 1))
	})

	// A provider requiring signed requests: its unsigned request is refused on the way
	// in, as it would be arriving by POST, and its signed one is answered.
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers SET want_authn_requests_signed = true
		WHERE entity_id = $1`, rf.own); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		signer spSigner
		want   int
	}{{"unsigned", sp.withoutKey(), http.StatusBadRequest}, {"signed", sp, http.StatusOK}} {
		answering(func(r *saml.ArtifactResolve) string {
			return artifactAnswer(rf.own, r.ID, c.signer.authnRequest(t, rf.own))
		})
		rec := byArtifact(sentArtifact(t, rf.own, 1))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: the artifact was answered %d: %.300s", c.name, rec.Code, rec.Body.String())
		}
		if rec := sso(rec.Header().Get("Location")); rec.Code != c.want {
			t.Errorf("a %s request where signed ones are required was answered %d, want %d: %s", c.name,
				rec.Code, c.want, refusalReason(rec.Body.String()))
		}
	}
}

// refusalReason is the part of a refusal page that says why, for a failure message.
func refusalReason(page string) string {
	if i := strings.Index(page, "<main"); i >= 0 {
		page = page[i:]
	}
	if len(page) > 600 {
		page = page[:600]
	}
	return page
}

// withoutKey is the provider sending unsigned.
func (s spSigner) withoutKey() spSigner { return spSigner{cert: s.cert} }
