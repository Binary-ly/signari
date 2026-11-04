package httpapi

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
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

	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// Logout by artifact, both ways (8.08, saml-bindings-2.0-os lines 1103-1108). A
// provider's LogoutRequest is fetched from it and acted on only when it is the
// provider's own and signed, as on POST; the answer, and a logout this deployment
// starts, go back by artifact to an endpoint registered for them; and the provider's
// LogoutResponse by artifact moves this deployment's logout along.
func TestALogoutComesAndGoesByArtifact(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	pool := rf.f.pool
	sp := newSPSigner(t)
	var providerID string
	if err := pool.QueryRow(ctx, `UPDATE core.saml_providers SET sp_signing_cert = $2 WHERE entity_id = $1
		RETURNING id::text`, rf.own, sp.pem()).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	// The other provider holds the same certificate, so a request in its name is told
	// from this one's by who the artifact came from, and not by the signature alone.
	if _, err := pool.Exec(ctx, `UPDATE core.saml_providers SET sp_signing_cert = $2 WHERE entity_id = $1`,
		rf.foreign, sp.pem()); err != nil {
		t.Fatal(err)
	}
	const sloURL = "https://sp.test/slo"
	if _, err := pool.Exec(ctx, `INSERT INTO core.saml_slo_urls (provider_id, url, binding)
		VALUES ($1::uuid, $2, 'HTTP-Artifact')`, providerID, sloURL); err != nil {
		t.Fatal(err)
	}

	// The provider's resolution service, answering whatever it is told to.
	var mu sync.Mutex
	answer := func(*saml.ArtifactResolve) string { return "" }
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resolve, err := saml.ReadArtifactResolve(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		a := answer
		mu.Unlock()
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
	if _, err := pool.Exec(ctx, `INSERT INTO core.saml_artifact_resolution (provider_id, endpoint_index, url)
		VALUES ($1::uuid, 1, $2)`, providerID, service.URL+"/ars"); err != nil {
		t.Fatal(err)
	}
	answering := func(message func(*saml.ArtifactResolve) string) {
		mu.Lock()
		answer = func(r *saml.ArtifactResolve) string { return artifactAnswer(rf.own, r.ID, message(r)) }
		mu.Unlock()
	}

	// Signed in to the provider, so there is a participant to end.
	request := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `+
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_slo-%d" Version="2.0" IssueInstant="%s">`+
		`<saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`, time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), rf.own)
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write([]byte(request))
	_ = fw.Close()
	signIn := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes())), nil)
	signIn.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, signIn)
	if rec.Code != http.StatusOK {
		t.Fatalf("signing in: %d %.300s", rec.Code, rec.Body.String())
	}
	var sid, nameID, index string
	if err := pool.QueryRow(ctx, `SELECT sid, name_id, session_index FROM core.saml_session_participants
		WHERE provider_id = $1::uuid`, providerID).Scan(&sid, &nameID, &index); err != nil {
		t.Fatal(err)
	}
	live := func() bool {
		t.Helper()
		_, live, err := store.ResolveSessionCookie(ctx, pool, store.HashToken(rf.cookie), rf.f.srv.instanceID)
		if err != nil {
			t.Fatal(err)
		}
		return live
	}
	logoutRequest := func(signer spSigner, issuer string) string {
		t.Helper()
		if signer.key == nil {
			return `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
				`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_unsigned-` + fmt.Sprint(time.Now().UnixNano()) +
				`" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `"><saml:Issuer>` + issuer +
				`</saml:Issuer><saml:NameID>` + nameID + `</saml:NameID><samlp:SessionIndex>` + index +
				`</samlp:SessionIndex></samlp:LogoutRequest>`
		}
		doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{Issuer: issuer,
			Destination: rf.f.srv.cfg.Issuer + "/saml/slo", NameID: nameID, NameIDFormat: saml.NameIDFormatPersistent,
			SessionIndex: index, Now: time.Now()}, signer.key, signer.cert)
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	slo := func(artifact, relay string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/saml/slo?"+url.Values{"SAMLart": {artifact}, "RelayState": {relay}}.Encode(), nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	// resolveHere is the provider fetching, from this deployment, what an artifact it
	// was handed names.
	resolveHere := func(artifact string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader(sp.resolve(t, rf.own, artifact)))
		r.Header.Set("Content-Type", "text/xml")
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		return rec.Body.String()
	}

	// Unsigned, or in another provider's name: refused, and nothing ended.
	answering(func(*saml.ArtifactResolve) string { return logoutRequest(sp.withoutKey(), rf.own) })
	if rec := slo(sentArtifact(t, rf.own, 1), "relay"); rec.Code != http.StatusBadRequest || !live() {
		t.Fatalf("an unsigned logout by artifact: %d, session live %v", rec.Code, live())
	}
	answering(func(*saml.ArtifactResolve) string { return logoutRequest(sp, rf.foreign) })
	if rec := slo(sentArtifact(t, rf.own, 1), "relay"); rec.Code != http.StatusBadRequest || !live() {
		t.Fatalf("a logout by artifact in another provider's name: %d, session live %v", rec.Code, live())
	}

	// The provider's own, signed: the session ends, and the answer goes back by
	// artifact, which the provider resolves here to a LogoutResponse to its request.
	var sent string
	answering(func(*saml.ArtifactResolve) string {
		sent = logoutRequest(sp, rf.own)
		return sent
	})
	rec = slo(sentArtifact(t, rf.own, 1), "relay")
	if live() {
		t.Fatalf("the provider's signed logout by artifact ended nothing: %d %.300s", rec.Code, rec.Body.String())
	}
	back, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(rec.Header().Get("Location"), sloURL+"?") || back.Query().Get("RelayState") != "relay" {
		t.Fatalf("answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var req saml.LogoutRequest
	if err := saml.Unmarshal([]byte(sent), &req); err != nil {
		t.Fatal(err)
	}
	if got := resolveHere(back.Query().Get("SAMLart")); !strings.Contains(got, "LogoutResponse") ||
		!strings.Contains(got, `InResponseTo="`+req.ID+`"`) {
		t.Errorf("the provider resolving the answer's artifact got %.400s", got)
	}

	// A logout this deployment starts goes to that endpoint by artifact too.
	to, err := rf.f.srv.logoutRedirectFor(ctx, store.LogoutStep{ProviderID: providerID, EntityID: rf.own,
		SLOURL: sloURL, NameID: nameID, SessionIndex: index}, "chain-token")
	if err != nil {
		t.Fatal(err)
	}
	out, err := url.Parse(to)
	if err != nil || out.Query().Get("SAMLart") == "" || out.Query().Get("RelayState") != "chain-token" ||
		out.Query().Get("SAMLRequest") != "" {
		t.Fatalf("a logout started here went out as %q", to)
	}
	if got := resolveHere(out.Query().Get("SAMLart")); !strings.Contains(got, "LogoutRequest") ||
		!strings.Contains(got, nameID) {
		t.Errorf("the provider resolving the logout's artifact got %.400s", got)
	}

	// And the provider's LogoutResponse by artifact moves that logout on to where it
	// was going.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	token, err := store.BeginLogoutChain(ctx, tx, store.LogoutChain{OrgID: rf.f.orgID, SID: sid, UserID: rf.f.userID,
		Remaining: []store.LogoutStep{{ProviderID: providerID, EntityID: rf.own, SLOURL: sloURL, NameID: nameID,
			SessionIndex: index}}, FinalRedirect: "https://app.test/signed-out"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	answering(func(*saml.ArtifactResolve) string {
		return `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
			`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr-` + fmt.Sprint(time.Now().UnixNano()) +
			`" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `"><saml:Issuer>` + rf.own +
			`</saml:Issuer><samlp:Status><samlp:StatusCode Value="` + saml.StatusSuccess + `"/></samlp:Status></samlp:LogoutResponse>`
	})
	if rec := slo(sentArtifact(t, rf.own, 1), token); rec.Header().Get("Location") != "https://app.test/signed-out" {
		t.Errorf("the provider's LogoutResponse by artifact left the logout at %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
