package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// samlUpstream is a SAML upstream with nothing asked of it.
type samlUpstream struct {
	f          *signInFixture
	slug       string
	providerID string
	// What the upstream signs its responses with.
	signer  saml.SPKey
	certDER []byte
}

func newSAMLUpstream(t *testing.T) *samlUpstream {
	t.Helper()
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	pkcs8, certPEM, err := saml.NewSPKey("https://upstream.test", saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := saml.ParseSPKey(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	u := &samlUpstream{f: f, slug: fmt.Sprintf("src-%d", time.Now().UnixNano()), signer: signer, certDER: block.Bytes}
	if err := f.pool.QueryRow(context.Background(), `WITH ip AS (
		  INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
		  VALUES ($1::uuid, $2, 'Upstream', 'saml', '', '{}') RETURNING id
		)
		INSERT INTO core.saml_sources (provider_id, org_id, entity_id, sso_url, cert_pem)
		SELECT id, $1::uuid, 'https://upstream.test/idp', 'https://upstream.test/sso', $3 FROM ip
		RETURNING provider_id::text`, f.orgID, u.slug, certPEM).Scan(&u.providerID); err != nil {
		t.Fatal(err)
	}
	return u
}

func (u *samlUpstream) get(path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	u.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/source/"+u.slug+path, nil))
	return rec
}

// The whole of it from the operator's side: a key made and published, the upstream
// held to it, and the request that then goes out verifying against the certificate
// the metadata handed over, and nothing else.
func TestAnUpstreamIsSentRequestsSignedByTheKeyItsMetadataPublishes(t *testing.T) {
	u := newSAMLUpstream(t)
	ctx, pool, root := context.Background(), u.f.pool, u.f.srv.root
	on, off := true, false

	if rec := u.get("/metadata"); !strings.Contains(rec.Body.String(), `AuthnRequestsSigned="false"`) ||
		strings.Contains(rec.Body.String(), "KeyDescriptor") {
		t.Fatalf("metadata before any key: %s", rec.Body.String())
	}
	if err := store.SetSAMLSourceKeyUse(ctx, pool, u.f.orgID, u.slug, &on, nil); err == nil {
		t.Fatal("held to signing with no key to sign with")
	}

	key, err := store.AddSAMLSourceKey(ctx, pool, root, u.f.orgID, u.slug, saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	if rec := u.get("/start"); strings.Contains(rec.Header().Get("Location"), "Signature=") {
		t.Fatalf("signed before it was asked to be: %s", rec.Header().Get("Location"))
	}
	if err := store.SetSAMLSourceKeyUse(ctx, pool, u.f.orgID, u.slug, &on, nil); err != nil {
		t.Fatal(err)
	}

	metadata := u.get("/metadata").Body.String()
	block, _ := pem.Decode([]byte(key.Certificate))
	if !strings.Contains(metadata, `AuthnRequestsSigned="true"`) || !strings.Contains(metadata, `<KeyDescriptor use="signing">`) ||
		!strings.Contains(metadata, saml.CertificateB64(block.Bytes)) {
		t.Fatalf("metadata does not publish the key: %s", metadata)
	}

	rec := u.get("/start")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther {
		t.Fatalf("starting: %d %v", rec.Code, err)
	}
	if err := saml.VerifyRedirectSignature(loc.RawQuery, key.Certificate, "SAMLRequest"); err != nil {
		t.Fatalf("the request did not verify against the published certificate: %v", err)
	}

	// A newer key signs, the older stays published for the overlap, and a retired
	// one goes.
	newer, err := store.AddSAMLSourceKey(ctx, pool, root, u.f.orgID, u.slug, saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.saml_source_keys SET created_at = now() + interval '1 minute' WHERE id = $1::uuid`, newer.ID); err != nil {
		t.Fatal(err)
	}
	loc, err = url.Parse(u.get("/start").Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if err := saml.VerifyRedirectSignature(loc.RawQuery, newer.Certificate, "SAMLRequest"); err != nil {
		t.Errorf("the newest key did not sign: %v", err)
	}
	if err := store.RetireSAMLSourceKey(ctx, pool, u.f.orgID, u.slug, key.ID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.get("/metadata").Body.String(), saml.CertificateB64(block.Bytes)) {
		t.Error("a retired key is still published")
	}
	if err := store.RetireSAMLSourceKey(ctx, pool, u.f.orgID, u.slug, newer.ID); err == nil {
		t.Error("the last key the upstream is held to was retired")
	}
	if err := store.SetSAMLSourceKeyUse(ctx, pool, u.f.orgID, u.slug, &off, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireSAMLSourceKey(ctx, pool, u.f.orgID, u.slug, newer.ID); err != nil {
		t.Errorf("a key nothing is held to was kept: %v", err)
	}
}

// post carries a response from the upstream to the real ACS, encrypted to encryptTo
// when it is given, and says whether a session came of it.
func (u *samlUpstream) post(t *testing.T, encryptTo string) bool {
	t.Helper()
	doc, err := saml.BuildResponse(saml.ResponseInput{Issuer: "https://upstream.test/idp",
		Destination: u.f.srv.cfg.Issuer + "/saml/source/" + u.slug + "/acs", Audience: u.f.srv.cfg.Issuer,
		Lifetime: 2 * time.Minute, Now: time.Now(), EncryptionCert: encryptTo,
		Subject: saml.Subject{NameID: "ada-at-upstream", NameIDFormat: saml.NameIDFormatPersistent, AuthnInstant: time.Now()}},
		"k1", u.signer, u.certDER)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(doc))}}
	r := httptest.NewRequest(http.MethodPost, "/saml/source/"+u.slug+"/acs", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.f.srv.Routes().ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}

// From the key's making to a person signed in through it, by the real ACS: an
// upstream encrypting to the certificate in the metadata gets its assertion read, and
// one held to encrypting gets a plain one refused.
func TestAnEncryptedAssertionSignsAPersonIn(t *testing.T) {
	u := newSAMLUpstream(t)
	ctx, pool, root := context.Background(), u.f.pool, u.f.srv.root
	on := true
	if _, err := pool.Exec(ctx, `UPDATE core.saml_sources SET allow_unsolicited = true WHERE provider_id = $1::uuid`, u.providerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'ada-at-upstream')`, u.providerID, u.f.userID, u.f.orgID); err != nil {
		t.Fatal(err)
	}
	key, err := store.AddSAMLSourceKey(ctx, pool, root, u.f.orgID, u.slug, saml.SPKeyEncryption)
	if err != nil {
		t.Fatal(err)
	}
	metadata := u.get("/metadata").Body.String()
	block, _ := pem.Decode([]byte(key.Certificate))
	if !strings.Contains(metadata, `<KeyDescriptor use="encryption">`) || !strings.Contains(metadata, saml.CertificateB64(block.Bytes)) ||
		!strings.Contains(metadata, `<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>`) {
		t.Fatalf("metadata does not offer the key: %s", metadata)
	}

	if !u.post(t, "") {
		t.Fatal("a plain assertion was refused from an upstream nothing holds to encrypting")
	}
	if !u.post(t, key.Certificate) {
		t.Fatal("an encrypted assertion did not sign the person in")
	}
	if err := store.SetSAMLSourceKeyUse(ctx, pool, u.f.orgID, u.slug, nil, &on); err != nil {
		t.Fatal(err)
	}
	if u.post(t, "") {
		t.Error("a plain assertion was taken from an upstream held to encrypting")
	}
	if !u.post(t, key.Certificate) {
		t.Error("an encrypted one was refused")
	}
	stray, err := store.AddSAMLSourceKey(ctx, pool, root, u.f.orgID, u.slug, saml.SPKeyEncryption)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RetireSAMLSourceKey(ctx, pool, u.f.orgID, u.slug, key.ID); err != nil {
		t.Fatal(err)
	}
	if u.post(t, key.Certificate) {
		t.Error("an assertion encrypted to a retired key was read")
	}
	if !u.post(t, stray.Certificate) {
		t.Error("the key that replaced it does not work")
	}
}

// signedInThrough is a person with a session that came through the upstream, and the
// cookies their browser holds for it.
func (u *samlUpstream) signedInThrough(t *testing.T) []*http.Cookie {
	t.Helper()
	doc, err := saml.BuildResponse(saml.ResponseInput{Issuer: "https://upstream.test/idp",
		Destination: u.f.srv.cfg.Issuer + "/saml/source/" + u.slug + "/acs", Audience: u.f.srv.cfg.Issuer,
		Lifetime: 2 * time.Minute, Now: time.Now(),
		Subject: saml.Subject{NameID: "ada-at-upstream", NameIDFormat: saml.NameIDFormatPersistent,
			SessionIndex: "upstream-session-1", AuthnInstant: time.Now()}}, "k1", u.signer, u.certDER)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(doc))}}
	r := httptest.NewRequest(http.MethodPost, "/saml/source/"+u.slug+"/acs", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.f.srv.Routes().ServeHTTP(rec, r)
	return rec.Result().Cookies()
}

// sessionsLeft counts the person's live sessions.
func (u *samlUpstream) sessionsLeft(t *testing.T) int {
	t.Helper()
	var n int
	if err := u.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions
		WHERE user_id = $1::uuid AND revoked_at IS NULL`, u.f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// upstreamLogout is the upstream's request to end somebody's session, signed by it.
func (u *samlUpstream) upstreamLogout(t *testing.T, nameID string, signer saml.SPKey, certDER []byte) *httptest.ResponseRecorder {
	t.Helper()
	doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{Issuer: "https://upstream.test/idp",
		Destination: u.f.srv.cfg.Issuer + "/saml/source/" + u.slug + "/slo", NameID: nameID,
		NameIDFormat: saml.NameIDFormatPersistent, Now: time.Now()}, signer, certDER)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := saml.EncodeRedirect(doc)
	if err != nil {
		t.Fatal(err)
	}
	query, err := saml.SignRedirectQuery("SAMLRequest", encoded, "their-state", signer)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	u.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/source/"+u.slug+"/slo?"+query, nil))
	return rec
}

// logoutReady is an upstream with an address to sign out at, a key to sign with and
// the person linked to it.
func (u *samlUpstream) logoutReady(t *testing.T) string {
	t.Helper()
	ctx, pool := context.Background(), u.f.pool
	if _, err := pool.Exec(ctx, `UPDATE core.saml_sources SET allow_unsolicited = true WHERE provider_id = $1::uuid`, u.providerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.identity_providers SET end_session_url = 'https://upstream.test/slo?tenant=a'
		WHERE id = $1::uuid`, u.providerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'ada-at-upstream')`, u.providerID, u.f.userID, u.f.orgID); err != nil {
		t.Fatal(err)
	}
	k, err := store.AddSAMLSourceKey(ctx, pool, u.f.srv.root, u.f.orgID, u.slug, saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	return k.Certificate
}

// signOut goes through the confirmation the endpoint asks for, as a browser does.
func (u *samlUpstream) signOut(t *testing.T, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	h := u.f.srv.Routes()
	get := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	for _, c := range cookies {
		get.AddCookie(c)
	}
	page := httptest.NewRecorder()
	h.ServeHTTP(page, get)
	action := regexp.MustCompile(`<form method="post" action="([^"]*)"`).FindStringSubmatch(page.Body.String())
	csrf := regexp.MustCompile(`name="` + csrfFormField + `" value="([^"]*)"`).FindStringSubmatch(page.Body.String())
	if action == nil || csrf == nil {
		t.Fatalf("no confirmation form: %d %.300s", page.Code, page.Body.String())
	}
	post := httptest.NewRequest(http.MethodPost, html.UnescapeString(action[1]),
		strings.NewReader(url.Values{csrfFormField: {csrf[1]}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range append(cookies, page.Result().Cookies()...) {
		post.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	return rec
}

// A sign-out here goes on to the upstream, carrying what the upstream needs to find
// the session and signed by the key it was given, and the answer brings the browser
// back. Our session ended before the browser left.
func TestASignOutGoesOnToTheUpstream(t *testing.T) {
	u := newSAMLUpstream(t)
	certificate := u.logoutReady(t)
	if !strings.Contains(u.get("/metadata").Body.String(), "/saml/source/"+u.slug+"/slo") {
		t.Fatal("the metadata offers no logout")
	}
	cookies := u.signedInThrough(t)
	if u.sessionsLeft(t) != 1 {
		t.Fatalf("%d sessions after signing in", u.sessionsLeft(t))
	}

	rec := u.signOut(t, cookies)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "https://upstream.test/slo?tenant=a&SAMLRequest=") {
		t.Fatalf("signing out answered %d %q: %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if u.sessionsLeft(t) != 0 {
		t.Error("the session here outlived the browser leaving")
	}
	if err := saml.VerifyRedirectSignature(loc.RawQuery, certificate, "SAMLRequest"); err != nil {
		t.Fatalf("the request does not verify: %v", err)
	}
	raw, err := saml.DecodeRedirect(loc.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	var sent saml.LogoutRequest
	if err := saml.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.NameID != "ada-at-upstream" || sent.SessionIndex != "upstream-session-1" || sent.Issuer != u.f.srv.cfg.Issuer {
		t.Errorf("the upstream was told %q %q", sent.NameID, sent.SessionIndex)
	}

	answer := func(inResponseTo, issuer, relay string) *httptest.ResponseRecorder {
		t.Helper()
		doc := `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
 ID="_r" Version="2.0" InResponseTo="` + inResponseTo + `"><saml:Issuer>` + issuer + `</saml:Issuer>
 <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>`
		encoded, err := saml.EncodeRedirect(doc)
		if err != nil {
			t.Fatal(err)
		}
		q := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}
		rec := httptest.NewRecorder()
		u.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/source/"+u.slug+"/slo?"+q.Encode(), nil))
		return rec
	}
	relay := loc.Query().Get("RelayState")
	if rec := answer("_somebody-elses", "https://upstream.test/idp", relay); rec.Code != http.StatusBadRequest {
		t.Errorf("an answer to another request: %d", rec.Code)
	}
	rec = u.signOut(t, u.signedInThrough(t))
	loc, err = url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = saml.DecodeRedirect(loc.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	if err := saml.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	if rec := answer(sent.ID, "https://upstream.test/idp", loc.Query().Get("RelayState")); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "signed out") {
		t.Errorf("the answer: %d %s", rec.Code, rec.Body.String())
	}
	if rec := answer(sent.ID, "https://upstream.test/idp", loc.Query().Get("RelayState")); rec.Code != http.StatusBadRequest {
		t.Errorf("the same answer twice: %d", rec.Code)
	}
}

// With no key a request cannot be signed, and the sign-out here stands on its own.
func TestASignOutWithNoKeyStopsHere(t *testing.T) {
	u := newSAMLUpstream(t)
	u.logoutReady(t)
	if _, err := u.f.pool.Exec(context.Background(), `UPDATE core.saml_source_keys SET retired_at = now() WHERE provider_id = $1::uuid`, u.providerID); err != nil {
		t.Fatal(err)
	}
	// The redirect binding needs a key to sign with; the SOAP binding does not, since
	// the upstream signs and the answer goes back on its connection.
	if meta := u.get("/metadata").Body.String(); strings.Contains(meta, saml.BindingRedirect) ||
		!strings.Contains(meta, saml.BindingSOAP) {
		t.Errorf("the metadata offers a logout this deployment cannot take part in, or not the one it can: %s", meta)
	}
	rec := u.signOut(t, u.signedInThrough(t))
	if strings.Contains(rec.Header().Get("Location"), "upstream.test") {
		t.Errorf("an unsigned request went out: %q", rec.Header().Get("Location"))
	}
	if u.sessionsLeft(t) != 0 {
		t.Error("the session here did not end")
	}
}

// The upstream ends a session here: only signed, only once, and for the person it
// names, with the answer signed by the key it was given.
func TestAnUpstreamEndsTheSessionsItBegan(t *testing.T) {
	u := newSAMLUpstream(t)
	certificate := u.logoutReady(t)
	pkcs8, strangerPEM, err := saml.NewSPKey("https://stranger.test", saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := saml.ParseSPKey(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(strangerPEM))

	u.signedInThrough(t)
	u.signedInThrough(t)
	if rec := u.upstreamLogout(t, "ada-at-upstream", stranger, block.Bytes); rec.Code != http.StatusBadRequest || u.sessionsLeft(t) != 2 {
		t.Fatalf("somebody else's signature: %d, %d sessions left", rec.Code, u.sessionsLeft(t))
	}
	rec := u.upstreamLogout(t, "somebody-we-do-not-know", u.signer, u.certDER)
	if rec.Code != http.StatusSeeOther || u.sessionsLeft(t) != 2 {
		t.Fatalf("a stranger's name: %d, %d sessions left", rec.Code, u.sessionsLeft(t))
	}

	rec = u.upstreamLogout(t, "ada-at-upstream", u.signer, u.certDER)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc.String(), "https://upstream.test/slo?tenant=a&SAMLResponse=") {
		t.Fatalf("the person: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if u.sessionsLeft(t) != 0 {
		t.Errorf("%d sessions outlived it", u.sessionsLeft(t))
	}
	if loc.Query().Get("RelayState") != "their-state" {
		t.Errorf("RelayState came back as %q", loc.Query().Get("RelayState"))
	}
	if err := saml.VerifyRedirectSignature(loc.RawQuery, certificate, "SAMLResponse"); err != nil {
		t.Errorf("the answer does not verify: %v", err)
	}
	var n int
	if err := u.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
		WHERE event_type = 'saml.logout_completed' AND subject_id = $1::uuid`, u.f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d audit rows", n)
	}
}

// soapLogout is the upstream ending a session with no browser: its signed request in a
// SOAP envelope, posted to the address our metadata gives.
func (u *samlUpstream) soapLogout(t *testing.T, nameID string, signer saml.SPKey, certDER []byte) (body []byte, id string, code int) {
	t.Helper()
	doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{Issuer: "https://upstream.test/idp",
		Destination: u.f.srv.cfg.Issuer + "/saml/source/" + u.slug + "/slo/soap", NameID: nameID,
		NameIDFormat: saml.NameIDFormatPersistent, Now: time.Now()}, signer, certDER)
	if err != nil {
		t.Fatal(err)
	}
	var sent saml.LogoutRequest
	if err := saml.Unmarshal([]byte(doc), &sent); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/saml/source/"+u.slug+"/slo/soap", strings.NewReader(saml.SOAPEnvelope(doc)))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.Header.Set("SOAPAction", saml.SOAPAction)
	rec := httptest.NewRecorder()
	u.f.srv.Routes().ServeHTTP(rec, r)
	return rec.Body.Bytes(), sent.ID, rec.Code
}

// The upstream ends sessions here over the SOAP binding: only signed by it, only once,
// answered on the connection with a LogoutResponse, signed when a key is held and
// unsigned when none is.
func TestAnUpstreamsSOAPLogoutEndsTheSessions(t *testing.T) {
	u := newSAMLUpstream(t)
	u.logoutReady(t)
	if !strings.Contains(u.get("/metadata").Body.String(), `Location="`+u.f.srv.cfg.Issuer+"/saml/source/"+u.slug+`/slo/soap"`) {
		t.Fatal("the metadata does not offer the SOAP address")
	}
	pkcs8, strangerPEM, err := saml.NewSPKey("https://stranger.test", saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := saml.ParseSPKey(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(strangerPEM))

	u.signedInThrough(t)
	u.signedInThrough(t)
	if body, _, code := u.soapLogout(t, "ada-at-upstream", stranger, block.Bytes); code != http.StatusInternalServerError ||
		!strings.Contains(string(body), "Fault") || u.sessionsLeft(t) != 2 {
		t.Fatalf("somebody else's signature: %d, %d sessions left: %s", code, u.sessionsLeft(t), body)
	}
	body, id, code := u.soapLogout(t, "ada-at-upstream", u.signer, u.certDER)
	if code != http.StatusOK || u.sessionsLeft(t) != 0 {
		t.Fatalf("the upstream's own: %d, %d sessions left: %s", code, u.sessionsLeft(t), body)
	}
	if err := saml.ReadSOAPLogoutResponse(body, id); err != nil || !strings.Contains(string(body), "Signature") {
		t.Errorf("the answer: %v, signed %v: %s", err, strings.Contains(string(body), "Signature"), body)
	}
	var audited int
	if err := u.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
		WHERE event_type = 'saml.logout_completed' AND subject_id = $1::uuid`, u.f.userID).Scan(&audited); err != nil || audited != 1 {
		t.Errorf("%d audit rows (%v)", audited, err)
	}

	// With no key of its own held here, the logout still happens and is answered,
	// unsigned.
	if _, err := u.f.pool.Exec(context.Background(), `UPDATE core.saml_source_keys SET retired_at = now() WHERE provider_id = $1::uuid`, u.providerID); err != nil {
		t.Fatal(err)
	}
	u.signedInThrough(t)
	body, id, code = u.soapLogout(t, "ada-at-upstream", u.signer, u.certDER)
	if code != http.StatusOK || u.sessionsLeft(t) != 0 || saml.ReadSOAPLogoutResponse(body, id) != nil ||
		strings.Contains(string(body), "Signature") {
		t.Errorf("with no key here: %d, %d sessions left: %s", code, u.sessionsLeft(t), body)
	}
}

// A request heard twice ends nothing the second time, however good its signature.
func TestAnUpstreamsLogoutIsHeardOnce(t *testing.T) {
	u := newSAMLUpstream(t)
	u.logoutReady(t)
	doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{Issuer: "https://upstream.test/idp",
		Destination: u.f.srv.cfg.Issuer + "/saml/source/" + u.slug + "/slo", NameID: "ada-at-upstream",
		NameIDFormat: saml.NameIDFormatPersistent, Now: time.Now()}, u.signer, u.certDER)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := saml.EncodeRedirect(doc)
	if err != nil {
		t.Fatal(err)
	}
	query, err := saml.SignRedirectQuery("SAMLRequest", encoded, "", u.signer)
	if err != nil {
		t.Fatal(err)
	}
	replay := func() {
		rec := httptest.NewRecorder()
		u.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/source/"+u.slug+"/slo?"+query, nil))
	}
	u.signedInThrough(t)
	replay()
	if u.sessionsLeft(t) != 0 {
		t.Fatal("the first did nothing")
	}
	u.signedInThrough(t)
	replay()
	if u.sessionsLeft(t) != 1 {
		t.Error("a captured request ended a session signed in since")
	}
}

// The private half is sealed, and sealed for this and nothing else.
func TestAnUpstreamKeyIsSealedUnderTheRootKey(t *testing.T) {
	u := newSAMLUpstream(t)
	ctx := context.Background()
	k, err := store.AddSAMLSourceKey(ctx, u.f.pool, u.f.srv.root, u.f.orgID, u.slug, saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := u.f.pool.QueryRow(ctx, `SELECT key_sealed FROM core.saml_source_keys WHERE id = $1::uuid`, k.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "PRIVATE") {
		t.Fatal("the key is stored in the clear")
	}
	if _, err := u.f.srv.root.Open(sealed, "something_else"); err == nil {
		t.Error("the key opened under another context")
	}
}
