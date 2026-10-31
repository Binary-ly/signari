package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// asked is an AuthnRequest with a RequestedAuthnContext, as a browser posts it.
func (rf *realmFixture) asked(t *testing.T, comparison string, classes ...string) *httptest.ResponseRecorder {
	t.Helper()
	var refs strings.Builder
	for _, c := range classes {
		fmt.Fprintf(&refs, "<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>", c)
	}
	attr := ""
	if comparison != "" {
		attr = fmt.Sprintf(` Comparison=%q`, comparison)
	}
	req := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%d" Version="2.0"
 IssueInstant="%s" Destination="https://signin-test.example/saml/sso"
 AssertionConsumerServiceURL="https://sp.test/acs"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer>
 <samlp:RequestedAuthnContext%s>%s</samlp:RequestedAuthnContext></samlp:AuthnRequest>`,
		time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), rf.own, attr, refs.String())
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(req))}}
	r := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func (rf *realmFixture) answer(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	m := samlResponseField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no SAMLResponse in a %d answer to %q: %.200s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return string(xml)
}

// A service provider asking for a second factor gets one, or is told it cannot, and
// a password session that happens to be live does not answer for it. Each stage is the
// same account as it would really move.
func TestARequestedClassIsHeldToTheSession(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	const mfa = saml.AuthnContextMFA

	// No factor to ask for: signing in again would land here for ever.
	if doc := rf.answer(t, rf.asked(t, "", mfa)); !strings.Contains(doc, saml.StatusNoAuthnContext) {
		t.Fatalf("a demand nobody can reach answered %.300s", doc)
	}

	// A class nobody here can state is the same answer.
	if doc := rf.answer(t, rf.asked(t, "", "urn:example:retina-scan")); !strings.Contains(doc, saml.StatusNoAuthnContext) {
		t.Errorf("an unknown class answered %.300s", doc)
	}

	// What a password does reach goes through.
	if doc := rf.answer(t, rf.asked(t, "", saml.AuthnContextPassword)); !strings.Contains(doc, ":Assertion") {
		t.Errorf("a password session refused a password class: %.300s", doc)
	}

	// Enrolled, and a flow that asks: back to sign in, saying so.
	if _, err := rf.f.pool.Exec(ctx, `INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`, rf.f.userID, rf.f.orgID); err != nil {
		t.Fatal(err)
	}
	rec := rf.asked(t, "", mfa)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login?authz=") ||
		!strings.Contains(rec.Header().Get("Location"), "acr_values") {
		t.Fatalf("a password session answered %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// Having signed in with it, the same request is answered.
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.sessions SET amr = ARRAY['pwd','otp','mfa'] WHERE cookie_hash = $1`,
		store.HashToken(rf.cookie)); err != nil {
		t.Fatal(err)
	}
	doc := rf.answer(t, rf.asked(t, "", mfa))
	if !strings.Contains(doc, ":Assertion") || !strings.Contains(doc, mfa) {
		t.Errorf("a multi-factor session answered %.400s", doc)
	}

	// better than a second factor is nothing a class here can name.
	if doc := rf.answer(t, rf.asked(t, "better", mfa)); !strings.Contains(doc, saml.StatusNoAuthnContext) {
		t.Errorf("better than multi-factor answered %.300s", doc)
	}
}
