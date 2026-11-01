package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
)

func fromAnotherSite(r *http.Request) *http.Request {
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Sec-Fetch-Dest", "document")
	return r
}

// A test can attach a cookie to anything, so it never saw this: a browser leaves a
// SameSite=Lax session behind on another site's form, and a person signed in was
// asked to sign in again. The request comes back as a GET, which brings the cookie.
func TestAnAuthorizationFormFromAnotherSiteComesBackForTheSession(t *testing.T) {
	f := newSignInFixture(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET first_party = true WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	session := f.signInAndReturnCookie(t)
	h := f.srv.Routes()

	r := fromAnotherSite(httptest.NewRequest(http.MethodPost, oidc.PathAuthorize, strings.NewReader(f.plainAuthz())))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the form was answered without the session: %d %.200s", rec.Code, rec.Body.String())
	}
	back := httptest.NewRequest(http.MethodGet, rec.Header().Get("Location"), nil)
	back.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	arrived := httptest.NewRecorder()
	h.ServeHTTP(arrived, back)
	if !strings.HasPrefix(arrived.Header().Get("Location"), "https://rp.test/cb?code=") {
		t.Errorf("the request came back as %d %q", arrived.Code, arrived.Header().Get("Location"))
	}

	// Refused before it is sent back: two of anything is not a request to repeat,
	// and a redirect would be to whichever of them survived.
	dup := fromAnotherSite(httptest.NewRequest(http.MethodPost, oidc.PathAuthorize,
		strings.NewReader(f.plainAuthz()+"&redirect_uri=https%3A%2F%2Fevil.test%2Fcb")))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, dup)
	if rec.Code == http.StatusSeeOther {
		t.Errorf("a request with two redirect_uri values was sent back: %q", rec.Header().Get("Location"))
	}

	// A form with no browser saying where it came from is what it always was.
	plain := httptest.NewRequest(http.MethodPost, oidc.PathAuthorize, strings.NewReader(f.plainAuthz()))
	plain.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	plain.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, plain)
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://rp.test/cb?code=") {
		t.Errorf("a post with its session answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestASAMLRequestFromAnotherSiteComesBackForTheSession(t *testing.T) {
	rf := newRealmFixture(t)
	doc := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%d" Version="2.0"
 IssueInstant="%s" Destination="https://signin-test.example/saml/sso"
 AssertionConsumerServiceURL="https://sp.test/acs"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), rf.own)
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(doc))}, "RelayState": {"relay"}}
	h := rf.f.srv.Routes()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, fromAnotherSite(httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther || loc.Path != "/saml/sso" || loc.Query().Get("Binding") != "POST" ||
		loc.Query().Get("RelayState") != "relay" {
		t.Fatalf("the request was answered without the session: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	back := httptest.NewRequest(http.MethodGet, loc.RequestURI(), nil)
	back.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	arrived := httptest.NewRecorder()
	h.ServeHTTP(arrived, back)
	if m := samlResponseField.FindStringSubmatch(arrived.Body.String()); m == nil {
		t.Errorf("no assertion came back: %d %.300s", arrived.Code, arrived.Body.String())
	}
}

func TestOnlyAFormFromAnotherSiteIsSentBack(t *testing.T) {
	for name, tc := range map[string]struct {
		method, site, dest string
		want               bool
	}{
		"another site's form":  {http.MethodPost, "cross-site", "document", true},
		"this origin's form":   {http.MethodPost, "same-origin", "document", false},
		"a sibling subdomain":  {http.MethodPost, "same-site", "document", false},
		"a link":               {http.MethodGet, "cross-site", "document", false},
		"another site's frame": {http.MethodPost, "cross-site", "iframe", false},
		"no browser":           {http.MethodPost, "", "", false},
	} {
		r := httptest.NewRequest(tc.method, "/x", nil)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		r.Header.Set("Sec-Fetch-Dest", tc.dest)
		if got := crossSiteForm(r); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}
