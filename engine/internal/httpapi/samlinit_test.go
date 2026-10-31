package httpapi

import (
	"context"
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A sign-in that starts here (8.02). An unsolicited response is a signed statement
// nobody asked for, so what must hold is who gets one: a provider that opted in, in the
// person's own organisation, that the policy lets them reach, at the URL it is registered
// with, and nothing about it chosen by the link.

func (rf *realmFixture) providerID(t *testing.T, entity string) string {
	t.Helper()
	var id string
	if err := rf.f.pool.QueryRow(context.Background(), `SELECT id::text FROM core.saml_providers WHERE entity_id = $1`,
		entity).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (rf *realmFixture) optIn(t *testing.T, entity, relayState string) string {
	t.Helper()
	var org string
	id := rf.providerID(t, entity)
	if err := rf.f.pool.QueryRow(context.Background(), `SELECT org_id::text FROM core.saml_providers WHERE id = $1::uuid`,
		id).Scan(&org); err != nil {
		t.Fatal(err)
	}
	on := true
	if err := store.SetSAMLIdPInitiated(context.Background(), rf.f.pool, org, id, &on, &relayState); err != nil {
		t.Fatal(err)
	}
	return id
}

func (rf *realmFixture) samlInit(path string, signedIn bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if signedIn {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	}
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// issued is the response in a page, "" for none.
func issued(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	m := samlResponseField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		return ""
	}
	xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return string(xml)
}

func TestASignInStartsHereOnlyForAProviderThatTakesOne(t *testing.T) {
	rf := newRealmFixture(t)
	own := rf.providerID(t, rf.own)

	refused := func(name, path string) {
		t.Helper()
		rec := rf.samlInit(path, true)
		if rec.Code != http.StatusBadRequest || issued(t, rec) != "" ||
			!strings.Contains(rec.Body.String(), "no such application") {
			t.Errorf("%s answered %d: %.200s", name, rec.Code, rec.Body.String())
		}
	}
	// Off until set.
	refused("a provider that has not opted in", pathSAMLInit+own)

	id := rf.optIn(t, rf.own, "/dashboard")

	// Asked for a session before anything is said about the provider.
	rec := rf.samlInit(pathSAMLInit+id, false)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") ||
		issued(t, rec) != "" {
		t.Fatalf("nobody signed in got %d, %q", rec.Code, rec.Header().Get("Location"))
	}

	// The operator's RelayState and the registered URL, whatever the link says.
	rec = rf.samlInit(pathSAMLInit+id+"?RelayState=/elsewhere&AssertionConsumerServiceURL=https://evil.test/acs", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("an opted-in provider answered %d: %.300s", rec.Code, rec.Body.String())
	}
	doc := issued(t, rec)
	if !strings.Contains(doc, "Assertion") || !strings.Contains(doc, rf.own) {
		t.Fatalf("no assertion for the provider: %.300s", doc)
	}
	if strings.Contains(doc, "InResponseTo") {
		t.Errorf("a response to nothing refers to a request: %.300s", doc)
	}
	if !strings.Contains(doc, `Recipient="https://sp.test/acs"`) {
		t.Errorf("the assertion is not for the registered URL: %.400s", doc)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="https://sp.test/acs"`) || strings.Contains(body, "evil.test") {
		t.Errorf("the response was sent somewhere else: %.300s", body)
	}
	if !strings.Contains(body, `value="/dashboard"`) || strings.Contains(body, "/elsewhere") {
		t.Errorf("the RelayState is not the operator's: %.400s", body)
	}

	// Another organisation's, even opted in, and one switched off, read the same.
	refused("another organisation's", pathSAMLInit+rf.optIn(t, rf.foreign, ""))
	refused("a disabled provider", pathSAMLInit+rf.optIn(t, rf.disabled, ""))
	refused("something that is no id", pathSAMLInit+"not-a-uuid")
	refused("an id nothing has", pathSAMLInit+"00000000-0000-4000-8000-000000000000")

	// Opting out stops it at once.
	off := false
	if err := store.SetSAMLIdPInitiated(context.Background(), rf.f.pool, rf.f.orgID, id, &off, nil); err != nil {
		t.Fatal(err)
	}
	refused("a provider that opted out", pathSAMLInit+id)
}

func TestTheAccessPolicyHoldsASignInStartedHereAndThePortalSaysSo(t *testing.T) {
	rf := newRealmFixture(t)
	link := pathSAMLInit + rf.providerID(t, rf.own)
	if strings.Contains(rf.samlInit("/apps", true).Body.String(), link) {
		t.Error("the portal offers a provider that has not opted in")
	}
	rf.optIn(t, rf.own, "")
	rf.optIn(t, rf.disabled, "")

	if rec := rf.samlInit("/apps", true); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), link) {
		t.Fatalf("the portal has no tile for it (%d): %.400s", rec.Code, rec.Body.String())
	}
	if rec := rf.samlInit("/apps", true); strings.Contains(rec.Body.String(), rf.providerID(t, rf.disabled)) {
		t.Error("the portal offers a disabled provider")
	}

	applyPolicy(t, rf.f.srv, rf.f.pool, rf.f.orgID, denyClient(rf.own))
	rec := rf.samlInit(link, true)
	if issued(t, rec) != "" || !strings.Contains(rec.Body.String(), "This application is closed to you.") {
		t.Errorf("a refused provider answered %d: %.300s", rec.Code, rec.Body.String())
	}
	portal := rf.samlInit("/apps", true).Body.String()
	if strings.Contains(portal, link) || !strings.Contains(portal, "This application is closed to you.") {
		t.Errorf("the portal still offers what the policy refuses: %.400s", portal)
	}
}
