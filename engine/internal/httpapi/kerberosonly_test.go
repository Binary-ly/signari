package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
)

// ticketsOnly is a sign-in flow a Kerberos ticket is the only way into.
const ticketsOnly = `
version: 1
flows:
  - name: tickets-only
    on: authentication
    stages: [kerberos, session]
    tests:
      - name: a ticket
        given: {}
        expect: [kerberos, session]
`

// A flow a ticket is the only way into skips the sign-in page for the Negotiate
// exchange, carrying the request, and the ticket comes back to it signed in (8.22). The
// page stays for a flow with another way in, and for a host with no keytab for the
// organisation, where the exchange would answer 404.
func TestAFlowOfTicketsAloneGoesStraightToNegotiate(t *testing.T) {
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	realm := newTestRealm(t, f, f.orgID, "ONLY", false)
	email := "grace@" + strings.ToLower(realm.realm)
	var userID string
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, decode(repeat(md5(random()::text),4),'hex'), $2) RETURNING id::text`,
		f.orgID, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	authorize := func(host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+f.plainAuthz(), nil)
		r.Host = host
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}

	// The built-in flow has other ways in, so the page; and a ticket among them, so the
	// page links the exchange where the host can take one, and only there.
	link := `href="/login/kerberos?authz=`
	if rec := authorize(realm.host); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), link) {
		t.Errorf("with the built-in flow on the realm's host the request answered %d %q, want the page linking a ticket",
			rec.Code, rec.Header().Get("Location"))
	}
	if rec := authorize("no-keytab-here.test"); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "/login/kerberos") {
		t.Errorf("on a host with no keytab the request answered %d, want the page without a ticket's link", rec.Code)
	}

	f.applyFlow(t, ticketsOnly)
	rec := authorize(realm.host)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/login/kerberos?") {
		t.Fatalf("a flow of tickets alone answered %d %q, want a redirect to the Negotiate exchange", rec.Code, loc)
	}
	if rec := authorize("no-keytab-here.test"); rec.Code != http.StatusOK {
		t.Errorf("a host with no keytab for the organisation answered %d %q, not the page",
			rec.Code, rec.Header().Get("Location"))
	}

	follow := httptest.NewRequest(http.MethodGet, loc, nil)
	follow.Host = realm.host
	follow.Header.Set("Authorization", ticket(t, realm.keytab, "grace", realm.realm, realm.spn, realm.realm))
	back := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(back, follow)
	if user, _ := signedInAs(t, f, back); user != userID {
		t.Fatalf("the ticket signed in %q, want %q: %d %.200s", user, userID, back.Code, back.Body.String())
	}
	next, err := url.Parse(back.Header().Get("Location"))
	if err != nil || next.Path != oidc.PathAuthorize || next.Query().Get("client_id") != f.clientID {
		t.Errorf("signed in, the exchange went to %q, want back to the request it carried", back.Header().Get("Location"))
	}
}
