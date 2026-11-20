package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// clientReads is how many of the statements read a client's row.
func clientReads(seen []string) int {
	n := 0
	for _, s := range seen {
		if strings.Contains(s, "SELECT org_id::text, display_name, client_type") {
			n++
		}
	}
	return n
}

// An authorization request with no session renders the sign-in page, which asks
// whose page it is several times over. It reads its client twice: once to
// authorize the request, once to know the page's organisation. Rendered with no
// answer kept, the page read it seven times, 8 of the request's 18 statements;
// the login page's own handlers already kept one (E.34).
func TestAnAuthorizationRenderingTheSignInPageReadsItsClientTwice(t *testing.T) {
	f := newSignInFixture(t)
	spent := traced(t, f.srv)
	rec := f.authorizeWith(t, "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), csrfFormField) {
		t.Fatalf("the authorization request answered %d, not the sign-in page: %.300s", rec.Code, rec.Body.String())
	}
	seen := spent.take()
	if n := clientReads(seen); n > 2 {
		t.Errorf("the authorization request read its client %d times in %d statements, want 2", n, len(seen))
	}
}

// What the sign-in page decides from (its brands, provider buttons, sign-up rule, "stay
// signed in", single sign-on by address and passkeys, and the first organisation) is
// asked in one round trip, a batch, and none of it on its own. It was a statement each,
// in turn, ten of a render's dozen (E.36).
func TestTheSignInPageReadsItsSettingsInOneRoundTrip(t *testing.T) {
	f := newSignInFixture(t)
	trips := countRoundTripsOf(t, f.srv)
	rec := httptest.NewRecorder()
	f.srv.handleLoginGet(rec, httptest.NewRequest(http.MethodGet, "/login?authz="+url.QueryEscape(f.plainAuthz()), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the login page answered %d", rec.Code)
	}
	settings := []string{"FROM core.brands", "FROM core.org_brands", "FROM core.identity_providers WHERE enabled AND org_id",
		"persistent_sessions FROM core.organizations", "rp_id", "cardinality(login_domains)", "FROM core.signup_rules",
		"ORDER BY o.created_at LIMIT 1", "FROM core.kerberos_realms"}
	trips.mu.Lock()
	seen := append([]string(nil), trips.what...)
	trips.mu.Unlock()
	batched := map[string]bool{}
	for _, s := range seen {
		for _, k := range settings {
			if !strings.Contains(s, k) {
				continue
			}
			if strings.HasPrefix(s, "in the batch:") {
				batched[k] = true
			} else {
				t.Errorf("the login page asked %q in a round trip of its own: %.140s", k, s)
			}
		}
	}
	for _, k := range settings {
		if !batched[k] {
			t.Errorf("the login page did not ask %q in its batch", k)
		}
	}
	t.Logf("the login page took %d round trips:%s", trips.n.Load(), trips)
}

// firstOrgReads is how many of the statements asked the instance's first organisation.
func firstOrgReads(seen []string) int {
	n := 0
	for _, s := range seen {
		if strings.Contains(s, "ORDER BY o.created_at LIMIT 1") {
			n++
		}
	}
	return n
}

// The sign-in page's recovery link and its sign-up link are each decided under the
// instance's first organisation, and each asked which that is: a statement each, in
// every render (E.35). The page asks once.
func TestTheSignInPageAsksTheFirstOrganisationOnce(t *testing.T) {
	f := newSignInFixture(t)
	spent := traced(t, f.srv)
	if rec := f.authorizeWith(t, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("the authorization request answered %d, not the sign-in page", rec.Code)
	}
	if n := firstOrgReads(spent.take()); n > 1 {
		t.Errorf("rendering the sign-in page from the authorization endpoint asked the first organisation %d times", n)
	}
	rec := httptest.NewRecorder()
	f.srv.handleLoginGet(rec, httptest.NewRequest(http.MethodGet, "/login?authz="+url.QueryEscape(f.plainAuthz()), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the login page answered %d", rec.Code)
	}
	if n := firstOrgReads(spent.take()); n > 1 {
		t.Errorf("the login page asked the first organisation %d times", n)
	}
}
