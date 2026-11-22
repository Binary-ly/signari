package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

// With no RP ID a ceremony cannot start, and the page went on offering one and asking
// for a challenge it could not have, which only a browser's console showed.
func TestTheSignInPageOffersAPasskeyOnlyWhereOneCanWork(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	page := func() string {
		t.Helper()
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+f.plainAuthz(), nil))
		return rec.Body.String()
	}
	set := func(rpID any) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE core.instances SET rp_id = $1
			WHERE id = (SELECT instance_id FROM core.organizations WHERE id = $2::uuid)`, rpID, f.orgID); err != nil {
			t.Fatal(err)
		}
	}
	offered := func(body string) bool {
		return strings.Contains(body, `id="passkey-signin"`) || strings.Contains(body, `src="/passkey.js"`)
	}

	set(nil)
	if body := page(); offered(body) {
		t.Error("the page offers a passkey with no relying party to use it with")
	}
	set("signin-test.example")
	body := page()
	if !strings.Contains(body, `id="passkey-signin"`) || !strings.Contains(body, `src="/passkey.js"`) {
		t.Error("the page does not offer a passkey where one can work")
	}
}
