package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The sign-in page links to recovery unless the recovery flow denies it, and
// to sign-up only when self-service sign-up is open. Neither was linked, so
// both existed and nobody signing in could reach them (2.14).
func TestTheSignInPageOffersRecoveryAndSignUpAsConfigured(t *testing.T) {
	j := newPasskeyJourney(t) // a server whose issuer is its instance's, so the default organisation resolves
	ctx := context.Background()
	page := func() string {
		t.Helper()
		rec := httptest.NewRecorder()
		j.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/login answered %d", rec.Code)
		}
		return rec.Body.String()
	}
	links := func(body string) (recover, signup bool) {
		return strings.Contains(body, `href="/recover"`), strings.Contains(body, `href="/signup"`)
	}

	if r, s := links(page()); !r || s {
		t.Errorf("by default: recovery link %v, sign-up link %v; want recovery only", r, s)
	}

	if _, err := j.pool.Exec(ctx, `INSERT INTO core.signup_rules (org_id) VALUES ($1::uuid)
		ON CONFLICT (org_id) DO NOTHING`, j.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.signup_rules WHERE org_id = $1::uuid`, j.orgID)
	})
	if _, s := links(page()); !s {
		t.Error("with sign-up open, the page offers no sign-up link")
	}

	j.applyFlow(t, `
version: 1
flows:
  - name: recovery-closed
    on: recovery
    stages:
      - deny
    tests:
      - name: closed
        given: {}
        expect: [deny]
`)
	if r, _ := links(page()); r {
		t.Error("with recovery denied by the flow, the page still links to it")
	}
}
