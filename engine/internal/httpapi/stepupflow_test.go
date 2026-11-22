package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// The step-up loop by another road (4.18). A factor is enrolled, so the
// requirement looks reachable, but the organisation's flow never asks a
// password sign-in for one: the form gives acr 1, and the authorization
// endpoint shows the form again, for ever.
func TestAStepUpTheFlowNeverAsksForIsRefusedRatherThanLooped(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}

	// The built-in flow asks somebody with a factor: the form.
	if rec := f.authorizeWithACR(t, cookie); rec.Code != http.StatusOK {
		t.Fatalf("under the built-in flow a reachable step-up answered %d %q",
			rec.Code, rec.Header().Get("Location"))
	}

	f.applyFlow(t, `
version: 1
flows:
  - name: never-asks
    on: authentication
    stages:
      - password
      - session
    tests:
      - name: straight through
        given: {user_has_second_factor: true}
        expect: [password, session]
`)
	rec := f.authorizeWithACR(t, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "error=unmet_authentication_requirements") {
		t.Fatalf("a step-up no sign-in under this flow can reach answered %d %q; showing the "+
			"form here is the loop", rec.Code, rec.Header().Get("Location"))
	}
}

// A passkey holder can still reach it: their passkey's own sign-in is
// multi-factor, whatever the flow asks of a password.
func TestAStepUpAPasskeyCanReachStillShowsTheForm(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	cookie := j.signInAndReturnCookie(t)
	j.register(t, &http.Cookie{Name: SessionCookieName, Value: cookie})
	j.applyFlow(t, `
version: 1
flows:
  - name: never-asks-a-password
    on: authentication
    stages:
      - one_of:
          - {stage: passkey, when: proved_by_passkey}
          - {stage: password}
      - session
    tests:
      - name: a password
        given: {}
        expect: [password, session]
`)
	if rec := j.authorizeWithACR(t, cookie); rec.Code != http.StatusOK {
		t.Errorf("a step-up a passkey reaches answered %d %q, want the form",
			rec.Code, rec.Header().Get("Location"))
	}
}
