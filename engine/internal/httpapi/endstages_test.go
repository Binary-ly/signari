package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// The invitation and redirect stages, through the routes (5.24).

// signUpFlow puts an enrolment flow in force for the journey's organisation,
// the one sign-up runs under.
func (j *passkeyJourney) signUpFlow(t *testing.T, stages, tests string) {
	t.Helper()
	j.applyFlow(t, `
version: 1
flows:
  - name: sign-up
    on: enrolment
    stages:
`+stages+`
    tests:
`+tests)
}

func newSignUpAddress(t *testing.T, j *passkeyJourney) (email, password string) {
	t.Helper()
	raw := make([]byte, 10)
	_, _ = rand.Read(raw)
	email = "stage-" + hex.EncodeToString(raw[:4]) + "@example.test"
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.users WHERE org_id = $1::uuid AND email = $2`, j.orgID, email)
	})
	return email, "a-stage-pass-" + hex.EncodeToString(raw)
}

func TestSignUpByInvitationOnly(t *testing.T) {
	j := newPasskeyJourney(t)
	j.openSignup(t)
	j.signUpFlow(t, "      - invitation\n      - create_user\n      - done",
		"      - {name: invited, given: {}, expect: [invitation, create_user, done]}")
	b := newTestBrowser(t, j.h)
	email, password := newSignUpAddress(t, j)

	rec := b.post("/signup", b.get("/signup"), url.Values{"email": {email}, "password": {password}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "created by invitation") {
		t.Errorf("an open sign-up under an invitation-only flow: %d %s", rec.Code, truncate(rec.Body.String(), 200))
	}
	var made int
	if err := j.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.users WHERE email = $1`, email).Scan(&made); err != nil {
		t.Fatal(err)
	}
	if made != 0 {
		t.Fatal("an account was made with no invitation")
	}

	token, err := store.CreateInvitation(context.Background(), j.pool, j.orgID, email, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	form := b.get("/signup?invite=" + url.QueryEscape(token))
	rec = b.post("/signup", form, url.Values{"email": {email}, "password": {password}, "invite": {token}})
	if !strings.Contains(rec.Body.String(), "can now sign in") {
		t.Errorf("an invited sign-up was refused: %d %s", rec.Code, truncate(rec.Body.String(), 200))
	}
}

func TestASignUpCanEndOnTheOperatorsPage(t *testing.T) {
	j := newPasskeyJourney(t)
	j.openSignup(t)
	j.signUpFlow(t, "      - create_user\n      - {stage: redirect, to: \"https://welcome.example.com/start\"}",
		"      - {name: made, given: {}, expect: [create_user, redirect]}")
	b := newTestBrowser(t, j.h)
	email, password := newSignUpAddress(t, j)
	rec := b.post("/signup", b.get("/signup"), url.Values{"email": {email}, "password": {password}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://welcome.example.com/start" {
		t.Errorf("a sign-up ending in a redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// One an application asked for still returns to it.
	email, password = newSignUpAddress(t, j)
	authz := url.Values{"client_id": {j.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}}.Encode()
	rec = b.post("/signup", b.get("/signup?authz="+url.QueryEscape(authz)),
		url.Values{"email": {email}, "password": {password}, "authz": {authz}})
	if rec.Code == http.StatusSeeOther || !strings.Contains(rec.Body.String(), "/login?authz=") {
		t.Errorf("a sign-up an application asked for was sent past it: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestARecoveryCanEndOnTheOperatorsPage(t *testing.T) {
	f := newTokenFixture(t)
	givePassword(t, f)
	applyRecoveryFlow(t, f, `
version: 1
flows:
  - name: recovery-to-the-app
    on: recovery
    stages: [identify, email_otp, password_change, {stage: redirect, to: "/account"}]
    tests: [{name: as written, given: {}, expect: [identify, email_otp, password_change, redirect]}]
`)
	rec := postReset(t, f, newResetToken(t, f), "a-perfectly-good-new-password-42")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Errorf("a reset ending in a redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
