package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// /account/security (5.02, 5.03): the person sees every way they sign in and
// removes their own authenticator app, email codes or text-message codes,
// behind a recent sign-in, audited and told; the last second factor takes the
// recovery codes with it.

func (f *signInFixture) factorRows(t *testing.T) (totp, email, recovery int) {
	t.Helper()
	if err := f.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM core.totp_credentials WHERE user_id = $1::uuid),
		       (SELECT count(*) FROM core.email_otp_credentials WHERE user_id = $1::uuid),
		       (SELECT count(*) FROM core.recovery_codes WHERE user_id = $1::uuid)`, f.userID).
		Scan(&totp, &email, &recovery); err != nil {
		t.Fatal(err)
	}
	return
}

func (f *signInFixture) audited(t *testing.T, event string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = $2`, f.userID, event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAPersonRemovesTheirOwnSignInMethods(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	giveTOTP(t, f)
	giveEmailFactor(t, f)
	giveRecoveryCodes(t, f)

	// The account page links here, and the page lists both, each removable.
	if acct := accountGET(f, cookie, "/account"); !strings.Contains(acct.Body.String(), `href="/account/security"`) {
		t.Fatal("the account page does not link to the sign-in methods")
	}
	page := accountGET(f, cookie, "/account/security")
	body := page.Body.String()
	if page.Code != http.StatusOK || strings.Count(body, `action="/account/security/remove"`) != 2 ||
		!strings.Contains(body, f.email) {
		t.Fatalf("the page: %d %s", page.Code, truncate(body, 400))
	}

	// The app goes; the email factor is still a second factor, so the codes stay.
	rec := f.formPost(t, cookie, "/account/security", "/account/security/remove", url.Values{"factor": {"totp"}})
	if totp, email, recovery := f.factorRows(t); rec.Code != http.StatusOK || totp != 0 || email != 1 || recovery == 0 {
		t.Fatalf("removing the app: %d; left totp %d, email %d, recovery %d", rec.Code, totp, email, recovery)
	}
	told := 0
	for _, m := range mailer.messages() {
		if m.To == f.email && m.Subject == "A sign-in method was removed from your account" &&
			strings.Contains(m.Body, "authenticator app") && !strings.Contains(m.Body, "administrator") {
			told++
		}
	}
	if told != 1 || f.audited(t, "mfa.totp_removed") != 1 {
		t.Errorf("removing the app: %d notices, %d audited", told, f.audited(t, "mfa.totp_removed"))
	}

	// The last second factor goes, and the recovery codes with it.
	rec = f.formPost(t, cookie, "/account/security", "/account/security/remove", url.Values{"factor": {"email_otp"}})
	if _, email, recovery := f.factorRows(t); email != 0 || recovery != 0 || !strings.Contains(rec.Body.String(), "recovery codes have gone") {
		t.Fatalf("removing the last factor: email %d, recovery %d: %s", email, recovery, truncate(rec.Body.String(), 300))
	}
	if f.audited(t, "mfa.email_otp_removed") != 1 {
		t.Error("the email factor's removal was not audited")
	}

	// Nothing else is removed here: a passkey has its own route, Duo is the
	// administrator's.
	for _, kind := range []string{"webauthn", "duo", "recovery", "users"} {
		if rec := f.formPost(t, cookie, "/account", "/account/security/remove",
			url.Values{"factor": {kind}}); rec.Code != http.StatusBadRequest {
			t.Errorf("removing %q: %d, want 400", kind, rec.Code)
		}
	}
}

// The text-message page's own remove button is the same removal.
func TestTheTextMessagePageRemovesThroughTheSameRemoval(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	f.srv.texter = &captureTexter{}
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.sms_otp_credentials (user_id, org_id, number, verified_at)
		VALUES ($1::uuid, $2::uuid, '+447700900123', now())`, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	giveRecoveryCodes(t, f)
	f.formPost(t, cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"remove"}})
	var sms int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sms_otp_credentials
		WHERE user_id = $1::uuid`, f.userID).Scan(&sms); err != nil {
		t.Fatal(err)
	}
	if _, _, recovery := f.factorRows(t); sms != 0 || recovery != 0 {
		t.Fatalf("after removing the number: sms %d, recovery %d", sms, recovery)
	}
	if len(mailer.messages()) == 0 {
		t.Error("the holder was not told the number was removed")
	}
}
