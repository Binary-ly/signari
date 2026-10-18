package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// Email and SMS codes stop at the consecutive-failure ceiling, as an
// authenticator app does. Each code allowed five guesses and a new one came
// every minute, with nothing counting across codes: about 960 guesses a day at
// a six-digit code, indefinitely.
func TestEmailAndSMSCodesStopAtTheCeilingAndTellTheHolder(t *testing.T) {
	for _, c := range []struct {
		factor, table, subject string
		give                   func(t *testing.T, f *signInFixture)
		issue                  func(context.Context, pgx.Tx, string) (string, string, error)
	}{
		{factorEmailOTP, "email_otp_credentials", "mail.emailotp.disabled.subject", giveEmailFactor, store.IssueEmailOTP},
		{factorSMSOTP, "sms_otp_credentials", "mail.smsotp.disabled.subject", giveSMSFactor, store.IssueSMSOTP},
	} {
		t.Run(c.factor, func(t *testing.T) {
			f := newSignInFixture(t)
			clearSecondFactorBucket(t, f)
			mailer := &captureMailer{}
			f.srv.mailer = mailer
			ctx := context.Background()
			c.give(t, f)
			codes := giveRecoveryCodes(t, f)

			// Ninety-nine failures behind it, and a live code out.
			if _, err := f.pool.Exec(ctx, fmt.Sprintf(`
				UPDATE core.%s SET failed_attempts = $2, last_sent_at = now() - interval '1 hour'
				 WHERE user_id = $1::uuid`, c.table), f.userID, store.MaxConsecutiveFactorFailures-1); err != nil {
				t.Fatal(err)
			}
			live := issueCode(t, f, c.issue)
			wrong := "000000"
			if live == wrong {
				wrong = "111111"
			}
			step := newMFAStep(t, f)

			if rec := step.submit(wrong); rec.Code != http.StatusUnauthorized {
				t.Fatalf("the hundredth wrong code answered %d, want 401", rec.Code)
			}
			var disabled bool
			if err := f.pool.QueryRow(ctx, fmt.Sprintf(
				`SELECT disabled_at IS NOT NULL FROM core.%s WHERE user_id = $1::uuid`, c.table),
				f.userID).Scan(&disabled); err != nil {
				t.Fatal(err)
			}
			if !disabled {
				t.Fatal("the hundredth consecutive failure did not disable the factor")
			}
			subject := f.srv.notifierFor(ctx, f.userID).Text(c.subject)
			told := 0
			for _, m := range mailer.messages() {
				if m.To == f.email && m.Subject == subject {
					told++
				}
			}
			if told != 1 {
				t.Fatalf("the holder was told %d time(s), want 1", told)
			}

			// The code that was live no longer works, and no new one is sent.
			if rec := step.submit(live); sessionSet(rec) {
				t.Fatal("a disabled factor's code still signed somebody in")
			}
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, _, ierr := c.issue(ctx, tx, f.userID)
			_ = tx.Rollback(ctx)
			if ierr == nil {
				t.Fatal("a disabled factor was issued another code")
			}

			// Still a multi-factor account; the way in is a recovery code.
			if has, err := store.HasSecondFactor(ctx, f.pool, f.userID); err != nil || !has {
				t.Fatalf("disabling the factor left the account without a second factor (%v, %v)", has, err)
			}
			if rec := step.submit(codes[0]); !sessionSet(rec) {
				t.Fatalf("a recovery code did not sign the holder in (status %d)", rec.Code)
			}
		})
	}
}

// A right code resets the count: the ceiling is for failures in a row.
func TestARightEmailCodeResetsTheFailureCount(t *testing.T) {
	f := newSignInFixture(t)
	clearSecondFactorBucket(t, f)
	ctx := context.Background()
	giveEmailFactor(t, f)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.email_otp_credentials SET failed_attempts = 50, last_sent_at = now() - interval '1 hour'
		 WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	live := issueCode(t, f, store.IssueEmailOTP)
	if rec := newMFAStep(t, f).submit(live); !sessionSet(rec) {
		t.Fatalf("the right code did not sign in (status %d)", rec.Code)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT failed_attempts FROM core.email_otp_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a right code left %d consecutive failures counted", n)
	}
}

func issueCode(t *testing.T, f *signInFixture, issue func(context.Context, pgx.Tx, string) (string, string, error)) string {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	code, _, err := issue(ctx, tx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return code
}

// giveEmailFactor proves an address through the enrolment functions themselves.
func giveEmailFactor(t *testing.T, f *signInFixture) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartEmailOTPEnrolment(ctx, tx, f.userID, f.orgID, f.email); err != nil {
		t.Fatal(err)
	}
	code, _, err := store.IssueEmailOTPEnrolment(ctx, tx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := store.ConfirmEmailOTPEnrolment(ctx, tx, f.userID, code); err != nil || !ok {
		t.Fatalf("proving the address: %v %v", ok, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// giveSMSFactor proves a number through the enrolment functions themselves.
func giveSMSFactor(t *testing.T, f *signInFixture) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	number := fmt.Sprintf("+4477%09d", time.Now().UnixNano()%1_000_000_000)
	if _, err := store.EnrollSMSOTP(ctx, tx, f.userID, f.orgID, number); err != nil {
		t.Fatal(err)
	}
	code, _, err := store.IssueSMSOTPEnrolment(ctx, tx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := store.ConfirmSMSOTPEnrolment(ctx, tx, f.userID, code); err != nil || !ok {
		t.Fatalf("proving the number: %v %v", ok, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
