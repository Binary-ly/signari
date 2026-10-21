package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A person moves their own account to another address (5.06): the account
// keeps its address until a code sent to the new one comes back, the new one is
// verified by that proof, and the old address is told.

func (f *signInFixture) addressNow(t *testing.T) (email string, verified bool) {
	t.Helper()
	if err := f.pool.QueryRow(context.Background(), `SELECT COALESCE(email, ''), email_verified_at IS NOT NULL
		FROM core.users WHERE id = $1::uuid`, f.userID).Scan(&email, &verified); err != nil {
		t.Fatal(err)
	}
	return email, verified
}

func TestAPersonMovesTheirAccountToANewAddressOnlyWithItsCode(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	old := f.email
	moved := fmt.Sprintf("moved-%d@example.test", time.Now().UnixNano())
	post := func(form url.Values) string {
		t.Helper()
		return f.formPost(t, cookie, "/account/email", "/account/email", form).Body.String()
	}

	if acct := accountGET(f, cookie, "/account").Body.String(); !strings.Contains(acct, `href="/account/email"`) {
		t.Fatal("the account page does not link to the address page")
	}
	post(url.Values{"step": {"start"}, "address": {moved}})
	var code string
	for _, m := range mailer.messages() {
		if m.To == old {
			t.Errorf("the code went to the old address: %q", m.Subject)
		}
		if m.To == moved {
			code = codeInMail.FindString(m.Body)
		}
	}
	if code == "" {
		t.Fatal("no code went to the new address")
	}
	// Unchanged until the code comes back, wrong codes included.
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	if body := post(url.Values{"step": {"verify"}, "code": {wrong}}); !strings.Contains(body, "not right") {
		t.Errorf("a wrong code was not refused: %s", truncate(body, 300))
	}
	if now, _ := f.addressNow(t); now != old {
		t.Fatalf("the address moved to %q before its code came back", now)
	}

	before := len(mailer.messages())
	post(url.Values{"step": {"verify"}, "code": {code}})
	if now, verified := f.addressNow(t); now != moved || !verified {
		t.Fatalf("after the right code: %q, verified %v", now, verified)
	}
	told := map[string]bool{}
	for _, m := range mailer.messages()[before:] {
		if m.Subject == "Your account moved to a new email address" && !strings.Contains(m.Body, moved) &&
			!strings.Contains(m.Body, old) {
			told[m.To] = true
		}
	}
	if !told[old] || !told[moved] {
		t.Errorf("told %v, want the old address and the new, neither named", told)
	}
	var audited int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = 'user.email_changed'`, f.userID).Scan(&audited); err != nil || audited != 1 {
		t.Errorf("%d user.email_changed records (%v), want 1", audited, err)
	}
	// Spent: the same code again moves nothing anywhere.
	post(url.Values{"step": {"verify"}, "code": {code}})
	if now, _ := f.addressNow(t); now != moved {
		t.Errorf("a spent code changed the address to %q", now)
	}
}

func TestAChangeOfAddressRefusesWhatCannotBeAndCanBeAbandoned(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	f.srv.mailer = &captureMailer{}
	ctx := context.Background()
	other := fmt.Sprintf("taken-%d@example.test", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(convert_to($2, 'UTF8')) || sha256(convert_to($2 || 'x', 'UTF8')), $2)`,
		f.orgID, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, other) })
	post := func(form url.Values) string {
		t.Helper()
		return f.formPost(t, cookie, "/account/email", "/account/email", form).Body.String()
	}
	for addr, want := range map[string]string{
		strings.ToUpper(other):   "another account already uses that address",
		strings.ToUpper(f.email): "that is already the address on your account",
		"not-an-address":         "Enter the full address",
	} {
		if body := post(url.Values{"step": {"start"}, "address": {addr}}); !strings.Contains(body, want) {
			t.Errorf("starting a change to %q: want %q in %s", addr, want, truncate(body, 200))
		}
	}
	moved := fmt.Sprintf("abandoned-%d@example.test", time.Now().UnixNano())
	post(url.Values{"step": {"start"}, "address": {moved}})
	if body := post(url.Values{"step": {"cancel"}}); !strings.Contains(body, "unchanged") {
		t.Errorf("cancelling: %s", truncate(body, 200))
	}
	var pending int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.email_changes WHERE user_id = $1::uuid`,
		f.userID).Scan(&pending); err != nil || pending != 0 {
		t.Errorf("%d changes left after cancelling (%v)", pending, err)
	}
	if now, _ := f.addressNow(t); now != f.email {
		t.Errorf("an abandoned change moved the address to %q", now)
	}
}
