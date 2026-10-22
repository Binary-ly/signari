package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
)

// Doing without a password (5.15): only with two passkeys, so losing one
// device is not the end of the account, and only where the sign-in flow takes
// a passkey alone; the same guard on the directory's write path.

func addPasskeys(t *testing.T, f *signInFixture, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := f.pool.Exec(context.Background(), `
			INSERT INTO core.webauthn_credentials
				(user_id, org_id, credential_id, public_key, rp_id, friendly_name, is_discoverable)
			VALUES ($1::uuid, $2::uuid, decode(md5(gen_random_uuid()::text),'hex'), '\x02'::bytea,
			        'localhost', 'key ' || gen_random_uuid(), true)`, f.userID, f.orgID); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *signInFixture) passwords(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.password_credentials WHERE user_id = $1::uuid`, f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestThePasswordIsRemovedOnlyWithTwoPasskeys(t *testing.T) {
	f, cookie := enrolFixture(t)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	// The token from the password page, which always has a form: the security
	// page has none of its own until there is something it may remove.
	remove := func() string {
		return f.formPost(t, cookie, "/account/password", "/account/password/remove", url.Values{}).Body.String()
	}
	for _, have := range []int{0, 1} {
		if have == 1 {
			addPasskeys(t, f, 1)
		}
		page := accountGET(f, cookie, "/account/security").Body.String()
		if strings.Contains(page, `action="/account/password/remove"`) {
			t.Errorf("with %d passkey(s) the page offers to remove the password", have)
		}
		if !strings.Contains(page, "add a second passkey first") {
			t.Errorf("with %d passkey(s) the page does not say what is missing", have)
		}
		if out := remove(); f.passwords(t) != 1 || !strings.Contains(out, "Your password was kept") {
			t.Fatalf("with %d passkey(s): %d password(s) left; %s", have, f.passwords(t), truncate(out, 200))
		}
	}

	addPasskeys(t, f, 1)
	if page := accountGET(f, cookie, "/account/security").Body.String(); !strings.Contains(page, `action="/account/password/remove"`) {
		t.Fatal("with two passkeys the page does not offer to remove the password")
	}
	if out := remove(); f.passwords(t) != 0 || !strings.Contains(out, "Your password has been removed") {
		t.Fatalf("with two passkeys: %d password(s) left; %s", f.passwords(t), truncate(out, 200))
	}
	var audited int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = 'user.password_removed'`, f.userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	told := false
	for _, m := range mailer.messages() {
		told = told || m.Subject == "Your password was removed"
	}
	if audited != 1 || !told {
		t.Errorf("recorded %d time(s), told %v; want 1, true", audited, told)
	}
}

// Two passkeys are not enough where the organisation's sign-in takes no
// passkey alone: removing the password would leave a way in the flow refuses.
func TestASignInThatAsksForAPasswordKeepsIt(t *testing.T) {
	f, cookie := enrolFixture(t)
	addPasskeys(t, f, 2)
	f.applyFlow(t, `
version: 1
flows:
  - name: passwords-only
    on: authentication
    stages: [password, session]
    tests: [{name: as written, given: {proved_by_password: true}, expect: [password, session]}]
`)
	if page := accountGET(f, cookie, "/account/security").Body.String(); strings.Contains(page, `action="/account/password/remove"`) {
		t.Error("the page offers to remove a password the sign-in flow asks for")
	}
	f.formPost(t, cookie, "/account/password", "/account/password/remove", url.Values{})
	if f.passwords(t) != 1 {
		t.Error("the password was removed though the sign-in flow takes no passkey alone")
	}
}

// The directory's `delete userPassword` passes the same guard.
func TestAnLDAPWriteCannotTakeAwayThePasswordOfSomebodyWithoutTwoPasskeys(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	w := NewLDAPWriter(f.pool, nil, passwords.Policy{}, f.orgID, slog.New(slog.NewTextHandler(io.Discard, nil)))
	empty := ""
	if err := w.Update(ctx, "cn=admin", f.email, &ldapd.Update{Password: &empty}); !errors.Is(err, ldapd.ErrConstraint) {
		t.Fatalf("removing the only way in: %v, want a constraint violation", err)
	}
	if f.passwords(t) != 1 {
		t.Fatal("the directory removed the password of somebody with no passkey")
	}
	addPasskeys(t, f, 2)
	if err := w.Update(ctx, "cn=admin", f.email, &ldapd.Update{Password: &empty}); err != nil {
		t.Fatalf("with two passkeys: %v", err)
	}
	if f.passwords(t) != 0 {
		t.Error("with two passkeys the directory's removal did not happen")
	}
}
