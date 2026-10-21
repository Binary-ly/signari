package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A person deletes their own account (5.07), through the unenrolment flow:
// typed confirmation, the account erased as the Admin API erases it, every
// application they used told by back-channel logout, the address told.

func (f *signInFixture) accountRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.users WHERE id = $1::uuid`,
		f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAPersonDeletesTheirOwnAccount(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	ctx := context.Background()
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	sid, _, err := store.ResolveSessionCookie(ctx, f.pool, store.HashToken(cookie))
	if err != nil || sid == "" {
		t.Fatalf("the fixture's session: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET backchannel_logout_uri = 'https://rp.example.test/bc'
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.outbox WHERE topic = 'backchannel_logout' AND payload->>'sub' = $1`, f.userID)
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.subject_keys WHERE subject_id = $1::uuid`, f.userID)
	})

	if acct := accountGET(f, cookie, "/account").Body.String(); !strings.Contains(acct, `href="/account/delete"`) {
		t.Fatal("the account page does not link to deleting the account")
	}
	page := accountGET(f, cookie, "/account/delete").Body.String()
	if !strings.Contains(page, `action="/account/delete"`) || !strings.Contains(page, f.email) {
		t.Fatalf("the page does not ask for the address to confirm: %s", truncate(page, 300))
	}

	// A mistyped confirmation deletes nothing.
	if body := f.formPost(t, cookie, "/account/delete", "/account/delete",
		url.Values{"confirm": {"not-" + f.email}}).Body.String(); !strings.Contains(body, "does not match") ||
		f.accountRows(t) != 1 {
		t.Fatalf("a wrong confirmation: account rows %d, %s", f.accountRows(t), truncate(body, 200))
	}

	rec := f.formPost(t, cookie, "/account/delete", "/account/delete", url.Values{"confirm": {strings.ToUpper(f.email)}})
	if f.accountRows(t) != 0 || !strings.Contains(rec.Body.String(), "has been deleted") {
		t.Fatalf("after confirming: account rows %d, %s", f.accountRows(t), truncate(rec.Body.String(), 200))
	}
	var notices, audited, shredded int
	if err := f.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM core.outbox WHERE topic = 'backchannel_logout'
		          AND payload->>'sub' = $1 AND payload->>'client_id' = $2 AND payload->>'reason' = 'user_deleted'),
		       (SELECT count(*) FROM core.audit_events WHERE subject_id = $1::uuid AND event_type = 'account.deleted'
		          AND detail->>'by' = 'owner'),
		       (SELECT count(*) FROM core.subject_keys WHERE subject_id = $1::uuid AND erased_at IS NOT NULL)`,
		f.userID, f.clientID).Scan(&notices, &audited, &shredded); err != nil {
		t.Fatal(err)
	}
	if notices != 1 || audited != 1 || shredded != 1 {
		t.Errorf("back-channel logouts %d, audited %d, erasure recorded %d; want 1, 1, 1", notices, audited, shredded)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		cleared = cleared || (c.Name == SessionCookieName && c.MaxAge < 0)
	}
	told := false
	for _, m := range mailer.messages() {
		told = told || (m.To == f.email && m.Subject == "Your account was deleted")
	}
	if !cleared || !told {
		t.Errorf("session cookie cleared %v, address told %v", cleared, told)
	}
}

// The organisation's unenrolment flow decides: deny closes self-service
// deletion, and a flow that accepts only one proof refuses a sign-in by
// another.
func TestTheUnenrolmentFlowDecidesWhetherAnAccountMayBeDeleted(t *testing.T) {
	for _, c := range []struct{ name, stages string }{
		{"closed", "[deny]"},
		{"passkeys only", "[passkey, done]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, cookie := enrolFixture(t)
			clearSignInBucket(t, f.pool)
			f.applyFlow(t, `
version: 1
flows:
  - name: deletion
    on: unenrolment
    stages: `+c.stages+`
    tests: [{name: as written, given: {}, expect: `+c.stages+`}]
`)
			if page := accountGET(f, cookie, "/account/delete").Body.String(); !strings.Contains(page, "does not let accounts be deleted") {
				t.Errorf("the page offers deletion: %s", truncate(page, 300))
			}
			rec := f.formPost(t, cookie, "/account", "/account/delete", url.Values{"confirm": {f.email}})
			if f.accountRows(t) != 1 || rec.Code != http.StatusOK {
				t.Errorf("deleted under a flow that refuses it: %d rows, %d", f.accountRows(t), rec.Code)
			}
		})
	}
}
