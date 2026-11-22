package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A sign-in's proving stage is matched to the proof presented (2.49): a
// `passkey, session` flow refuses a password, and the built-in flow still
// admits every way in it admitted before. The walker passed the password and
// passkey stages whatever amr held, so "passkeys only" admitted a password,
// reproduced against the running server.
func TestASignInsProvingStageMustBeTheProofPresented(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	routes := map[string][]string{
		"password":       {"pwd"},
		"passkey":        {"user", "hwk", "mfa"},
		"Kerberos":       {"krb"},
		"provider":       {"fed"},
		"password + key": {"pwd", "user", "hwk", "mfa"},
	}
	signIn := func(amr []string) bool {
		t.Helper()
		before := f.sessionRows(t)
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		f.srv.completeSignIn(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/login", nil),
			tx, f.userID, f.orgID, amr, "")
		return f.sessionRows(t) > before
	}

	// The built-in flow, as every deployment that wrote none runs it.
	for name, amr := range routes {
		if !signIn(amr) {
			t.Errorf("the built-in flow refused a %s sign-in it has always admitted", name)
		}
	}

	f.applyFlow(t, `
version: 1
flows:
  - name: passkeys-only
    on: authentication
    stages: [passkey, session]
    tests: [{name: t, given: {}, expect: [passkey, session]}]
`)
	for name, amr := range routes {
		want := name == "passkey"
		if got := signIn(amr); got != want {
			t.Errorf("under passkeys-only a %s sign-in signed in: %v, want %v", name, got, want)
		}
	}
	var reason, required, presented string
	if err := f.pool.QueryRow(ctx, `SELECT detail->>'reason', detail->>'required', detail->>'presented'
		FROM core.audit_events WHERE subject_id = $1::uuid AND event_type = 'login.failed'
		ORDER BY occurred_at DESC LIMIT 1`, f.userID).Scan(&reason, &required, &presented); err != nil {
		t.Fatal(err)
	}
	if reason != "flow_requires_another_proof" || required != "passkey" {
		t.Errorf("the refusal was recorded as %q, %q required, %q presented", reason, required, presented)
	}
}
