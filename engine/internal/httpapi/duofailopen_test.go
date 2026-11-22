package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
)

// Duo failing open, for a person whose only second factor is Duo.
//
// The fail-open path used to finish the sign-in itself: open a transaction,
// call completeSignIn. Whose mfa stage, still unsatisfied by a password, began
// the challenge again -- which asked Duo again, failed open again, and opened
// another transaction while the last was held. Each level kept its connection
// until the pool was empty, and from then on every sign-in in the deployment
// waited on a Duo outage, which is the one moment fail-open exists for.

type duoOutage struct {
	f      *signInFixture
	health atomic.Int32
}

func newDuoOutage(t *testing.T) *duoOutage {
	t.Helper()
	f := newSignInFixture(t)
	d := &duoOutage{f: f}

	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/v1/health_check" {
			d.health.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"stat":"FAIL","message":"down"}`))
	}))
	t.Cleanup(stub.Close)
	t.Setenv("SIGNARI_DUO_BASE_URL", stub.URL)

	sealed, err := root.Seal([]byte("0123456789012345678901234567890123456789"), "duo_secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.duo_integrations (org_id, client_id, secret_enc, api_host, fail_open)
		VALUES ($1::uuid, 'DIXXXXXXXXXXXXXXXXXX', $2, 'api-test.duosecurity.com', true)`,
		f.orgID, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.duo_enrollments (user_id, org_id, duo_username)
		VALUES ($1::uuid, $2::uuid, 'person')`, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	return d
}

// deadline bounds the request. The recursion this guards against ends by
// blocking on an empty pool rather than by returning; with a deadline the
// blocked Begin gives up, every level unwinds and releases its connection, and
// the assertions below say what happened instead of the suite hanging.
func deadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func (d *duoOutage) assertOneFailOpenSession(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if n := d.health.Load(); n != 1 {
		t.Errorf("Duo was asked whether it was up %d times for one sign-in, want 1", n)
	}
	if n := d.f.sessionRows(t); n != 1 {
		t.Errorf("%d session rows for one sign-in, want 1", n)
	}
	var skipped int
	if err := d.f.pool.QueryRow(ctx, `
		SELECT count(*) FROM core.audit_events
		 WHERE subject_id = $1::uuid AND event_type = 'mfa.skipped_duo_unavailable'`,
		d.f.userID).Scan(&skipped); err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("%d records of signing in without the second factor, want 1", skipped)
	}
	// Fail-open decides whether the sign-in continues, never what it proved.
	var amr []string
	if err := d.f.pool.QueryRow(ctx,
		`SELECT amr FROM core.sessions WHERE user_id = $1::uuid`, d.f.userID).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	if len(amr) != 1 || !slices.Contains(amr, "pwd") {
		t.Errorf("the fail-open session claims amr %v, want only the password", amr)
	}
}

func TestDuoFailingOpenSignsInOnceThroughThePasswordForm(t *testing.T) {
	d := newDuoOutage(t)
	got := d.f.attemptCtx(t, deadline(t), d.f.email, signInTestPassword)
	if !got.signedIn() {
		t.Fatalf("Duo is down and the deployment fails open, but no session was issued "+
			"(status %d, Duo asked %d times)", got.status, d.health.Load())
	}
	d.assertOneFailOpenSession(t)
}

// Every other way in -- passkey, Kerberos, federation, the Duo callback --
// reaches the mfa stage inside completeSignIn, holding its transaction.
func TestDuoFailingOpenSignsInOnceFromInsideTheFlow(t *testing.T) {
	d := newDuoOutage(t)
	ctx := context.Background()
	tx, err := d.f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(deadline(t), http.MethodPost, "/login", nil)
	d.f.srv.completeSignIn(rec, req, tx, d.f.userID, d.f.orgID, []string{"pwd"}, "")
	if !sessionSet(rec) {
		t.Fatalf("no session from inside the flow (status %d, Duo asked %d times)",
			rec.Code, d.health.Load())
	}
	d.assertOneFailOpenSession(t)
}
