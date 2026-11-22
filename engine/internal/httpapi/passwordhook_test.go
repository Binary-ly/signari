package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A person moves from a system only the operator's own service can talk to, through the
// `password_verify` hook, at their first sign-in, and leaves a local hash (10.07, 10.14).
// The provider is told who and what they typed, is asked once, and is never asked again;
// what it says no to is a wrong password, and what it does not answer is an outage.
func TestAPersonMigratesThroughThePasswordVerifyHook(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerAccountWindow)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root

	// Registered and configured as an operator would, in order.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.SetMigrationSource(ctx, tx, root, f.orgID, store.MigrationSourceConfig{
		Kind: "hook", DisplayName: "Old system"}); err == nil {
		t.Fatal("a hook source with no provider to ask was accepted; it would refuse everybody still to migrate")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, 'old-system', 'password_verify', 'https://old-system.test/verify', 'fail_closed', 2000)`,
		f.orgID); err != nil {
		t.Fatal(err)
	}
	tx, err = f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	source, err := store.SetMigrationSource(ctx, tx, root, f.orgID, store.MigrationSourceConfig{
		Kind: "hook", DisplayName: "Old system"})
	if err != nil {
		t.Fatalf("a hook source: %v", err)
	}
	if err := store.SetMigrationSourceEnabled(ctx, tx, f.orgID, true); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.migration_sources WHERE id = $1::uuid`, source)
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.providers WHERE org_id = $1::uuid AND name = 'old-system'`, f.orgID)
	})

	const oldPassword = "the-password-the-old-system-knows"
	type asked struct {
		Username string `json:"username"`
		Password string `json:"password"`
		OrgID    string `json:"org_id"`
	}
	var calls []asked
	answer := func(a asked) (int, string) {
		if a.Password == oldPassword {
			return http.StatusOK, `{"verified":true}`
		}
		return http.StatusOK, `{"verified":false}`
	}
	f.srv.outboundHTTP = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var a asked
			_ = json.NewDecoder(r.Body).Decode(&a)
			calls = append(calls, a)
			status, body := answer(a)
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	t.Cleanup(func() { f.srv.outboundHTTP = nil })

	n := time.Now().UnixNano()
	person := func(tag string) (email, id string) {
		t.Helper()
		email = fmt.Sprintf("hook-%s-%d@example.test", tag, n)
		if err := f.pool.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, user_handle, migration_state, migration_source_id)
			VALUES ($1::uuid, $2, decode(md5($2) || md5($2 || 'x') || md5($2 || 'y') || md5($2 || 'z'), 'hex'),
			        'pending', $3::uuid) RETURNING id::text`, f.orgID, email, source).Scan(&id); err != nil {
			t.Fatalf("pending user: %v", err)
		}
		return email, id
	}
	state := func(id string) (string, bool) {
		t.Helper()
		var migration string
		var hashed bool
		if err := f.pool.QueryRow(ctx, `SELECT u.migration_state, EXISTS (SELECT 1 FROM core.password_credentials pc
			WHERE pc.user_id = u.id) FROM core.users u WHERE u.id = $1::uuid`, id).Scan(&migration, &hashed); err != nil {
			t.Fatal(err)
		}
		return migration, hashed
	}
	const signedIn = `"status":"signed in"`
	said := func(rec *httptest.ResponseRecorder, text string) bool {
		return strings.Contains(rec.Body.String(), text)
	}

	// A wrong password, as the provider says: charged like any other, and nothing kept.
	email, id := person("wrong")
	rec := passwordSignIn(t, f.srv, "203.0.113.70", email, "not-it")
	if said(rec, signedIn) || !said(rec, "Incorrect username or password") {
		t.Fatalf("a password the provider refused gave %d: %.200s", rec.Code, rec.Body.String())
	}
	if got, hashed := state(id); got != "pending" || hashed {
		t.Errorf("after a refusal: migration_state %q, local hash %v", got, hashed)
	}
	if len(calls) != 1 || calls[0].Username != email || calls[0].Password != "not-it" || calls[0].OrgID != f.orgID {
		t.Fatalf("the provider was asked %+v", calls)
	}

	// Right, and the person is signed in with a hash of their own.
	calls = nil
	email, id = person("right")
	rec = passwordSignIn(t, f.srv, "203.0.113.71", email, oldPassword)
	if !said(rec, signedIn) {
		t.Fatalf("a password the provider verified gave %d: %.200s", rec.Code, rec.Body.String())
	}
	if got, hashed := state(id); got != "complete" || !hashed {
		t.Errorf("after the provider verified it: migration_state %q, local hash %v", got, hashed)
	}
	if len(calls) != 1 {
		t.Fatalf("the provider was asked %d times", len(calls))
	}

	// Later sign-ins are local: with the provider saying no to everything it is not
	// even asked, and the person gets in.
	calls = nil
	answer = func(asked) (int, string) { return http.StatusOK, `{"verified":false}` }
	rec = passwordSignIn(t, f.srv, "203.0.113.72", email, oldPassword)
	if !said(rec, signedIn) {
		t.Errorf("the second sign-in gave %d: %.200s", rec.Code, rec.Body.String())
	}
	if len(calls) != 0 {
		t.Errorf("the provider was told a migrated person's password: %+v", calls)
	}

	// No answer in every way there is, none of them a wrong password and none a yes.
	email, id = person("outage")
	for _, broken := range []struct {
		name, body string
		status     int
	}{
		{"a refusal of the call", `{"verified":true}`, http.StatusForbidden},
		{"a server error", ``, http.StatusBadGateway},
		{"a body that is not JSON", `<html>`, http.StatusOK},
		{"a 200 that does not say", `{}`, http.StatusOK},
		{"a verdict of the wrong type", `{"verified":"true"}`, http.StatusOK},
		{"a null verdict", `{"verified":null}`, http.StatusOK},
	} {
		answer = func(asked) (int, string) { return broken.status, broken.body }
		rec = passwordSignIn(t, f.srv, "203.0.113.73", email, oldPassword)
		if said(rec, signedIn) || !said(rec, "temporarily unavailable") {
			t.Errorf("%s gave %d: %.160s", broken.name, rec.Code, rec.Body.String())
		}
		if got, hashed := state(id); got != "pending" || hashed {
			t.Errorf("after %s: migration_state %q, local hash %v", broken.name, got, hashed)
		}
	}
	var lastError string
	if err := f.pool.QueryRow(ctx, `SELECT coalesce(last_error, '') FROM core.migration_sources WHERE id = $1::uuid`,
		source).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastError, "verified") {
		t.Errorf("the source's last error is %q; the operator should see what the provider did", lastError)
	}
	if strings.Contains(lastError, oldPassword) {
		t.Error("the source's last error carries the password")
	}

	// A provider taken away leaves the source refusing, as an outage.
	if _, err := f.pool.Exec(ctx, `UPDATE core.providers SET enabled = false
		WHERE org_id = $1::uuid AND name = 'old-system'`, f.orgID); err != nil {
		t.Fatal(err)
	}
	calls = nil
	answer = func(asked) (int, string) { return http.StatusOK, `{"verified":true}` }
	rec = passwordSignIn(t, f.srv, "203.0.113.74", email, oldPassword)
	if said(rec, signedIn) || !said(rec, "temporarily unavailable") || len(calls) != 0 {
		t.Errorf("with the provider disabled: %d, %d calls", rec.Code, len(calls))
	}
}

// What `migration-source test` makes of a hook source: the step, and an empty password
// that is never sent.
func TestAHookSourceIsTestedThroughItsProvider(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	calls := 0
	body := `{"verified":true}`
	client := func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	r := store.TryPasswordProvider(ctx, f.pool, nil, client, f.orgID, "alice", "secret")
	if r.OK || r.Step != delegated.StepConfiguration {
		t.Errorf("with no provider: %+v", r)
	}
	if _, err := store.ConsultPasswordProvider(ctx, f.pool, nil, client, f.orgID, "alice", "secret"); !errors.Is(err, store.ErrNoPasswordProvider) {
		t.Errorf("with no provider: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, 'old-system', 'password_verify', 'https://old-system.test/verify', 'fail_closed', 2000)`,
		f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.providers WHERE org_id = $1::uuid AND name = 'old-system'`, f.orgID)
	})
	if r := store.TryPasswordProvider(ctx, f.pool, nil, client, f.orgID, "alice", "secret"); !r.OK {
		t.Errorf("a verified credential: %+v", r)
	}
	body = `{"verified":false}`
	if r := store.TryPasswordProvider(ctx, f.pool, nil, client, f.orgID, "alice", "secret"); r.OK || r.Step != delegated.StepAnswer {
		t.Errorf("a refused credential: %+v", r)
	}
	calls = 0
	body = `{"verified":true}`
	if yes, err := store.ConsultPasswordProvider(ctx, f.pool, nil, client, f.orgID, "alice", ""); yes || err != nil || calls != 0 {
		t.Errorf("an empty password: %v, %v, sent %d times", yes, err, calls)
	}
}
