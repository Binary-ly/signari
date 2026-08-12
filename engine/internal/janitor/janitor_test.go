package janitor

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parsing dsn: %v", err)
	}
	// Every pooled connection, not just the first: the janitor's work spans
	// several checkouts and a connection without the role would fail on RLS.
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// A session past not_after must be TERMINATED, and terminating it must queue the
// back-channel notice. Merely deleting the row, or revoking it without notifying,
// leaves every relying party still showing the user as signed in -- which is the
// failure this job exists to prevent.
func TestSweepTerminatesExpiredSessionsAndNotifiesRelyingParties(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	sid := plantExpiredSession(t, pool)

	st, err := RunOnce(ctx, pool, discard())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if st.Skipped {
		t.Fatal("the pass was skipped; another holder had the lock")
	}
	if st.SessionsSwept < 1 {
		t.Fatalf("swept %d sessions, want at least the one planted", st.SessionsSwept)
	}

	var reason string
	var revoked bool
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(revocation_reason, ''), revoked_at IS NOT NULL
		FROM core.sessions WHERE sid = $1`, sid).Scan(&reason, &revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("the expired session is still live after a sweep")
	}
	if reason != "expired" {
		t.Errorf("revocation_reason = %q, want \"expired\"", reason)
	}

	var notices int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM core.outbox
		WHERE topic = 'backchannel_logout' AND payload->>'sid' = $1`, sid).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices == 0 {
		t.Error("no back-channel logout notice was queued; the relying party will never learn the session ended")
	}
}

// The second pass must find nothing. Without the revoked_at IS NULL filter, every
// pass would re-terminate every already-dead session and re-queue its notices --
// a logout storm that grows with the age of the database.
func TestSweepIsIdempotent(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	plantExpiredSession(t, pool)

	if _, err := RunOnce(ctx, pool, discard()); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	st, err := RunOnce(ctx, pool, discard())
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if st.SessionsSwept != 0 {
		t.Errorf("the second pass swept %d sessions; already-dead sessions are being re-terminated", st.SessionsSwept)
	}
}

// The whole reason this is safe to start on every node.
func TestConcurrentPassIsSkippedNotDuplicated(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// Hold the lock the way a peer node would: inside a transaction.
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()

	var got bool
	if err := holder.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("could not take the lock to simulate a peer")
	}

	plantExpiredSession(t, pool)

	st, err := RunOnce(ctx, pool, discard())
	if err != nil {
		t.Fatalf("RunOnce should not error when the lock is held: %v", err)
	}
	if !st.Skipped {
		t.Fatal("a second node ran the pass while a peer held the lock")
	}
	if st.SessionsSwept != 0 {
		t.Errorf("a skipped pass reported %d swept sessions", st.SessionsSwept)
	}
}

// plantExpiredSession creates a session that expired an hour ago, bound to a
// client with a back-channel logout endpoint so a notice is expected.
func plantExpiredSession(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()

	var orgID, userID string
	err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://janitor-' || gen_random_uuid() || '.test', 'J') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'j' || substr(gen_random_uuid()::text, 1, 8), 'Org' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, email, user_handle)
		SELECT id, 'j' || substr(gen_random_uuid()::text, 1, 8) || '@example.test',
		       decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text) ||
		              md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex')
		FROM o
		RETURNING org_id::text, id::text`).Scan(&orgID, &userID)
	if err != nil {
		t.Fatalf("fixture user: %v", err)
	}

	clientID := "janitor-" + orgID[:8]
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, backchannel_logout_uri)
		VALUES ($1, $2, 'J', 'confidential', 'x', 'https://rp.test/backchannel')`,
		clientID, orgID); err != nil {
		t.Fatalf("fixture client: %v", err)
	}

	sid := "janitor-sid-" + orgID[:8]
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, decode(md5($1), 'hex'), $2, $3, '1', ARRAY['pwd'], now() - interval '2 hours', now() - interval '1 hour')`,
		sid, orgID, userID); err != nil {
		t.Fatalf("fixture session: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)`, sid, clientID); err != nil {
		t.Fatalf("fixture session_client: %v", err)
	}

	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(c, `DELETE FROM core.outbox WHERE payload->>'sid' = $1`, sid)
		_, _ = pool.Exec(c, `DELETE FROM core.session_clients WHERE sid = $1`, sid)
		_, _ = pool.Exec(c, `DELETE FROM core.sessions WHERE sid = $1`, sid)
	})

	return sid
}
