package store

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/migrate"
)

// A session a restore brought back stays dead after `restore finalize`
// (3.10). The backup holds every session as it was, so one ended after the
// backup was taken is live again in the restored database, and nothing can
// tell it from one that was never ended: every session and refresh family is
// ended, each application told, and the restore recorded. Against a database
// of its own, because it ends every session there is.
func TestFinalizingARestoreEndsWhatTheBackupBroughtBack(t *testing.T) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("signari_restoretest_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	u, err := url.Parse(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, tier := range []migrate.Tier{migrate.TierBootstrap, migrate.TierCore} {
		if _, err := migrate.Up(ctx, conn, tier, 0, migrate.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// The restored state: a live session with an application that wants to be
	// told, a refresh family on it, and one on no session at all.
	_, userID, clientID, sid := fixture(t, conn)
	var orgID string
	must(t, conn.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID))
	for _, s := range []*string{&sid, nil} {
		_, err := conn.Exec(ctx, `
			INSERT INTO core.refresh_token_families (org_id, client_id, user_id, sid)
			VALUES ($1::uuid, $2, $3::uuid, $4)`, orgID, clientID, userID, s)
		must(t, err)
	}

	f, err := FinalizeRestore(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if f.People != 1 || f.Sessions != 1 || f.Notices != 1 || f.RefreshFamilies != 1 {
		t.Errorf("finalize ended %+v, want one person, one session, one notice and the "+
			"family on no session (the session's own goes with it)", f)
	}

	var revoked, reason string
	must(t, conn.QueryRow(ctx, `
		SELECT (revoked_at IS NOT NULL)::text, COALESCE(revocation_reason, '') FROM core.sessions WHERE sid = $1`,
		sid).Scan(&revoked, &reason))
	if revoked != "true" || reason != "restored" {
		t.Errorf("the restored session is revoked=%s reason=%q, want ended as restored", revoked, reason)
	}
	var liveFamilies, notices, audited int
	must(t, conn.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM core.refresh_token_families WHERE revoked_at IS NULL),
		       (SELECT count(*) FROM core.outbox WHERE topic = 'backchannel_logout'
		           AND payload->>'sub' = $1 AND payload->>'reason' = 'restored'),
		       (SELECT count(*) FROM core.audit_events WHERE event_type = 'restore.finalized')`,
		userID).Scan(&liveFamilies, &notices, &audited))
	if liveFamilies != 0 || notices != 1 || audited != 1 {
		t.Errorf("after finalize: %d live refresh families, %d logout notices, %d restore.finalized "+
			"rows; want 0, 1, 1", liveFamilies, notices, audited)
	}

	again, err := FinalizeRestore(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if again.People != 0 || again.Sessions != 0 || again.RefreshFamilies != 0 {
		t.Errorf("a second run ended %+v; it should find nothing live", again)
	}
}
