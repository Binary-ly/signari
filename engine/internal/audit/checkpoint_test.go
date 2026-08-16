package audit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Checkpoints, and the two things they must not do: repair the past, or hide
// the future.

// checkpointPool requires a DISPOSABLE database.
//
// These tests delete and alter audit rows on purpose, which is the only way to
// prove a break is detected -- and doing so breaks that database's chain
// permanently. There is no repair, by design: rewriting entries to close a
// break is exactly what the chain exists to make detectable.
//
// So they refuse to run against SIGNARI_TEST_DSN, which every other test uses.
// The first version did use it, and left the shared chain broken at id 688 --
// failing three unrelated audit tests on data they had not touched, which is
// precisely the "cries wolf" outcome this whole area is about.
//
//	createdb signari_scratch
//	SIGNARI_DSN=…signari_scratch signari migrate all
//	SIGNARI_DESTRUCTIVE_TEST_DSN=…signari_scratch go test ./internal/audit/
func checkpointPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SIGNARI_DESTRUCTIVE_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_DESTRUCTIVE_TEST_DSN not set: these tests break the audit " +
			"chain of whatever database they run against, permanently")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func orgFor(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`SELECT id::text FROM core.organizations LIMIT 1`).Scan(&id); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	return id
}

// TestCheckpointRefusedOnASoundChain is the guard against the obvious abuse.
//
// On an intact chain a checkpoint can only narrow what a later verification
// covers. Somebody reaching for it there has either misunderstood it or is
// shortening the window on purpose.
func TestCheckpointRefusedOnASoundChain(t *testing.T) {
	pool := checkpointPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if broken, _, err := Verify(ctx, tx); err != nil {
		t.Fatal(err)
	} else if broken != 0 {
		t.Skip("this database already has a broken chain; that case is covered " +
			"by TestCheckpointDoesNotHideALaterBreak")
	}

	_, err = DeclareCheckpoint(ctx, tx, orgFor(t, pool), "ops@example.test", "because")
	if err == nil {
		t.Fatal("a checkpoint was accepted on an intact chain, which can only " +
			"shorten what a later export asserts")
	}
	if !strings.Contains(err.Error(), "verifies over all") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestCheckpointNeedsAReasonAndAName(t *testing.T) {
	pool := checkpointPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	org := orgFor(t, pool)
	if _, err := DeclareCheckpoint(ctx, tx, org, "ops@example.test", "   "); err == nil {
		t.Fatal("a checkpoint with no reason was accepted; an unexplained gap in " +
			"an audit log is worse than an explained one")
	}
	if _, err := DeclareCheckpoint(ctx, tx, org, "", "a reason"); err == nil {
		t.Fatal("a checkpoint with nobody's name on it was accepted")
	}
}

// TestCheckpointDoesNotHideALaterBreak is the property that decides whether
// this feature is safe to have at all.
//
// If a checkpoint restored trust in everything after it unconditionally, then
// anybody who deleted an entry could declare one and the export would verify.
// It must cover only what precedes it.
func TestCheckpointDoesNotHideALaterBreak(t *testing.T) {
	pool := checkpointPool(t)
	ctx := context.Background()
	org := orgFor(t, pool)
	marker := fmt.Sprintf("checkpoint-probe-%d", time.Now().UnixNano())

	// A short, sound segment to work with.
	for i := 0; i < 6; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := Write(ctx, tx, Event{Type: marker, OrgID: org,
			Detail: map[string]any{"n": i}}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	var ids []int64
	rows, err := pool.Query(ctx,
		`SELECT id FROM core.audit_events WHERE event_type = $1 ORDER BY id`, marker)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) < 6 {
		t.Fatalf("wrote %d probe entries", len(ids))
	}

	// Verification from the FIRST probe entry is sound.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	broken, checked, err := VerifyFrom(ctx, tx, ids[0])
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("a freshly written segment does not verify: broken at %d after %d",
			broken, checked)
	}

	// Now remove one of them: a deletion after the start point.
	if _, err := pool.Exec(ctx,
		`DELETE FROM core.audit_events WHERE id = $1`, ids[3]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.audit_events WHERE event_type = $1`, marker)
	})

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	broken, _, err = VerifyFrom(ctx, tx, ids[0])
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if broken == 0 {
		t.Fatal("a deleted entry after the start point was NOT detected. A " +
			"checkpoint would then be a way to launder a deletion, which is the " +
			"one thing it must never be.")
	}
	if broken <= ids[3] {
		t.Fatalf("the break was reported at %d; it should be at the successor of "+
			"the deleted row (%d)", broken, ids[3])
	}
}

// TestVerifyFromDoesNotTrustTheStartingEntryBlindly.
//
// Only the LINK from the starting entry to its predecessor is disclaimed. The
// entry's own hash is still checked, so a checkpoint cannot be used to smuggle
// an altered entry in at the boundary.
func TestVerifyFromChecksTheStartingEntryItself(t *testing.T) {
	pool := checkpointPool(t)
	ctx := context.Background()
	org := orgFor(t, pool)
	marker := fmt.Sprintf("checkpoint-boundary-%d", time.Now().UnixNano())

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(ctx, tx, Event{Type: marker, OrgID: org,
		Detail: map[string]any{"original": true}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var id int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM core.audit_events WHERE event_type = $1`, marker).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.audit_events WHERE event_type = $1`, marker)
	})

	// Alter it in place, leaving its stored hash untouched.
	if _, err := pool.Exec(ctx,
		`UPDATE core.audit_events SET detail = '{"original": false}'::jsonb WHERE id = $1`,
		id); err != nil {
		t.Skipf("the audit table refuses updates, which is stronger: %v", err)
	}

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	broken, _, err := VerifyFrom(ctx, tx, id)
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if broken != id {
		t.Fatalf("an altered entry at the checkpoint boundary was accepted "+
			"(broken=%d, want %d). Only its LINK to the past is disclaimed, never "+
			"its contents.", broken, id)
	}
}
