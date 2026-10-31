package directory

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// dueSource is an LDAP source on a closed port, so a sync fails at once, whose next
// sync is overdue, in an organisation of the test's own.
func dueSource(t *testing.T, pool *pgxpool.Pool, dryRun bool) (orgID, sourceID, slug string) {
	t.Helper()
	ctx := context.Background()
	orgID, _ = fixture(t, pool)
	slug = "due-" + rnd(t)
	id, err := AddSource(ctx, pool, attributeRoot(t), orgID, SourceSpec{Kind: "ldap", Slug: slug,
		LDAPURL: "ldaps://127.0.0.1:1", LDAPBaseDN: "dc=x", LDAPFlavour: "openldap", LDAPPassword: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.directory_sources SET dry_run = $2, sync_interval_seconds = 300,
		next_sync_at = now() - interval '1 second' WHERE id = $1::uuid`, id, dryRun); err != nil {
		t.Fatal(err)
	}
	return orgID, id, slug
}

func nextSync(t *testing.T, pool *pgxpool.Pool, id string) time.Time {
	t.Helper()
	var at time.Time
	if err := pool.QueryRow(context.Background(), `SELECT next_sync_at FROM core.directory_sources WHERE id = $1::uuid`,
		id).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// claimOf takes what is due until it finds the test's own: the shared database may
// hold another package's. Anything else taken is left to its own next turn.
func claimOf(t *testing.T, pool *pgxpool.Pool, want string) bool {
	t.Helper()
	for {
		id, _, _, err := claimDue(context.Background(), pool)
		if err != nil {
			t.Error(err) // Not Fatal: a test's goroutines call this.
			return false
		}
		if id == want {
			return true
		}
		if id == "" {
			return false
		}
	}
}

// A failing sync is recorded on the source and in the trail, and waits for its next
// turn rather than being asked again every minute.
func TestAScheduledFailureWaitsForItsTurn(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, id, slug := dueSource(t, pool, false)
	s := &Scheduler{DB: pool, Root: attributeRoot(t), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	before := time.Now()
	s.sync(ctx, id, orgID, slug)
	var lastError string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(last_error, '') FROM core.directory_sources WHERE id = $1::uuid`,
		id).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastError, "127.0.0.1:1") {
		t.Errorf("the source says %q", lastError)
	}
	var recorded string
	if err := pool.QueryRow(ctx, `SELECT detail::text FROM core.audit_events WHERE org_id = $1::uuid
		AND event_type = 'directory.scheduled_sync'`, orgID).Scan(&recorded); err != nil {
		t.Fatalf("no record of it: %v", err)
	}
	if !strings.Contains(recorded, `"applied": false`) || !strings.Contains(recorded, "127.0.0.1:1") {
		t.Errorf("the record reads %s", recorded)
	}
	if !claimOf(t, pool, id) {
		t.Fatal("a due source was not claimed")
	}
	if at := nextSync(t, pool, id); at.Before(before.Add(290 * time.Second)) {
		t.Errorf("the next sync is at %v, not an interval from %v", at, before)
	}
	if claimOf(t, pool, id) {
		t.Error("a source was claimed twice in one interval")
	}
}

// A plan past the ceiling on a run nobody is watching has to say so somewhere.
func TestARefusedSyncIsWrittenOnTheSource(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID, remote, _ := mappedPeople(t, pool)
	src := &loadedSource{id: sourceID, onMissing: "deactivate", maxPct: 20}
	var r SyncReport
	if err := reconcile(ctx, pool, attributeRoot(t), src, orgID, remote[:0], true, &r); !errors.Is(err, ErrSyncRefused) {
		t.Fatalf("a directory that lost everybody answered %v", err)
	}
	var lastError string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(last_error, '') FROM core.directory_sources WHERE id = $1::uuid`,
		sourceID).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastError, "sync refused") {
		t.Errorf("the source says %q", lastError)
	}
}

// Of several nodes one takes a source: the claim is the statement that moves it.
func TestOneNodeTakesASource(t *testing.T) {
	pool := testDB(t)
	_, id, _ := dueSource(t, pool, false)
	var mu sync.Mutex
	taken := 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimOf(t, pool, id) {
				mu.Lock()
				taken++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if taken != 1 {
		t.Errorf("%d nodes took one source", taken)
	}
}

// A schedule cannot do what the source's own settings say not to.
func TestAScheduleLeavesAloneWhatIsNotReady(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	_, dry, _ := dueSource(t, pool, true)
	_, disabled, _ := dueSource(t, pool, false)
	if _, err := pool.Exec(ctx, `UPDATE core.directory_sources SET enabled = false WHERE id = $1::uuid`, disabled); err != nil {
		t.Fatal(err)
	}
	suspendedOrg, suspended, _ := dueSource(t, pool, false)
	if _, err := pool.Exec(ctx, `UPDATE core.organizations SET status = 'suspended' WHERE id = $1::uuid`, suspendedOrg); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{dry, disabled, suspended} {
		if claimOf(t, pool, id) {
			t.Errorf("source %s was claimed", id)
		}
	}
}

// A schedule's first run is an interval away, so setting one applies nothing
// unattended; stopping it takes its next run with it.
func TestSettingAScheduleAppliesNothingAtOnce(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, id, slug := dueSource(t, pool, false)
	hour, zero, few := 3600, 0, 60
	if err := ChangeSource(ctx, pool, orgID, slug, SourceChange{SyncInterval: &few}); err == nil {
		t.Error("a sync every minute was accepted")
	}
	if err := ChangeSource(ctx, pool, orgID, slug, SourceChange{SyncInterval: &hour}); err != nil {
		t.Fatal(err)
	}
	if until := time.Until(nextSync(t, pool, id)); until < 59*time.Minute {
		t.Errorf("the first run is in %v", until)
	}
	enabled := true
	if err := ChangeSource(ctx, pool, orgID, slug, SourceChange{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	if nextSync(t, pool, id).IsZero() {
		t.Error("changing something else stopped the schedule")
	}
	if err := ChangeSource(ctx, pool, orgID, slug, SourceChange{SyncInterval: &zero}); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	if err := pool.QueryRow(ctx, `SELECT next_sync_at IS NULL AND sync_interval_seconds IS NULL
		FROM core.directory_sources WHERE id = $1::uuid`, id).Scan(&cleared); err != nil {
		t.Fatal(err)
	}
	if !cleared {
		t.Error("stopping the schedule left it")
	}
}
