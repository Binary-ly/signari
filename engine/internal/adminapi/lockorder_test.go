package adminapi

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// A CLI write and an unconditional write through this API, at once, both
// commit (4.25). The CLI takes the configuration version's row at its first
// statement (migration 0139's trigger) and the audit chain's lock after; this
// API took the chain lock inside fn and the row at the end, and the two
// deadlocked -- seen as a 500 in the full parallel run.
//
// Staged: the CLI side holds the row, the API write is started, and only then
// does the CLI side audit. Under the old order the API write had the chain
// lock by then and was waiting for the row.
func TestACLIWriteAndAnAPIWriteTogetherBothCommit(t *testing.T) {
	s, pool := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)

	cli, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Rollback(ctx) }()
	if _, err := cli.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', true)`); err != nil {
		t.Fatal(err)
	}
	// Any statement on a core table moves the version under the CLI setting;
	// this one changes no row.
	if _, err := cli.Exec(ctx, `UPDATE core.organizations SET display_name = display_name WHERE false`); err != nil {
		t.Fatal(err)
	}

	ran := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.mutate(ctx, func(tx pgx.Tx) error {
			close(ran)
			return audit.Write(ctx, tx, audit.Event{Type: "admin.webauthn_policy_set", OrgID: org,
				Detail: map[string]any{"test": "lock order"}})
		})
		done <- err
	}()
	select {
	case <-ran:
		// The old order: fn ran while the CLI side held the row.
	case <-time.After(500 * time.Millisecond):
		// Waiting for the row before fn, as it should.
	}

	if err := audit.Write(ctx, cli, audit.Event{Type: "admin.webauthn_policy_set", OrgID: org,
		Detail: map[string]any{"test": "lock order", "via": "cli"}}); err != nil {
		t.Fatalf("the CLI side's audit record: %v", err)
	}
	if err := cli.Commit(ctx); err != nil {
		t.Fatalf("the CLI side's commit: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the API write: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the API write never finished")
	}
}
