package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Two writers each adding one half of a collision cannot both pass (2.59): the
// second waits for the first and then reads its row. Nothing else stands
// between them, since neither sees the other's uncommitted row.
func TestTwoWritersCannotEachAddHalfACollision(t *testing.T) {
	first, second := connect(t), connect(t)
	ctx := context.Background()
	stamp := fmt.Sprint(time.Now().UnixNano())
	var org string
	must(t, first.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name) VALUES ($1, 'test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, $2, 'Test' FROM i RETURNING id::text`,
		"https://lock-"+stamp+".example", "lock"+stamp).Scan(&org))
	t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{`DELETE FROM core.users WHERE org_id = $1::uuid`,
			`DELETE FROM core.organizations WHERE id = $1::uuid`} {
			if _, err := first.Exec(ctx, q, org); err != nil {
				t.Errorf("removing what the test made: %v", err)
			}
		}
	})

	shared := "shared" + stamp + "@example.test"
	tx, err := first.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO core.users (org_id, user_handle, username)
		VALUES ($1::uuid, sha256(convert_to($2, 'UTF8')), $2)`, org, shared)
	must(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := second.Exec(ctx, `
			INSERT INTO core.users (org_id, user_handle, email)
			VALUES ($1::uuid, sha256(convert_to($2 || 'other', 'UTF8')), $2)`, org, shared)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the second writer did not wait for the first: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	must(t, tx.Commit(ctx))
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "users_identifier_cross_field") {
			t.Errorf("the second half of a collision answered %v, want it refused", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second writer never finished")
	}
}

// One transaction holds one lock however many people it writes (7.16). It held
// one for each identifier until it committed, and PostgreSQL's lock table
// holds about 6,400 at its defaults, so a first sync of a large directory
// failed with `out of shared memory` around the twelve-thousandth person. So
// would an import.
func TestAWriteHoldsOneLockHoweverManyPeople(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	var org string
	must(t, tx.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name) VALUES ($1, 'test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, $2, 'Test' FROM i RETURNING id::text`,
		"https://locks-"+stamp+".example", "locks"+stamp).Scan(&org))
	_, err = tx.Exec(ctx, `
		INSERT INTO core.users (org_id, user_handle, email, username)
		SELECT $1::uuid, sha256(convert_to(i::text, 'UTF8')), 'p' || i || '@example.test', 'name' || i
		FROM generate_series(1, 500) i`, org)
	must(t, err)
	var held int
	must(t, tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()`).Scan(&held))
	if held != 1 {
		t.Errorf("writing 500 people holds %d advisory locks, want 1", held)
	}
}
