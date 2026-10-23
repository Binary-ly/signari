package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A connection limited to a group admits members of its own organisation's
// group of that name (0.40): a membership row naming another organisation's
// group of the same name must not open it.
func TestARACGroupIsTheConnectionsOrganisations(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	n := time.Now().UnixNano()
	var instance, own, other, user string
	if err := pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name) VALUES ($1, 'probe')
		RETURNING id::text`, fmt.Sprintf("https://racgroup-%d.invalid", n)).Scan(&instance); err != nil {
		t.Fatal(err)
	}
	for i, org := range []*string{&own, &other} {
		if err := pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
			VALUES ($1::uuid, $2, 'probe') RETURNING id::text`, instance, fmt.Sprintf("racgroup-%d-%d", n, i)).
			Scan(org); err != nil {
			t.Fatal(err)
		}
	}
	// Users first: users.org_id does not cascade.
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM core.users WHERE org_id IN ($1::uuid, $2::uuid)`, own, other)
		_, _ = pool.Exec(ctx, `DELETE FROM core.organizations WHERE id IN ($1::uuid, $2::uuid)`, own, other)
		_, _ = pool.Exec(ctx, `DELETE FROM core.instances WHERE id = $1::uuid`, instance)
	})
	if err := pool.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email) VALUES ($1::uuid,
		sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2) RETURNING id::text`,
		own, fmt.Sprintf("racgroup-%d@example.test", n)).Scan(&user); err != nil {
		t.Fatal(err)
	}
	member := func(org string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `WITH g AS (INSERT INTO core.groups (org_id, name, display_name)
			VALUES ($1::uuid, 'ops', 'ops') RETURNING id, org_id)
			INSERT INTO core.group_members (group_id, user_id, org_id) SELECT id, $2::uuid, org_id FROM g`,
			org, user); err != nil {
			t.Fatal(err)
		}
	}
	conn := &RACConnection{OrgID: own, Slug: "bastion", RequireGroup: "ops"}

	member(other)
	if ok, err := MayUse(ctx, pool, conn, user); err != nil || ok {
		t.Errorf("a membership of another organisation's ops let them in: %v, %v", ok, err)
	}
	member(own)
	if ok, err := MayUse(ctx, pool, conn, user); err != nil || !ok {
		t.Errorf("a member of the connection's own ops was refused: %v, %v", ok, err)
	}
}
