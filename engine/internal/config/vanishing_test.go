package config

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// vanishing is a transaction in which a client is deleted just before the nth
// single-row read, as somebody else's commit lands between two statements of a
// plan at READ COMMITTED.
type vanishing struct {
	pgx.Tx
	client string
	at     int
	reads  int
}

func (v *vanishing) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	v.reads++
	if v.reads == v.at {
		if _, err := v.Tx.Exec(ctx, `DELETE FROM core.clients WHERE client_id = $1`, v.client); err != nil {
			panic(err)
		}
	}
	return v.Tx.QueryRow(ctx, sql, args...)
}

// A plan reads the clients in a list and then each in turn. Somebody deleting one
// in between failed the plan of everything else with "no such client", which a
// shared test database turned up twice as a failure in an unrelated test.
func TestAClientDeletedDuringAPlanIsNotThereToCompare(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	for _, at := range []int{1, 2} {
		t.Run(fmt.Sprintf("before read %d", at), func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			// An organisation of its own, so the only client is this one and the
			// reads counted are its reads.
			var own string
			if err := tx.QueryRow(ctx, `
				INSERT INTO core.organizations (instance_id, slug, display_name)
				SELECT instance_id, 'vanish-' || substr(gen_random_uuid()::text, 1, 8), 'V'
				  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, org).Scan(&own); err != nil {
				t.Fatal(err)
			}
			id := fmt.Sprintf("cfg-vanish-%d-%d", at, time.Now().UnixNano())
			if _, err := tx.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash)
				VALUES ($1, $2::uuid, 'V', 'confidential', 'x')`, id, own); err != nil {
				t.Fatal(err)
			}
			got, err := read(ctx, &vanishing{Tx: tx, client: id, at: at}, own)
			if err != nil {
				t.Fatalf("a client deleted during the read failed it: %v", err)
			}
			if _, there := got.clients[id]; there {
				t.Error("a client that is gone was kept in the state compared against")
			}
		})
	}
}
