package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A stream is registered only for a client of its own organisation (0.35).
// Events go to a stream by its client, so one registered under organisation A
// for organisation B's client sent B's people's session events to a receiver
// A chose; `ssf add-stream` checked neither, and stored A's org_id beside B's
// client.
func TestAStreamIsRegisteredOnlyForAClientOfItsOrganisation(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	orgs := make([]string, 2)
	for i := range orgs {
		must(t, conn.QueryRow(ctx, `
			INSERT INTO core.organizations (instance_id, slug, display_name)
			VALUES ((SELECT id FROM core.instances ORDER BY created_at LIMIT 1),
			        'ssf-' || substr(md5(random()::text),1,8), 'Streams')
			RETURNING id::text`).Scan(&orgs[i]))
		org := orgs[i]
		t.Cleanup(func() {
			_, _ = conn.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, org)
		})
	}
	theirs := fmt.Sprintf("ssf-theirs-%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		client_secret_hash, enabled) VALUES ($1, $2::uuid, 'theirs', 'confidential', 'x', true)`, theirs, orgs[1]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, theirs)
	})

	spec := StreamSpec{ClientID: theirs, Endpoint: "https://receiver.example.test/events"}
	if _, err := AddStream(ctx, conn, nil, orgs[0], spec); !errors.Is(err, ErrStreamClientElsewhere) {
		t.Errorf("a stream for another organisation's client answered %v", err)
	}
	var n int
	must(t, conn.QueryRow(ctx, `SELECT count(*) FROM core.ssf_streams WHERE client_id = $1`, theirs).Scan(&n))
	if n != 0 {
		t.Fatalf("the refused stream was stored")
	}
	if _, err := AddStream(ctx, conn, nil, orgs[1], spec); err != nil {
		t.Fatalf("a stream in the client's own organisation: %v", err)
	}
	if _, err := AddStream(ctx, conn, nil, orgs[1], spec); !errors.Is(err, ErrStreamExists) {
		t.Errorf("a second stream for the client answered %v", err)
	}
}
