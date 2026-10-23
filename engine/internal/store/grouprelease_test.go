package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A group release is set for the organisation's own client, of groups it has
// (0.42). The row is keyed by client id alone, so `signari group release -org
// A -client-id <B's client>` wrote B's client's release under A's id, and a
// misspelled group was stored and released nothing.
func TestAGroupReleaseIsTheOrganisationsOwnClientsAndGroups(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n := time.Now().UnixNano()
	var instance, own, other string
	if err := tx.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name) VALUES ($1, 'probe')
		RETURNING id::text`, fmt.Sprintf("https://release-%d.invalid", n)).Scan(&instance); err != nil {
		t.Fatal(err)
	}
	for i, org := range []*string{&own, &other} {
		if err := tx.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
			VALUES ($1::uuid, $2, 'probe') RETURNING id::text`, instance, fmt.Sprintf("release-%d-%d", n, i)).
			Scan(org); err != nil {
			t.Fatal(err)
		}
	}
	client := fmt.Sprintf("theirs-%d", n)
	if _, err := tx.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		client_secret_hash, grant_types, scopes) VALUES ($1, $2::uuid, 'T', 'public', '', '{authorization_code}',
		'{openid}')`, client, other); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, 'staff', 'staff')`,
		other); err != nil {
		t.Fatal(err)
	}

	if err := ReleaseGroupsToClient(ctx, tx, own, client, nil); !errors.Is(err, ErrReleaseClientUnknown) {
		t.Errorf("another organisation's client was given a release: %v", err)
	}
	if _, released, err := GroupReleaseOf(ctx, tx, client); err != nil || released {
		t.Errorf("the other organisation's client is released to (%v)", err)
	}
	if err := ReleaseGroupsToClient(ctx, tx, other, client, []string{"stafff"}); !errors.Is(err, ErrReleaseGroupUnknown) {
		t.Errorf("a misspelled group was released: %v", err)
	}
	if err := ReleaseGroupsToClient(ctx, tx, other, client, []string{"staff"}); err != nil {
		t.Errorf("the client's own release of its own group: %v", err)
	}
}
