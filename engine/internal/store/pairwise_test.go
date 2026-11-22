package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// pairwiseFixture is a client and a person in an organisation of their own, in a
// transaction that is rolled back: visible to this connection, residue for nobody.
func pairwiseFixture(t *testing.T) (context.Context, pgx.Tx, string, string, string) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE signari_maintenance`); err != nil {
		t.Fatal(err)
	}
	var org, user string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://pw-' || gen_random_uuid() || '.test', 'P') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'p' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, email, user_handle)
		SELECT id, 'p'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		       sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea)
		FROM o RETURNING org_id::text, id::text`).Scan(&org, &user); err != nil {
		t.Fatal(err)
	}
	const client = "pairwise-client"
	if _, err := tx.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash)
		VALUES ($1, $2::uuid, 'P', 'public', '')`, client, org); err != nil {
		t.Fatal(err)
	}
	return ctx, tx, org, user, client
}

// Where a sector comes from: named, kept, or the one host of the redirect URIs, never
// guessed from several or from an address that says nothing of whose the client is.
func TestASectorIsNamedKeptOrTheOneHost(t *testing.T) {
	ctx, tx, _, _, client := pairwiseFixture(t)
	pairwise, public, none := "pairwise", "public", ""
	redirects := func(uris ...string) {
		t.Helper()
		if err := func() error {
			if _, err := tx.Exec(ctx, `DELETE FROM core.client_redirect_uris WHERE client_id = $1`, client); err != nil {
				return err
			}
			for _, uri := range uris {
				if _, err := tx.Exec(ctx, `INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
					VALUES ($1, $2)`, client, uri); err != nil {
					return err
				}
			}
			return nil
		}(); err != nil {
			t.Fatal(err)
		}
	}
	sector := func() string {
		t.Helper()
		v, err := ClientSettingsOf(ctx, tx, client)
		if err != nil {
			t.Fatal(err)
		}
		return v.Sector
	}
	// A refusal aborts nothing here: each is decided before anything is written.
	refused := func(name string) {
		t.Helper()
		if err := SetClientSettings(ctx, tx, client, ClientSettings{SubjectType: &pairwise}); !errors.Is(err, ErrInvalidClientSetting) {
			t.Errorf("%s: %v", name, err)
		}
	}

	redirects()
	refused("no redirect URI")
	redirects("https://a.example/cb", "https://b.example/cb")
	refused("two hosts")
	for _, uri := range []string{"http://127.0.0.1:8000/cb", "http://localhost/cb", "http://[::1]/cb", "com.example.app:/cb"} {
		redirects(uri)
		refused(uri)
	}

	redirects("https://App.Example/cb", "https://app.example:8443/other")
	if err := SetClientSettings(ctx, tx, client, ClientSettings{SubjectType: &pairwise, Sector: &none}); err != nil {
		t.Fatal(err)
	}
	if got := sector(); got != "app.example" {
		t.Errorf("one host gave the sector %q", got)
	}

	// Stored, so moving a redirect URI renames nobody, and going back keeps it.
	redirects("https://moved.example/cb")
	if err := SetClientSettings(ctx, tx, client, ClientSettings{SubjectType: &pairwise}); err != nil {
		t.Fatal(err)
	}
	if err := SetClientSettings(ctx, tx, client, ClientSettings{SubjectType: &public}); err != nil {
		t.Fatal(err)
	}
	if err := SetClientSettings(ctx, tx, client, ClientSettings{SubjectType: &pairwise}); err != nil {
		t.Fatal(err)
	}
	if got := sector(); got != "app.example" {
		t.Errorf("after moving a redirect URI the sector is %q", got)
	}

	named := "Shared.Example"
	if err := SetClientSettings(ctx, tx, client, ClientSettings{Sector: &named}); err != nil {
		t.Fatal(err)
	}
	if got := sector(); got != "shared.example" {
		t.Errorf("a named sector is %q", got)
	}
	for _, bad := range []string{"https://shared.example", "a b", "-x", strings.Repeat("a", 254)} {
		bad := bad
		if err := CheckClientSettings(ClientSettings{Sector: &bad}); !errors.Is(err, ErrInvalidClientSetting) {
			t.Errorf("the sector %q: %v", bad, err)
		}
	}
	other := "other"
	if err := CheckClientSettings(ClientSettings{SubjectType: &other}); !errors.Is(err, ErrInvalidClientSetting) {
		t.Errorf("a subject type of %q: %v", other, err)
	}
}

// A pairwise subject is the sector's, reads back to its person, and goes with them. What
// stood for nobody is an error and never passed on as if it were a client's own subject.
func TestAPairwiseSubjectBelongsToASectorAndReadsBack(t *testing.T) {
	ctx, tx, org, user, client := pairwiseFixture(t)

	sub, err := PairwiseSubject(ctx, tx, org, "one.example", user)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sub, PairwisePrefix) || strings.Contains(sub, user) {
		t.Fatalf("the subject is %q", sub)
	}
	again, err := PairwiseSubject(ctx, tx, org, "one.example", user)
	if err != nil || again != sub {
		t.Errorf("asked again: %q, %v", again, err)
	}
	other, err := PairwiseSubject(ctx, tx, org, "two.example", user)
	if err != nil || other == sub {
		t.Errorf("another sector: %q, %v", other, err)
	}

	// A client's own subject, even one shaped like a person's id, is left alone.
	const clientShaped = "11111111-1111-4111-8111-111111111111"
	if got, err := PairwiseSubject(ctx, tx, org, "one.example", clientShaped); err != nil || got != clientShaped {
		t.Errorf("a client id shaped like a person's: %q, %v", got, err)
	}
	if got, err := PairwiseSubject(ctx, tx, org, "one.example", client); err != nil || got != client {
		t.Errorf("a client id: %q, %v", got, err)
	}

	if got, err := PersonNamedBy(ctx, tx, client, sub); err != nil || got != user {
		t.Errorf("reading it back: %q, %v", got, err)
	}
	if got, err := PersonNamedBy(ctx, tx, client, user); err != nil || got != user {
		t.Errorf("a person's id: %q, %v", got, err)
	}
	if got, err := PersonNamedBy(ctx, tx, PairwisePrefix+"client", PairwisePrefix+"client"); err != nil ||
		got != PairwisePrefix+"client" {
		t.Errorf("a client named like one, for its own token: %q, %v", got, err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, user); err != nil {
		t.Fatal(err)
	}
	if _, err := PersonNamedBy(ctx, tx, client, sub); !errors.Is(err, ErrNoPairwiseSubject) {
		t.Errorf("after the person went: %v", err)
	}
	var left int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.pairwise_subjects WHERE org_id = $1::uuid`, org).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d subjects outlived their person", left)
	}
}
