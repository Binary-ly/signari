package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store/storetest"
)

// What `kerberos sync` does with the people a realm lists (8.11), from a list as kadmin
// would give it: each one nobody here holds is created pending, with no password; a dry
// run changes nothing; and somebody already here is left alone unless -adopt-existing,
// which marks pending only a person with no password here and a migration never begun.
// A local password is never sent to the realm, and a finished migration stays finished.
func TestARealmsPeopleAreCreatedAndAdoptedOnlyAsAsked(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var org string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://krb-sync-' || gen_random_uuid() || '.test', 'Kerberos sync test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'k' || substr(gen_random_uuid()::text, 1, 8), 'Kerberos' FROM i RETURNING id::text`).
		Scan(&org); err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, db, org)

	realm := "SYNC" + strings.ToUpper(strconv.FormatInt(time.Now().UnixNano(), 36)) + ".TEST"
	address := func(name string) string { return name + "@" + strings.ToLower(realm) }
	person := func(name, migration string) string {
		t.Helper()
		var id string
		if err := db.QueryRow(ctx, `
			INSERT INTO core.users (org_id, user_handle, email, migration_state)
			VALUES ($1::uuid, decode(repeat(md5(random()::text), 4), 'hex'), $2, $3)
			RETURNING id::text`, org, address(name), migration).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	person("bare", "none")
	withPassword := person("local", "none")
	if _, err := db.Exec(ctx, `INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, 'not-a-real-hash', 'argon2id')`, withPassword, org); err != nil {
		t.Fatal(err)
	}
	person("finished", "complete")

	state := func(name string) string {
		t.Helper()
		var s string
		err := db.QueryRow(ctx, `SELECT migration_state FROM core.users
			WHERE org_id = $1::uuid AND email_fold = lower($2)`, org, address(name)).Scan(&s)
		if err != nil {
			return "absent"
		}
		return s
	}
	expect := func(when string, want map[string]string) {
		t.Helper()
		for name, w := range want {
			if got := state(name); got != w {
				t.Errorf("%s, %s is %s, want %s", when, name, got, w)
			}
		}
	}
	names := []string{"bare", "local", "finished", "newcomer"}

	if err := syncRealmPeople(ctx, db, org, realm, names, false, true); err != nil {
		t.Fatal(err)
	}
	expect("after a dry run", map[string]string{"bare": "none", "local": "none", "finished": "complete", "newcomer": "absent"})

	if err := syncRealmPeople(ctx, db, org, realm, names, true, false); err != nil {
		t.Fatal(err)
	}
	expect("applied without adopting", map[string]string{"bare": "none", "local": "none", "finished": "complete", "newcomer": "pending"})
	var passwords int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM core.password_credentials pc JOIN core.users u ON u.id = pc.user_id
		WHERE u.org_id = $1::uuid AND u.email_fold = lower($2)`, org, address("newcomer")).Scan(&passwords); err != nil {
		t.Fatal(err)
	}
	if passwords != 0 {
		t.Errorf("the newcomer was given %d local password(s); the realm is how they sign in", passwords)
	}

	if err := syncRealmPeople(ctx, db, org, realm, names, true, true); err != nil {
		t.Fatal(err)
	}
	expect("applied adopting", map[string]string{"bare": "pending", "local": "none", "finished": "complete", "newcomer": "pending"})
}
