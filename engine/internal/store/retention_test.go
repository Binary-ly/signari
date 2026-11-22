package store

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/migrate"
)

// A pass deletes what the retention says nothing reads any more, and keeps
// what something still does (3.17): a live session and a recently ended one,
// a live refresh family and its rotated tokens, whose presentation is how a
// stolen token is caught, each person's newest location, the password hashes
// the reuse check reads. Against a database of its own, so the rows it counts
// are the ones it seeded.
func TestRetentionDeletesOnlyWhatNothingReads(t *testing.T) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("signari_retentiontest_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	u, err := url.Parse(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, tier := range []migrate.Tier{migrate.TierBootstrap, migrate.TierCore} {
		if _, err := migrate.Up(ctx, conn, tier, 0, migrate.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	orgID, userID, clientID, liveSID := fixture(t, conn)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
	}
	session := func(sid, revokedAgo string) {
		exec(`INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after, revoked_at, revocation_reason)
			VALUES ($1, $2::uuid, $3::uuid, now() - interval '90 days', now() - interval '60 days',
			        now() - $4::interval, 'logout')`, sid, orgID, userID, revokedAgo)
	}
	session("ended-long-ago", "40 days")
	session("ended-yesterday", "1 day")
	family := func(sid *string, revokedAgo *string, createdAgo, tokenExpiresIn string) string {
		var id string
		if err := conn.QueryRow(ctx, `
			INSERT INTO core.refresh_token_families (org_id, client_id, user_id, sid, revoked_at, created_at)
			VALUES ($1::uuid, $2, $3::uuid, $4, now() - $5::interval, now() - $6::interval) RETURNING id::text`,
			orgID, clientID, userID, sid, revokedAgo, createdAgo).Scan(&id); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO core.refresh_tokens (token_hash, family_id, scopes, expires_at, consumed_at)
			VALUES (decode(md5(gen_random_uuid()::text), 'hex'), $1::uuid, '{openid}', now() + $2::interval, now())`,
			id, tokenExpiresIn)
		return id
	}
	str := func(s string) *string { return &s }
	liveFamily := family(&liveSID, nil, "60 days", "30 days")
	revokedFamily := family(nil, str("40 days"), "60 days", "-30 days")
	expiredFamily := family(nil, nil, "60 days", "-40 days")
	exec(`INSERT INTO core.outbox (topic, payload, delivered_at) VALUES
		('backchannel_logout', '{"n":1}', now() - interval '10 days'),
		('backchannel_logout', '{"n":2}', now() - interval '1 day'),
		('backchannel_logout', '{"n":3}', NULL)`)
	exec(`INSERT INTO core.auth_locations (user_id, org_id, occurred_at, source, latitude, longitude) VALUES
		($1::uuid, $2::uuid, now() - interval '200 days', 'geoip', 1, 1),
		($1::uuid, $2::uuid, now() - interval '100 days', 'geoip', 2, 2)`, userID, orgID)
	exec(`INSERT INTO core.credential_nonces (nonce_hash, expires_at, created_at) VALUES
		(decode(md5('old'), 'hex'), now() - interval '2 days', now() - interval '3 days'),
		(decode(md5('new'), 'hex'), now() + interval '1 hour', now())`)
	for i := range 4 {
		exec(`INSERT INTO core.password_history (user_id, org_id, hash, algorithm, retired_at)
			VALUES ($1::uuid, $2::uuid, $3, 'argon2id', now() - $4::interval)`,
			userID, orgID, fmt.Sprintf("hash-%d", i), fmt.Sprintf("%d days", 10*(i+1)))
	}

	r := DefaultRetention()
	r.PasswordHistory = 2
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PurgeRetained(ctx, tx, r, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"sessions": 1, "refresh_token_families": 2, "outbox": 1, "auth_locations": 1,
		"credential_nonces": 1, "password_history": 2}
	for table, n := range want {
		if got[table] != n {
			t.Errorf("%s: %d deleted, want %d (all: %v)", table, got[table], n, got)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM core.sessions WHERE sid = ANY($1)`,
		[]string{liveSID, "ended-yesterday"}); n != 2 {
		t.Errorf("%d of the live and the recently ended session are left, want 2", n)
	}
	if n := count(`SELECT count(*) FROM core.refresh_tokens WHERE family_id = $1::uuid`, liveFamily); n != 1 {
		t.Errorf("the live family's rotated token is gone (%d left): a stolen one would no longer be caught", n)
	}
	if n := count(`SELECT count(*) FROM core.refresh_token_families WHERE id = ANY($1::uuid[])`,
		[]string{revokedFamily, expiredFamily}); n != 0 {
		t.Errorf("%d revoked or expired families are left", n)
	}
	if n := count(`SELECT count(*) FROM core.auth_locations WHERE user_id = $1::uuid AND latitude = 2`, userID); n != 1 {
		t.Error("the person's newest location was deleted; the next sign-in has nothing to compare with")
	}
	if n := count(`SELECT count(*) FROM core.password_history WHERE user_id = $1::uuid AND hash IN ('hash-0', 'hash-1')`,
		userID); n != 2 {
		t.Errorf("%d of the two newest password hashes are left, want 2", n)
	}

	again, err := func() (map[string]int, error) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		return PurgeRetained(ctx, tx, r, 1000)
	}()
	if err != nil {
		t.Fatal(err)
	}
	for table, n := range again {
		if n != 0 {
			t.Errorf("a second pass deleted %d more from %s", n, table)
		}
	}
}
