package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/tokens"
)

// Every way a token can end, each read in the one statement, and each reported as
// itself: the callers say different things for each, and a resource server relies
// on the difference being true. Rolled back, so nothing stays behind.
func TestEachWayATokenEndsIsToldApart(t *testing.T) {
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
	defer tx.Rollback(ctx)

	var orgID, userID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://standing-probe.invalid', 'probe') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'standing-probe', 'probe' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, user_handle, email)
		SELECT o.id, sha256(convert_to(gen_random_uuid()::text, 'UTF8'))
		             || sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'standing@probe.invalid'
		  FROM o RETURNING org_id::text, id::text`).Scan(&orgID, &userID); err != nil {
		t.Fatal(err)
	}
	const client = "standing-app"
	if _, err := tx.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type)
		VALUES ($1, $2::uuid, 'probe', 'public')`, client, orgID); err != nil {
		t.Fatal(err)
	}
	session := func(sid, until string) string {
		t.Helper()
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
			VALUES ($1, decode(md5($1), 'hex'), $2::uuid, $3::uuid, '1', ARRAY['pwd'], now(), now() + $4::interval)`,
			sid, orgID, userID, until); err != nil {
			t.Fatal(err)
		}
		return sid
	}
	family := func(sid, revokedAgo, offline string) string {
		t.Helper()
		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO core.refresh_token_families (org_id, client_id, user_id, sid, revoked_at, offline_not_after)
			VALUES ($1::uuid, $2, $3::uuid, $4,
			        CASE WHEN $5 = '' THEN NULL ELSE now() - $5::interval END,
			        CASE WHEN $6 = '' THEN NULL ELSE now() + $6::interval END)
			RETURNING id::text`, orgID, client, userID, sid, revokedAgo, offline).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	live := session("standing-live", "1 hour")
	ended := session("standing-ended", "-1 hour")
	offlineSid := session("standing-offline", "-1 hour")
	if _, err := tx.Exec(ctx, `INSERT INTO core.revoked_jtis (jti, client_id, expires_at)
		VALUES ('standing-revoked', $1, now() + interval '1 hour')`, client); err != nil {
		t.Fatal(err)
	}
	gone := "6f1c9a52-0d3b-4c8e-9a71-2b5e8d4f0c14"

	for _, c := range []struct {
		name string
		jti  string
		gid  string
		sid  string
		want TokenStanding
	}{
		{"a token with nothing against it", "standing-jti", "", live, TokenStanding{}},
		{"a token with a live grant", "standing-jti", family(live, "", ""), live, TokenStanding{}},
		{"a token with no session or grant", "standing-jti", "", "", TokenStanding{}},
		{"its grant revoked", "standing-jti", family(live, "1 minute", ""), live, TokenStanding{GrantRevoked: true}},
		{"its grant gone", "standing-jti", gone, live, TokenStanding{GrantRevoked: true}},
		{"its jti revoked", "standing-revoked", "", live, TokenStanding{JTIRevoked: true}},
		{"its session over", "standing-jti", "", ended, TokenStanding{SessionEnded: true}},
		{"its session gone", "standing-jti", "", "standing-never", TokenStanding{SessionEnded: true}},
		{"its session over, an offline grant keeping it", "standing-jti", family(offlineSid, "", "1 hour"), offlineSid, TokenStanding{}},
		{"its session over, an offline grant ended", "standing-jti", family(offlineSid, "", "-1 hour"), offlineSid, TokenStanding{SessionEnded: true}},
	} {
		got, err := TokenStandingOf(ctx, tx, &tokens.AccessTokenClaims{JTI: c.jti, GrantID: c.gid, SessionID: c.sid,
			ClientID: client, Subject: userID})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: %+v, wanting %+v", c.name, got, c.want)
		}
		if got.Live() != (c.want == TokenStanding{}) {
			t.Errorf("%s: live %v", c.name, got.Live())
		}
	}
}

// When nobody can tell, the answer is no: a database that will not answer must
// not become a window in which revoked tokens work.
func TestATokenNobodyCanVouchForHasEnded(t *testing.T) {
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
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	got, err := TokenStandingOf(cancelled, conn, &tokens.AccessTokenClaims{JTI: "x", ClientID: "c", Subject: "s"})
	if err == nil || got.Live() {
		t.Errorf("with the database gone: %+v, %v", got, err)
	}
	got, err = TokenStandingOf(ctx, conn, &tokens.AccessTokenClaims{ClientID: "c", Subject: "s"})
	if err == nil || got.Live() {
		t.Errorf("a token with no jti: %+v, %v", got, err)
	}
	if got, err := TokenStandingOf(ctx, conn, &tokens.AccessTokenClaims{JTI: "x", GrantID: "not-a-uuid", ClientID: "c", Subject: "s"}); err == nil || got.Live() {
		t.Errorf("a grant that is no uuid: %+v, %v", got, err)
	}
}

// Two counters read together come back in the order asked for, a counter nothing
// has touched reads nought, and a window out of range is refused.
func TestCountersAreReadInTheOrderAsked(t *testing.T) {
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
	defer tx.Rollback(ctx)
	first, second := "count-order-a-"+t.Name(), "count-order-b-"+t.Name()
	for range 2 {
		if _, err := AllowRate(ctx, tx, first, 100, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := AllowRate(ctx, tx, second, 100, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := CountRates(ctx, tx, RateWindow{second, time.Hour}, RateWindow{"count-order-none", time.Minute}, RateWindow{first, time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 0 || got[2] != 2 {
		t.Errorf("the counters read %v", got)
	}
	if _, err := CountRates(ctx, tx, RateWindow{first, 0}); err == nil {
		t.Error("a window of nothing was read")
	}
}
