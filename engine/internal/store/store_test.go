package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sulimanbenhalim/idp/engine/internal/oauth"
)

// These tests need a real PostgreSQL with the core schema applied. The
// guarantees under test -- atomic single-use, snapshot-before-destroy -- are
// properties of the database, so a fake would test nothing.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("IDP_TEST_DSN")
	if dsn == "" {
		t.Skip("IDP_TEST_DSN not set; skipping database-backed tests")
	}
	return dsn
}

func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, "SET ROLE idp_maintenance"); err != nil {
		t.Fatalf("assuming idp_maintenance: %v", err)
	}
	return conn
}

// fixture creates an instance, org, user, client and session to hang tests off.
func fixture(t *testing.T, conn *pgx.Conn) (orgID, userID, clientID, sid string) {
	t.Helper()
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	var instanceID string
	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.instances (issuer, display_name)
		VALUES ($1, 'test') RETURNING id::text`,
		"https://test-"+itoa(suffix)+".example").Scan(&instanceID))

	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1, $2, 'Test') RETURNING id::text`,
		instanceID, "org"+itoa(suffix)).Scan(&orgID))

	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1, sha256($2::bytea) || sha256($3::bytea), $4) RETURNING id::text`,
		orgID, itoa(suffix), itoa(suffix+1), "u"+itoa(suffix)+"@test").Scan(&userID))

	clientID = "client-" + itoa(suffix)
	_, err := conn.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, backchannel_logout_uri)
		VALUES ($1, $2, 'App', 'confidential', 'x', 'https://app.test/logout')`,
		clientID, orgID)
	must(t, err)

	sid = "sess-" + itoa(suffix)
	_, err = conn.Exec(ctx, `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ($1, $2, $3, now(), now() + interval '1 hour')`, sid, orgID, userID)
	must(t, err)

	_, err = conn.Exec(ctx,
		`INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)`, sid, clientID)
	must(t, err)

	return orgID, userID, clientID, sid
}

// The single-use guarantee is in the WHERE clause, so it must hold under genuine
// concurrency. A read-then-write in Go would let both racers mint tokens.
func TestConsumeCodeIsAtomicUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, clientID, sid := fixture(t, conn)

	code, hash, err := NewCode()
	must(t, err)
	if code == "" {
		t.Fatal("empty code")
	}

	tx, err := conn.Begin(ctx)
	must(t, err)
	must(t, IssueCode(ctx, tx, orgID, clientID, sid, userID, oauth.GrantRecord{
		RedirectURI:         "https://app.test/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       oauth.Challenge("v"),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}, hash, nil))
	must(t, tx.Commit(ctx))

	const racers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		wins     int
		reuseErr int
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := pgx.Connect(ctx, testDSN(t))
			if err != nil {
				return
			}
			defer func() { _ = c.Close(ctx) }()
			_, _ = c.Exec(ctx, "SET ROLE idp_maintenance")

			tx, err := c.Begin(ctx)
			if err != nil {
				return
			}
			got, err := ConsumeCode(ctx, tx, hash)
			if err == nil && got != nil {
				_ = tx.Commit(ctx)
				mu.Lock()
				wins++
				mu.Unlock()
				return
			}
			_ = tx.Commit(ctx)
			if errors.Is(err, ErrCodeReused) {
				mu.Lock()
				reuseErr++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d concurrent redemptions succeeded; exactly 1 must win", wins)
	}
	if reuseErr == 0 {
		t.Error("no racer reported reuse; the losers must be distinguishable from unknown codes")
	}
}

func TestConsumeCodeDistinguishesUnknownFromReused(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = ConsumeCode(ctx, tx, HashToken("never-issued"))
	if !errors.Is(err, ErrCodeUnknown) {
		t.Fatalf("err = %v, want ErrCodeUnknown", err)
	}
}

// Snapshot before destroy: the outbox rows must exist and the sessions must be
// revoked, both from the same transaction.
func TestTerminateQueuesNoticesBeforeRevoking(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	_, userID, _, sid := fixture(t, conn)

	tx, err := conn.Begin(ctx)
	must(t, err)

	res, err := TerminateSessions(ctx, tx, sid, "", ReasonLogout)
	must(t, err)
	if res.Sessions != 1 {
		t.Errorf("revoked %d sessions, want 1", res.Sessions)
	}
	if res.Notices != 1 {
		t.Errorf("queued %d notices, want 1", res.Notices)
	}

	var revoked bool
	must(t, tx.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM core.sessions WHERE sid=$1`, sid).Scan(&revoked))
	if !revoked {
		t.Error("session not revoked")
	}

	// A single-session termination addresses the RP by sid, never by sub.
	n := lastNotice(t, ctx, tx)
	if n.SessionID != sid {
		t.Errorf("notice sid = %q, want %q", n.SessionID, sid)
	}
	if n.Subject != "" {
		t.Errorf("single-session logout must not carry sub, got %q", n.Subject)
	}

	must(t, tx.Commit(ctx))

	// Re-terminating must be a no-op, or an expiry sweep would replay logout
	// storms against every relying party.
	tx2, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx2.Rollback(ctx) }()
	res2, err := TerminateSessions(ctx, tx2, sid, "", ReasonLogout)
	must(t, err)
	if res2.Sessions != 0 || res2.Notices != 0 {
		t.Errorf("re-terminating a revoked session did work: %+v", res2)
	}
	_ = userID
}

func TestTerminateAllSessionsUsesSubNotSid(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	_, userID, _, _ := fixture(t, conn)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = TerminateSessions(ctx, tx, "", userID, ReasonUserDeactivated)
	must(t, err)

	n := lastNotice(t, ctx, tx)
	if n.Subject != userID {
		t.Errorf("notice sub = %q, want %q", n.Subject, userID)
	}
	if n.SessionID != "" {
		t.Errorf("all-sessions logout must not carry sid, got %q", n.SessionID)
	}
}

func TestTerminateNeedsExactlyOneSelector(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := TerminateSessions(ctx, tx, "", "", ReasonLogout); err == nil {
		t.Error("accepted neither sid nor userID")
	}
	if _, err := TerminateSessions(ctx, tx, "s", "u", ReasonLogout); err == nil {
		t.Error("accepted both sid and userID")
	}
}

func TestDeactivatedUserHasNoLiveSession(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	_, userID, _, sid := fixture(t, conn)

	live, err := IsSessionLive(ctx, conn, sid)
	must(t, err)
	if !live {
		t.Fatal("fresh session is not live")
	}

	_, err = conn.Exec(ctx, `UPDATE core.users SET status='deactivated' WHERE id=$1`, userID)
	must(t, err)

	live, err = IsSessionLive(ctx, conn, sid)
	must(t, err)
	if live {
		t.Fatal("session of a deactivated user still reports live")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// lastNotice reads the most recently queued back-channel logout notice.
func lastNotice(t *testing.T, ctx context.Context, tx pgx.Tx) LogoutNotice {
	t.Helper()
	var raw []byte
	must(t, tx.QueryRow(ctx, `
		SELECT payload FROM core.outbox
		WHERE topic='backchannel_logout' ORDER BY id DESC LIMIT 1`).Scan(&raw))
	var n LogoutNotice
	must(t, json.Unmarshal(raw, &n))
	return n
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
