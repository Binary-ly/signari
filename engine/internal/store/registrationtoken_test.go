package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RFC 7591 initial access tokens, ASVS 5.0 V10.4.7.
//
// docs/security-review-asvs.md lists three mitigations for unauthenticated
// dynamic registration — "off unless enabled; initial access tokens; a client
// ceiling" — and nothing in the repository tested any of them. No test
// referenced RedeemRegistrationToken or core.registration_tokens at all.
//
// The one that matters most is the use count. A token issued for one client that
// can be spent four times registers four clients, and dynamic registration is
// the one endpoint where an unauthenticated stranger creates persistent state.

func regPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// The pool must assume the maintenance role, exactly as connect() does for
	// the pgx.Conn tests beside this one.
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// plantRegistrationToken creates an org with a registration policy and a token.
func plantRegistrationToken(t *testing.T, pool *pgxpool.Pool, enabled bool,
	remaining *int, expiresAt *time.Time, revoked bool) (orgID string, raw []byte) {
	t.Helper()
	ctx := context.Background()

	var instanceID string
	suffix := time.Now().UnixNano()
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.instances (issuer, display_name)
		VALUES ($1, 'reg-test') RETURNING id::text`,
		"https://reg-"+itoa(suffix)+".example").Scan(&instanceID); err != nil {
		t.Fatalf("instance: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1::uuid, $2, 'Reg Test') RETURNING id::text`,
		instanceID, "reg-"+itoa(suffix)).Scan(&orgID); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.registration_policies (org_id, enabled) VALUES ($1::uuid, $2)`,
		orgID, enabled); err != nil {
		t.Fatalf("policy: %v", err)
	}

	raw = []byte("registration-token-" + itoa(suffix))
	hash := HashToken(string(raw))
	var revokedAt *time.Time
	if revoked {
		now := time.Now()
		revokedAt = &now
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.registration_tokens (org_id, name, token_hash, remaining, expires_at, revoked_at)
		VALUES ($1::uuid, 'test', $2, $3, $4, $5)`,
		orgID, hash, remaining, expiresAt, revokedAt); err != nil {
		t.Fatalf("token: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM core.registration_tokens WHERE org_id = $1::uuid`, orgID)
		_, _ = pool.Exec(c, `DELETE FROM core.registration_policies WHERE org_id = $1::uuid`, orgID)
	})
	return orgID, raw
}

// A one-use registration token is spent once, including when presented
// concurrently.
//
// # What this test does NOT establish, stated because the name would imply it
//
// It does not prove the redemption is atomic. `RedeemRegistrationToken` takes a
// `SELECT ... FOR UPDATE OF t` row lock and decrements inside the same
// transaction, which is the right shape — but deleting that `FOR UPDATE` leaves
// this test passing. I checked: 6 consecutive runs against the mutant, then 25
// rounds of 16 simultaneous redemptions, and the worst case observed was still
// exactly one winner. On a loopback socket the whole begin-select-update-commit
// costs less than the time to schedule the next goroutine, so the window between
// the read and the decrement never opens.
//
// So the atomicity of this particular function is UNVERIFIED, not verified. The
// window is real in principle — two readers of `remaining = 1` would both pass
// the check and both decrement, leaving -1 and two clients registered from a
// one-use token — and would widen with network latency or a loaded database. It
// simply cannot be provoked here, and a test that cannot fail against the defect
// it names is the thing this session has spent its time removing.
//
// What the test does establish, and what it is kept for: a one-use token is
// spent, an exhausted one is refused, and neither happens by accident.
func TestARegistrationTokenIsSpentOnce(t *testing.T) {
	pool := regPool(t)
	one := 1
	_, raw := plantRegistrationToken(t, pool, true, &one, nil, false)
	hash := HashToken(string(raw))

	const racers = 8
	var wg sync.WaitGroup
	ok := make([]bool, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, err := RedeemRegistrationToken(context.Background(), pool, hash)
			ok[i] = err == nil
		}(i)
	}
	close(start)
	wg.Wait()

	won := 0
	for _, v := range ok {
		if v {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d of %d redemptions of a one-use registration token succeeded; "+
			"exactly one may, or a token issued for one client registers several",
			won, racers)
	}

	// And the token is now spent.
	if _, _, err := RedeemRegistrationToken(context.Background(), pool, hash); !errors.Is(err, ErrRegistrationClosed) {
		t.Errorf("an exhausted token was not refused: %v", err)
	}
}

// The other two mitigations V10.4.7 claims, and the two lifecycle rules.
func TestRegistrationTokensRespectPolicyAndLifecycle(t *testing.T) {
	pool := regPool(t)
	ctx := context.Background()
	one := 1
	past := time.Now().Add(-time.Hour)

	for name, plant := range map[string]func() []byte{
		// "off unless enabled": the policy gates the token, not the other way
		// round. registration_policies.enabled defaults to false.
		"the organisation has registration disabled": func() []byte {
			_, raw := plantRegistrationToken(t, pool, false, &one, nil, false)
			return raw
		},
		"the token is revoked": func() []byte {
			_, raw := plantRegistrationToken(t, pool, true, &one, nil, true)
			return raw
		},
		"the token has expired": func() []byte {
			_, raw := plantRegistrationToken(t, pool, true, &one, &past, false)
			return raw
		},
	} {
		raw := plant()
		if _, _, err := RedeemRegistrationToken(ctx, pool, HashToken(string(raw))); err == nil {
			t.Errorf("%s: the token was still redeemed", name)
		}
	}

	// The positive case, so the negatives cannot pass by refusing everything.
	_, raw := plantRegistrationToken(t, pool, true, &one, nil, false)
	if _, _, err := RedeemRegistrationToken(ctx, pool, HashToken(string(raw))); err != nil {
		t.Fatalf("a live token against an enabled policy was refused: %v", err)
	}
}
