package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// The LDAP port must not be a quieter way to guess a password than the form.
//
// # What was actually wrong
//
// `LDAPAuthenticator`'s doc comment promised a bind was "throttled, audited and
// subject to the same lockout as any other authentication". The audit half was
// found missing once and fixed. The throttle half was still false: nothing on
// the bind path consulted a limiter of any kind, so `/login` capped guessing at
// thirty failures per quarter hour per account while port 389, three metres
// away in the same binary, would answer an unbounded number.
//
// An attacker does not have to pick the hard door. A control that exists on one
// of two entrances to the same credential is not a control, and the comment
// asserting otherwise is worse than no comment, because it answers the question
// somebody would otherwise go and check.
//
// # What these tests hold
//
// Two properties, and the second is the one that is easy to get wrong:
//
//  1. A metered bind is refused once the budget is spent.
//  2. It is the SAME budget as the sign-in form's. An `ldap:` namespace of its
//     own would have been the natural implementation and would have doubled the
//     attacker's allowance per account -- thirty at the form, thirty more at the
//     port, against a number documented as thirty.
//
// Every key here is unique per run. The suite shares one database and
// `signin:fail:*` has a fifteen-minute window, so fixed identifiers would
// accumulate across runs until a later run started at the ceiling -- the
// shared-test-state failure docs/BUILD-LOG.md records, which these tests are
// written to avoid rather than to rediscover.

func ldapAuthFixture(t *testing.T) (*LDAPAuthenticator, context.Context) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &LDAPAuthenticator{
		db: pool,
		// A small budget: these tests never verify a real hash, only the dummy
		// one on the unknown-user path, and a full-size Argon2 parameter set
		// times thirty iterations would make the run minutes long for nothing.
		hasher: passwords.NewHasher(8),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		via:    "ldap",
	}, ctx
}

// uniqueName returns an identifier no other run has used.
func uniqueName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("nobody-%d-%d@example.test", time.Now().UnixNano(), rand.Uint32())
}

// peerContext puts a per-run address on the context the way the LDAP server does.
func peerContext(ctx context.Context, t *testing.T) (context.Context, string) {
	t.Helper()
	// 2001:db8::/32 is the documentation range (RFC 3849), so these can never
	// collide with a real address in a shared bucket table.
	ip := fmt.Sprintf("2001:db8:%x:%x::1", time.Now().UnixNano()&0xffff, rand.Uint32()&0xffff)
	return ldapd.WithPeerAddr(ctx, ip), ip
}

// bindFromNewPeer attempts one bind from an address never used before.
//
// # Why the address has to move
//
// There are two budgets and the tighter one wins. Twenty failures per address
// per five minutes is reached before thirty per account per fifteen, so a test
// that guesses at one account from one address is stopped by the address limit
// after twenty and never exercises the account limit at all -- which is what
// the first version of these tests did, and it reported the account budget
// working when nothing had tested it.
//
// Moving the address each attempt leaves exactly one budget accumulating, so a
// failure names which of the two is broken. Every key is registered for
// cleanup, because these rows outlive the test by fifteen minutes and the suite
// shares one database.
func bindFromNewPeer(t *testing.T, a *LDAPAuthenticator, ctx context.Context, user string) error {
	t.Helper()
	peerCtx, ip := peerContext(ctx, t)
	cleanupBuckets(t, a, ctx, "signin:fail:ip:"+ip)
	_, err := a.Authenticate(peerCtx, user, "not-the-password")
	return err
}

// cleanupBuckets removes only the keys this test made.
//
// Scoped deletes, never `DELETE FROM core.rate_limits`: packages run in
// parallel against one database and a bare delete would drop a bucket another
// package's test had just written, surfacing as a failure somewhere unrelated.
func cleanupBuckets(t *testing.T, a *LDAPAuthenticator, ctx context.Context, keys ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, k := range keys {
			if _, err := a.db.Exec(ctx,
				`DELETE FROM core.rate_limits WHERE bucket_key = $1`, k); err != nil {
				t.Logf("cleaning up %q: %v", k, err)
			}
		}
	})
}

// Guessing at ONE ACCOUNT is bounded, however many addresses it comes from.
func TestAnLDAPBindIsRefusedOnceTheAccountBudgetIsSpent(t *testing.T) {
	a, ctx := ldapAuthFixture(t)
	user := uniqueName(t)
	cleanupBuckets(t, a, ctx, "signin:fail:user:"+strings.ToLower(user))

	// A username nobody holds. The budget must be charged for an unknown user
	// exactly as for a known one -- charging only for real accounts would make
	// the counter itself an enumeration oracle, where the refusals name the
	// accounts that exist.
	for i := 0; i < signInPerAccountLimit; i++ {
		if err := bindFromNewPeer(t, a, ctx, user); !errors.Is(err, errLDAPInvalid) {
			t.Fatalf("attempt %d: got %v, want an invalid-credentials refusal "+
				"while the budget still has room", i+1, err)
		}
	}

	// One past the limit, from an address that has spent nothing. A budget an
	// attacker escapes by moving address is not a budget on the account.
	if err := bindFromNewPeer(t, a, ctx, user); !errors.Is(err, ldapd.ErrBusy) {
		t.Fatalf("after %d failures against one account the bind returned %v; "+
			"want ldapd.ErrBusy. An unmetered bind path is a password-guessing "+
			"oracle on a port with no human in front of it.",
			signInPerAccountLimit, err)
	}
}

// Guessing FROM ONE ADDRESS is bounded, however many accounts it names.
//
// The account budget cannot see this attack: a run that tries one password
// against ten thousand usernames spends one failure per account and would never
// reach thirty on any of them. The address budget is the half that stops it.
func TestAnLDAPBindIsRefusedOnceTheAddressBudgetIsSpent(t *testing.T) {
	a, ctx := ldapAuthFixture(t)
	peerCtx, ip := peerContext(ctx, t)
	cleanupBuckets(t, a, ctx, "signin:fail:ip:"+ip)

	for i := 0; i < signInPerIPLimit; i++ {
		// A different account each time, so only the address budget grows.
		user := uniqueName(t)
		cleanupBuckets(t, a, ctx, "signin:fail:user:"+strings.ToLower(user))
		if _, err := a.Authenticate(peerCtx, user, "not-the-password"); !errors.Is(err, errLDAPInvalid) {
			t.Fatalf("attempt %d: got %v, want an invalid-credentials refusal", i+1, err)
		}
	}

	user := uniqueName(t)
	cleanupBuckets(t, a, ctx, "signin:fail:user:"+strings.ToLower(user))
	if _, err := a.Authenticate(peerCtx, user, "not-the-password"); !errors.Is(err, ldapd.ErrBusy) {
		t.Fatalf("after %d failures from one address the bind returned %v; want "+
			"ldapd.ErrBusy. Spraying one password across many accounts never "+
			"reaches any account's own limit.", signInPerIPLimit, err)
	}
}

// The port and the form draw down ONE budget, not two.
//
// This is the test that would have failed against the obvious implementation.
// Spending the account's allowance through the LDAP path must leave nothing for
// the form, because they guard the same credential.
func TestTheLDAPAndFormBudgetsAreTheSameBudget(t *testing.T) {
	a, ctx := ldapAuthFixture(t)
	user := uniqueName(t)
	key := "signin:fail:user:" + strings.ToLower(user)
	cleanupBuckets(t, a, ctx, key)

	for i := 0; i < signInPerAccountLimit; i++ {
		if err := bindFromNewPeer(t, a, ctx, user); !errors.Is(err, errLDAPInvalid) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}

	// Read the very key `allowSignInAttempt` reads. If the LDAP path had used a
	// namespace of its own this count would be zero and the form would still be
	// offering a full allowance on an account already guessed at thirty times.
	n, err := store.CountRate(ctx, a.db, key, signInPerAccountWindow)
	if err != nil {
		t.Fatal(err)
	}
	if n < signInPerAccountLimit {
		t.Fatalf("the form's bucket %q holds %d failures after %d LDAP binds. "+
			"Two doors onto one credential must draw down one budget, or the "+
			"budget describes neither door.", key, n, signInPerAccountLimit)
	}
}

// Retrying while throttled must not extend the ban.
//
// The product has expiring rate limits and deliberately no lockout, so that
// nobody can be denied sign-in on purpose. If a refused bind charged the budget
// again, a client that reconnects on a timer would hold its own account at the
// ceiling indefinitely -- a lockout, arrived at by accident, and one no
// administrator can see a cause for.
func TestABindRefusedForThrottlingIsNotChargedAgain(t *testing.T) {
	a, ctx := ldapAuthFixture(t)
	user := uniqueName(t)
	key := "signin:fail:user:" + strings.ToLower(user)
	cleanupBuckets(t, a, ctx, key)

	for i := 0; i < signInPerAccountLimit; i++ {
		if err := bindFromNewPeer(t, a, ctx, user); !errors.Is(err, errLDAPInvalid) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	before, err := store.CountRate(ctx, a.db, key, signInPerAccountWindow)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if err := bindFromNewPeer(t, a, ctx, user); !errors.Is(err, ldapd.ErrBusy) {
			t.Fatalf("retry %d: got %v, want ErrBusy", i+1, err)
		}
	}

	after, err := store.CountRate(ctx, a.db, key, signInPerAccountWindow)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("five refused retries moved the counter from %d to %d. A "+
			"refused caller must not be able to extend its own ban, or an "+
			"expiring limit becomes a permanent lockout.", before, after)
	}
}

// The wire answer for a throttled bind is `busy`, not `invalidCredentials`.
//
// Collapsing every failure to invalid credentials is right for the enumeration
// cases and wrong for this one. The throttle answer is identical for a user who
// exists and one who does not -- the budget is charged for both -- so it
// discloses nothing about the directory. Saying "wrong password" instead would
// send an operator to rotate a correct service-account credential while the
// guessing run that actually spent the budget stayed invisible.
func TestAThrottledBindIsReportedAsBusy(t *testing.T) {
	src, err := os.ReadFile("../ldapd/server.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, "errors.Is(err, ErrBusy)") {
		t.Fatal("handleBind does not distinguish ErrBusy, so a throttled bind " +
			"is reported to the client as an invalid credential")
	}
	if !strings.Contains(body, "resultBusy") {
		t.Fatal("the bind path never answers resultBusy (RFC 4511 §4.1.9, " +
			"specs/rfc4511.txt:2904)")
	}
}
