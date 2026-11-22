package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"signari.dev/engine/internal/ldapd"
)

// A burst of wrong binds stops at the budget, unverified. The budget was read
// before the Argon2 verification and charged after it, so every bind arriving
// while others were being verified read a count below the limit: a parallel
// burst was hashed in full, and the budget only counted it afterwards.
func TestABurstOfWrongBindsStopsAtTheBudget(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerAccountWindow)
	ctx := context.Background()
	key := "signin:fail:user:" + strings.ToLower(f.email)
	clear := func() {
		if _, err := f.pool.Exec(context.Background(), `DELETE FROM core.rate_limits WHERE bucket_key = $1`, key); err != nil {
			t.Fatal(err)
		}
	}
	clear()
	t.Cleanup(clear)
	count := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx,
			`SELECT COALESCE(sum(count), 0) FROM core.rate_limits WHERE bucket_key = $1`, key).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	b := f.binder()

	// A correct bind costs nothing: its place is handed back.
	for i := 0; i < 3; i++ {
		if _, err := b.Authenticate(ctx, f.email, signInTestPassword); err != nil {
			t.Fatalf("a correct bind failed: %v", err)
		}
	}
	if n := count(); n != 0 {
		t.Fatalf("three correct binds left %d in the failure budget", n)
	}

	const burst = 2 * signInPerAccountLimit
	var wg sync.WaitGroup
	var busy, invalid atomic.Int32
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := b.Authenticate(ctx, f.email, fmt.Sprintf("wrong-%d", i))
			switch {
			case errors.Is(err, ldapd.ErrBusy):
				busy.Add(1)
			case errors.Is(err, errLDAPInvalid):
				invalid.Add(1)
			default:
				t.Errorf("bind %d: unexpected outcome %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if int(invalid.Load()) != signInPerAccountLimit || int(busy.Load()) != burst-signInPerAccountLimit {
		t.Fatalf("a burst of %d wrong binds: %d verified and refused, %d refused at the budget; "+
			"want %d and %d", burst, invalid.Load(), busy.Load(), signInPerAccountLimit,
			burst-signInPerAccountLimit)
	}
	if n := count(); n != signInPerAccountLimit {
		t.Fatalf("the budget holds %d after the burst, want %d", n, signInPerAccountLimit)
	}
}
