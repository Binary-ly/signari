package keys

import (
	"strings"
	"sync"
	"testing"
)

// Reloading the live key set.
//
// The set was read once at startup and never again, which defeated rotation
// entirely: a `next` key published so relying parties could cache it before it
// signed anything never reached them at all, so the day-long wait before
// promotion protected nothing.

func genKey(t *testing.T, alg Algorithm, state State) Key {
	t.Helper()
	k, err := Generate(NewKID(), alg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := WithState(k, state)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReplaceSwapsWhatIsServed(t *testing.T) {
	first := genKey(t, ES256, StateActive)
	set, err := NewSet(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.JWKS().Keys) != 1 {
		t.Fatalf("expected one key to start")
	}

	// A rotation publishes a `next` key alongside the active one.
	next := genKey(t, ES256, StateNext)
	if err := set.Replace(first, next); err != nil {
		t.Fatal(err)
	}

	kids := map[string]bool{}
	for _, k := range set.JWKS().Keys {
		kids[k.KeyID] = true
	}
	if !kids[next.KID()] {
		t.Fatal("the new key is not published after Replace; a relying party would " +
			"never cache it, and the wait before promoting it protects nothing")
	}
	if !kids[first.KID()] {
		t.Fatal("the previous key stopped being published; tokens already issued " +
			"would stop verifying")
	}
}

// TestReplaceRefusesAnUnsafeSetAndKeepsTheOldOne.
//
// The running configuration is the one known to work. A reload that produced
// two active keys for one algorithm must not replace a good set with a bad one.
func TestReplaceRefusesAnUnsafeSetAndKeepsTheOldOne(t *testing.T) {
	good := genKey(t, ES256, StateActive)
	set, err := NewSet(good)
	if err != nil {
		t.Fatal(err)
	}

	other := genKey(t, ES256, StateActive)
	err = set.Replace(good, other)
	if err == nil {
		t.Fatal("two active keys for one algorithm were accepted; signing would be " +
			"non-deterministic")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("unhelpful error: %v", err)
	}

	// And the good set is still in force.
	active, err := set.Active(ES256)
	if err != nil {
		t.Fatalf("the working set was lost after a refused reload: %v", err)
	}
	if active.KID() != good.KID() {
		t.Fatalf("active key is %q, want the one that was working", active.KID())
	}
}

// TestConcurrentReadsDuringReplace is why the swap is behind a lock.
//
// The set is shared by every request in flight: one signing a token, another
// rendering JWKS, while a refresh replaces the keys underneath them.
func TestConcurrentReadsDuringReplace(t *testing.T) {
	a := genKey(t, ES256, StateActive)
	set, err := NewSet(a)
	if err != nil {
		t.Fatal(err)
	}
	b := genKey(t, ES256, StateNext)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Every reader: a short or torn slice here is the failure.
				if n := len(set.JWKS().Keys); n < 1 {
					t.Errorf("JWKS returned %d keys mid-replace", n)
					return
				}
				_ = set.Keys()
				_, _ = set.Active(ES256)
			}
		}()
	}

	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			_ = set.Replace(a, b)
		} else {
			_ = set.Replace(a)
		}
	}
	close(stop)
	wg.Wait()
}
