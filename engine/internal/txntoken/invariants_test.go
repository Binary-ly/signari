package txntoken

import (
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// The second turn on this specification: attacking the invariants rather than
// reading them.
//
// The first pass extracted all 143 normative uses across 36 sections and
// concluded, from reading `Replace`, that three properties hold — `txn`, `sub`
// and `aud` are immutable, scope only narrows, and a replacement never outlives
// the token it came from. "Very harshly tested" is a different claim from
// "carefully read", and this is the difference.
//
// `Replace` is EXPORTED, and its own comment notes that "a future caller might
// not verify first". So the generator here does not restrict itself to
// well-formed input: it produces the malformed, the adversarial and the merely
// strange, and asserts that every SUCCESSFUL replacement satisfies the
// invariants regardless of what was fed in.

// scopeVocabulary deliberately includes values designed to slip past a naive
// containment check: case variants, substrings of one another, and values
// carrying whitespace that a hand-rolled splitter would mishandle.
var scopeVocabulary = []string{
	"read", "READ", "read ", " read", "readwrite", "write", "admin",
	"read\twrite", "read\nwrite", "", " ", "read  write", "rea", "reads",
}

func randomScope(rng *rand.Rand) string {
	n := rng.Intn(4)
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, scopeVocabulary[rng.Intn(len(scopeVocabulary))])
	}
	sep := []string{" ", "  ", "\t", "\n"}[rng.Intn(4)]
	return strings.Join(parts, sep)
}

func asSet(scope string) map[string]bool {
	out := map[string]bool{}
	for _, s := range strings.Fields(scope) {
		out[s] = true
	}
	return out
}

func TestReplaceNeverBreaksItsInvariants(t *testing.T) {
	rng := rand.New(rand.NewSource(20260821))
	now := time.Unix(1_780_000_000, 0)

	var accepted, refused int
	for i := 0; i < 4000; i++ {
		prev := Claims{
			Issuer:      "https://tts.example",
			Audience:    []string{"trust-domain-a", "trust-domain-b", ""}[rng.Intn(3)],
			Transaction: []string{"txn-1", "txn-2", ""}[rng.Intn(3)],
			Subject:     []string{"user-1", "user-2", ""}[rng.Intn(3)],
			Scope:       randomScope(rng),
			// Expiries around, on and behind `now`, plus absent.
			Expiry:             now.Unix() + int64(rng.Intn(2000)-1000),
			IssuedAt:           now.Unix() - int64(rng.Intn(100)),
			RequestingWorkload: []string{"wl-a", ""}[rng.Intn(2)],
			TransactionContext: map[string]any{"action": "transfer"},
		}
		if rng.Intn(8) == 0 {
			prev.Expiry = 0
		}
		if rng.Intn(6) == 0 {
			n := rng.Intn(MaxCallChain + 3)
			prev.CallChain = make([]string, n)
			for j := range prev.CallChain {
				prev.CallChain[j] = "hop"
			}
		}

		req := Replacement{
			Previous: prev,
			Workload: []string{"wl-next", ""}[rng.Intn(2)],
			Scope:    strings.Fields(randomScope(rng)),
		}
		ttl := []time.Duration{0, -time.Hour, time.Minute, DefaultTTL, MaxTTL, 100 * time.Hour}[rng.Intn(6)]

		out, err := Replace(req, "https://tts.example", now, ttl)
		if err != nil {
			refused++
			continue
		}
		accepted++

		// 1. The three immutable claims (§13.15: "MUST NOT modify txn, sub, and
		//    aud values of the Txn-Token in the request").
		if out.Transaction != prev.Transaction {
			t.Fatalf("txn changed: %q -> %q", prev.Transaction, out.Transaction)
		}
		if out.Subject != prev.Subject {
			t.Fatalf("sub changed: %q -> %q", prev.Subject, out.Subject)
		}
		if out.Audience != prev.Audience {
			t.Fatalf("aud changed: %q -> %q", prev.Audience, out.Audience)
		}

		// 2. Scope only narrows (§13.15: "MUST NOT enable modification to asserted
		//    values that expand the scope of permitted actions").
		had, got := asSet(prev.Scope), asSet(out.Scope)
		_ = had
		for s := range got {
			if !had[s] {
				t.Fatalf("scope widened: %q appeared in the replacement but was not "+
					"in %q (requested %v)", s, prev.Scope, req.Scope)
			}
		}

		// 2b. Asking for NOTHING inherits everything, rather than dropping it.
		//
		// The subset check above cannot see this: silently emptying the scope is a
		// narrowing, and narrowing is permitted. But `Replace` states the opposite
		// intent -- "asking for nothing means carry what I have... silence should
		// not silently drop authority the next hop needs" -- and a mutation that
		// replaced the validated `want` with the caller's raw `r.Scope` passed
		// every other assertion here precisely because of that blind spot.
		if len(req.Scope) == 0 {
			for s := range had {
				if !got[s] {
					t.Fatalf("a replacement that requested no scope lost %q; asking "+
						"for nothing means carrying what the presented token had, not "+
						"surrendering it (%q -> %q)", s, prev.Scope, out.Scope)
				}
			}
		}

		// 3. The replacement never outlives what it replaced, and is alive when
		//    issued.
		if out.Expiry > prev.Expiry {
			t.Fatalf("exp extended: %d -> %d", prev.Expiry, out.Expiry)
		}
		if out.Expiry <= now.Unix() {
			t.Fatalf("issued an already-expired token: exp %d, now %d",
				out.Expiry, now.Unix())
		}

		// 4. The call chain grows by exactly one and loses nothing (§13.15's
		//    "MUST maintain the Call Chain").
		before := existingChain(prev)
		if len(out.CallChain) != len(before)+1 {
			t.Fatalf("chain length %d, want %d+1", len(out.CallChain), len(before))
		}
		for j := range before {
			if out.CallChain[j] != before[j] {
				t.Fatalf("chain entry %d changed: %q -> %q", j, before[j], out.CallChain[j])
			}
		}
		if out.CallChain[len(out.CallChain)-1] != req.Workload {
			t.Fatalf("the last chain entry is %q, not the requesting workload %q",
				out.CallChain[len(out.CallChain)-1], req.Workload)
		}

		// 5. Transaction context is immutable too -- "what is being done does not
		//    change because the request moved one service to the right".
		if out.TransactionContext["action"] != "transfer" {
			t.Fatalf("tctx was altered: %v", out.TransactionContext)
		}
	}

	// The generator must actually exercise both paths, or an invariant that holds
	// vacuously would look proven.
	if accepted < 200 || refused < 200 {
		t.Fatalf("the generator is lopsided: %d accepted, %d refused -- the "+
			"invariants above are only meaningful over accepted replacements",
			accepted, refused)
	}
	t.Logf("%d accepted, %d refused", accepted, refused)
}

// A chain at the limit must refuse, and refuse for the stated reason, however
// the limit was reached.
func TestChainLimitHoldsUnderAdversarialInput(t *testing.T) {
	now := time.Now()
	for _, n := range []int{MaxCallChain, MaxCallChain + 1, MaxCallChain + 50} {
		chain := make([]string, n)
		for i := range chain {
			chain[i] = "hop"
		}
		_, err := Replace(Replacement{
			Previous: Claims{
				Transaction: "t", Subject: "s", Scope: "read",
				Expiry: now.Add(time.Hour).Unix(), CallChain: chain,
			},
			Workload: "next", Scope: []string{"read"},
		}, "https://tts.example", now, DefaultTTL)
		if !errors.Is(err, ErrChainTooLong) {
			t.Errorf("a chain of %d was not refused as too long: %v", n, err)
		}
	}
}
