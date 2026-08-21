package httpapi

import (
	"context"
	"testing"
)

// What the sign-in path costs, and what share of it the flow engine is.
//
// Run:
//
//	SIGNARI_TEST_DSN=... go test ./internal/httpapi/ -run '^$' \
//	    -bench BenchmarkFullSignIn -benchtime 30x
//
// The question these exist to answer is a specific one. Moving the sequence into
// a file put a configuration lookup and a set of condition queries on the path
// that every password sign-in takes, and "it is probably fine" is not a claim
// this project accepts about its own hot paths -- particularly one that
// publishes p95 figures.
//
// Measured on the development laptop, August 2026:
//
//	BenchmarkFullSignIn-8         59,837,825 ns/op    (59.8 ms)
//	BenchmarkFlowMFADecision-8       442,007 ns/op    ( 0.44 ms)
//
// So the flow decision is 0.7% of a sign-in, and the sign-in is Argon2-bound --
// which is the design. The 19 MiB memory-hard hash is meant to dominate, and a
// change that showed up against it would be a change worth worrying about.
//
// # Re-measured 21 August 2026, and the second sentence above is no longer true
//
// Three consecutive runs at the documented `-benchtime 30x`, same machine:
//
//	BenchmarkFullSignIn-8         76.0, 75.7, 76.3 ms   (was 59.8)
//	BenchmarkFlowMFADecision-8    152, 156, 150 us      (was 442)
//	BenchmarkArgon2Verify         30.2 ms  (measured separately, throwaway)
//
// **Argon2 is now 40% of a sign-in, not the dominant share.** 76 ms total against
// 30 ms of hashing leaves ~46 ms of other work on a path this comment describes
// as "Argon2-bound". The claim was true when written and has stopped being true,
// which is exactly what re-running a benchmark is for.
//
// The two figures moved in OPPOSITE directions on the same machine in the same
// session -- the decision got three times faster while the sign-in got 27%
// slower -- so this is not the machine being uniformly slower. At least one of
// them is a real change in the code.
//
// Ruled out, with measurements rather than reasoning:
//
//   - Argon2 parameters: unchanged at 19 MiB, t=2, p=1.
//   - Double hashing via the lazy rehash in flow.go: the fixture stores a
//     current-policy `$argon2id$` hash, so `needsRehash` is false and Hash is
//     never called on this path.
//   - Database round trips: ~13 transactions per sign-in, and an in-process pgx
//     round trip on loopback is sub-millisecond.
//
// Not localised. `attempt` measures a GET of the form (render plus CSRF mint)
// and then the POST, so the ~46 ms is spread across two requests and whatever
// middleware now sits in front of them. Recorded in TODO-FOR-YOU.md rather than
// guessed at.
//
// The decision costs ONE query, the same as the `if enrolled` it replaced. An
// earlier version of this code cost three, and then six; see
// TestTheSecondFactorDecisionCostsOneQuery, which pins it.

func BenchmarkFullSignIn(b *testing.B) {
	t := &testing.T{}
	f := newSignInFixture(t)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.attempt(t, f.email, signInTestPassword)
		// Outside the timer: the fixture asserts on session count elsewhere, and
		// leaving rows behind would measure a growing table rather than a sign-in.
		b.StopTimer()
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.sessions WHERE user_id = $1::uuid`, f.userID)
		b.StartTimer()
	}
}

// BenchmarkFlowMFADecision isolates the part that is new.
func BenchmarkFlowMFADecision(b *testing.B) {
	t := &testing.T{}
	f := newSignInFixture(t)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.srv.FlowDemandsMFA(ctx, f.pool, f.orgID, f.userID, "", []string{"pwd"})
	}
}
