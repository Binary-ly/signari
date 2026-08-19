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
