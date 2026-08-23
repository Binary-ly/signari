package passwords

import (
	"context"
	"testing"
)

// BenchmarkArgon2Verify measures a single Argon2id verification at the shipped
// parameters (19 MiB, t=2, p=1).
//
// It exists so the "the sign-in path is Argon2-bound" claim in
// internal/httpapi/signinbench_test.go is checkable rather than asserted from a
// throwaway measurement. A full sign-in benchmarked at ~45 ms and this at ~30 ms
// means the memory-hard hash is ~two-thirds of the path, which is the design: a
// change that showed up here would be one worth worrying about, and a sign-in
// that drifted far above hash+overhead would mean something new joined the path.
//
// Run:
//
//	go test ./internal/passwords/ -run '^$' -bench BenchmarkArgon2Verify -benchtime 20x
func BenchmarkArgon2Verify(b *testing.B) {
	h := NewHasher(0)
	ctx := context.Background()
	// Hash once, outside the timer -- verification is the hot path (every sign-in),
	// hashing is the cold one (password set/change).
	stored, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		b.Fatalf("hash: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.Verify(ctx, stored, "correct horse battery staple"); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}
