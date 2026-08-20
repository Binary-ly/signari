package httpapi

import (
	"os"
	"testing"
)

// A suite that skipped most of itself must not exit 0 silently.
//
// This exists because of a specific wrong conclusion. A mutation run reported
// eight surviving mutants in internal/tokens -- guards it claimed no test
// covered, including the one gating /userinfo. Re-run with SIGNARI_TEST_DSN
// set, every one of them was killed. The harness had run without a database,
// so every database-backed test called t.Skip, and a skipped test cannot fail.
// The harness read the exit code, saw 0, and reported "your tests do not cover
// this" about code that was thoroughly covered.
//
// Note which direction that error runs. A skipped test cannot fail, so it can
// never produce a false KILL -- only a false SURVIVAL. Every "caught" recorded
// in docs/ therefore still stands. What the flaw destroyed was the ability to
// trust a clean report, and the effort spent writing tests for already-tested
// code.
//
// The rule this encodes: a green suite must mean the suite RAN. Anything
// reading an exit code -- a mutation harness, CI, a coverage gate, a person in
// a hurry -- is entitled to assume that, and until now it was not true.
//
// Developers without Postgres set SIGNARI_ALLOW_SKIPPED_DB_TESTS=1. That is a
// deliberate, visible choice rather than the accident of an unset variable,
// which is the entire distinction this test exists to draw.
func TestDatabaseBackedTestsWereNotSilentlySkipped(t *testing.T) {
	if os.Getenv("SIGNARI_TEST_DSN") != "" {
		return // they ran; nothing to say
	}
	if os.Getenv("SIGNARI_ALLOW_SKIPPED_DB_TESTS") == "1" {
		t.Skip("SIGNARI_ALLOW_SKIPPED_DB_TESTS=1: the database-backed tests were " +
			"skipped on purpose, and this run proves nothing about them")
	}
	t.Fatal("SIGNARI_TEST_DSN is not set, so every database-backed test in this " +
		"repository just skipped -- which is most of them, including the whole of " +
		"the sign-in, token, SCIM and userinfo coverage.\n\n" +
		"This run would otherwise have exited 0 while proving almost nothing. A " +
		"mutation harness once read exactly that exit code and reported eight " +
		"uncovered guards that were in fact all covered.\n\n" +
		"Set SIGNARI_TEST_DSN=postgres://<user>@localhost:5432/signari_test to run " +
		"them, or SIGNARI_ALLOW_SKIPPED_DB_TESTS=1 to say you meant to skip them.")
}
