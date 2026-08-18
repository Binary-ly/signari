package httpapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The batch loop must reach its short-circuit check on every path.
//
// AuthZEN §7.1.2.1 defines deny_on_first_deny as short-circuiting on "any denial
// (error, or `"decision": false`)" — so a malformed entry and a failed decision
// have to stop the batch exactly as an ordinary denial does. Both failure
// branches used to `continue`, which skipped the check entirely.
//
// # Why this test reads the source
//
// The natural test — "assert the rule" — is the one written first, in
// internal/authzen/semantics_test.go. It models the decision rule and passes
// whatever the handler does, including with the `continue` still in place. It is
// worth keeping as documentation of the rule, and it is worthless as a
// regression guard for this bug.
//
// Driving the real handler needs a Server with a database, a policy store and an
// org — a fixture this package does not have, and building one to prove a `break`
// is reached would be a large amount of machinery around a small fact.
//
// So this checks the shape instead: no `continue` inside the evaluations loop.
// That is narrow and slightly brittle, and it fails on the exact edit that
// caused the bug, which the other test does not.
func TestTheBatchLoopHasNoContinuePastTheShortCircuit(t *testing.T) {
	src, err := os.ReadFile("authorization.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	start := strings.Index(body, "for _, e := range batch.Evaluations {")
	if start < 0 {
		t.Fatal("the evaluations loop was not found; this test needs updating " +
			"alongside whatever replaced it")
	}
	end := strings.Index(body[start:], "\n\techoRequestID(w, r)")
	if end < 0 {
		t.Fatal("could not find the end of the evaluations loop")
	}
	loop := body[start : start+end]

	if regexp.MustCompile(`(?m)^\s*continue\s*$`).MatchString(loop) {
		t.Error("the evaluations loop contains a `continue`, which skips the " +
			"short-circuit check below it. AuthZEN §7.1.2.1 short-circuits " +
			"deny_on_first_deny on \"any denial (error, or `\"decision\": false`)\", " +
			"so a malformed entry and a failed decision must stop the batch too. " +
			"Append the response and fall through instead.")
	}

	// And the check itself must still be there to fall through to.
	for _, want := range []string{"DenyOnFirstDeny", "PermitOnFirstPermit"} {
		if !strings.Contains(loop, want) {
			t.Errorf("the evaluations loop no longer applies %s", want)
		}
	}
}
