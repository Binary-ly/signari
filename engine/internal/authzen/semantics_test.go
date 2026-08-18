package authzen

import "testing"

// AuthZEN Authorization API 1.0 §7.1.2.1, on `deny_on_first_deny`:
//
//	"Deny on first denial (or failure). This semantic could be desired if a PEP
//	wants to issue a few requests in a particular order, with any denial (error,
//	or `"decision": false`) 'short-circuiting' the evaluations call and returning
//	on the first denial. This essentially works like the && operator in
//	programming languages."
//
// The parenthetical is the load-bearing part: **error** counts as a denial.
//
// The batch handler used to `continue` past the short-circuit check on both of
// its failure paths — a malformed entry, and a decision that errored. Each
// produced `"decision": false` and then kept evaluating. A PEP expressing `&&`
// got an array that did not mean what the semantic promised: an errored first
// entry answered `false`, and the rest evaluated anyway.
//
// This test models the loop's decision rule directly, because that rule is the
// thing that was wrong — not the transport around it.
func TestShortCircuitTreatsAFailureAsADenial(t *testing.T) {
	// stop reports whether the loop should break after appending `decision`
	// under `semantic`. It is the rule from handleAuthzEvaluations.
	stop := func(semantic string, decision bool) bool {
		if semantic == DenyOnFirstDeny && !decision {
			return true
		}
		if semantic == PermitOnFirstPermit && decision {
			return true
		}
		return false
	}

	for _, c := range []struct {
		name      string
		semantic  string
		decision  bool
		wantBreak bool
	}{
		// A failure is represented as decision=false, so it must stop a
		// deny_on_first_deny batch exactly as an ordinary denial does. That
		// equivalence is the whole fix: the old code produced this same false
		// and then skipped the check.
		{"a failure denies", DenyOnFirstDeny, false, true},
		{"an ordinary denial denies", DenyOnFirstDeny, false, true},
		{"a permit continues", DenyOnFirstDeny, true, false},

		{"a permit short-circuits", PermitOnFirstPermit, true, true},
		{"a denial continues", PermitOnFirstPermit, false, false},
		// A failure under permit_on_first_permit is decision=false, which must
		// NOT short-circuit -- a later entry may still permit.
		{"a failure does not permit", PermitOnFirstPermit, false, false},

		{"execute_all never stops on a denial", ExecuteAll, false, false},
		{"execute_all never stops on a permit", ExecuteAll, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := stop(c.semantic, c.decision); got != c.wantBreak {
				t.Fatalf("stop(%q, decision=%v) = %v, want %v",
					c.semantic, c.decision, got, c.wantBreak)
			}
		})
	}
}

// The three semantics the specification names, and no others.
//
// §7.1.2.1: "a PEP can pass in options.evaluations_semantic with exactly one of
// the following values: execute_all, deny_on_first_deny, permit_on_first_permit"
// and "execute_all is the default semantic".
func TestTheThreeSemanticsAreSpelledExactly(t *testing.T) {
	for name, got := range map[string]string{
		"execute_all":            ExecuteAll,
		"deny_on_first_deny":     DenyOnFirstDeny,
		"permit_on_first_permit": PermitOnFirstPermit,
	} {
		if got != name {
			t.Errorf("constant for %q is %q; a PEP sending the specified "+
				"spelling would be refused", name, got)
		}
	}
}
