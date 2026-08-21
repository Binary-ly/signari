package flow

import "testing"

// The flow language defines four designations and this engine executes one.
//
// `flowFor` has exactly two callers and both pass Authentication. `/signup` and
// `/recover` are hardcoded journeys that never read a flow document. So an
// operator can write a recovery flow, have it parsed, have safety rules written
// specifically for it applied, watch its tests pass, install it — and it governs
// nothing.
//
// This test does not assert that the gap is closed. It asserts that the
// codebase's own answer to "is this executed?" stays truthful, so that the
// warnings built on it cannot quietly become wrong in either direction.
func TestOnlyAuthenticationIsDriven(t *testing.T) {
	if !Authentication.Driven() {
		t.Error("Authentication is reported as not driven; flowFor passes it")
	}
	for _, d := range []Designation{Enrolment, Recovery, Unenrolment} {
		if d.Driven() {
			t.Errorf("%s is reported as driven. If a driver was added, this test "+
				"and item 9q both need updating -- and if one was NOT added, the "+
				"CLI is now telling operators their flow runs when it does not", d)
		}
	}
}

// The list the CLI iterates must match the predicate, or a designation could be
// added and silently omitted from the warning.
func TestUndrivenListsEveryUndrivenDesignation(t *testing.T) {
	got := map[Designation]bool{}
	for _, d := range Undriven() {
		if d.Driven() {
			t.Errorf("Undriven() returned %s, which reports itself as driven", d)
		}
		got[d] = true
	}
	for _, d := range []Designation{Authentication, Enrolment, Recovery, Unenrolment} {
		if !d.Driven() && !got[d] {
			t.Errorf("%s is not driven and Undriven() omits it, so nothing warns "+
				"about a file that declares one", d)
		}
	}
}
