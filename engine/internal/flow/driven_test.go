package flow

import "testing"

// The flow language defines four designations and this engine executes three:
// authentication (always), enrolment (9q option 2 -- /signup walks the flow) and
// recovery (9q option 3 -- /recover and /recover/reset walk it).
//
// Unenrolment is the fourth and is deliberately not driven, for a different
// reason than the other three ever were: there is no unenrolment journey in this
// engine to drive. Account deletion is `signari erase subject` and the admin API,
// which are operator actions rather than a sequence a subject walks. If a
// self-service deletion endpoint is ever built, this test is what fails and says
// so.
//
// This test asserts that the codebase's own answer to "is this executed?" stays
// truthful, so the warnings built on it cannot quietly become wrong in either
// direction: if a driver is added without updating Driven(), operators keep being
// warned about a flow that now runs; if Driven() is widened without a driver,
// they stop being warned about one that does not.
func TestDrivenReportsTheDesignationsWithDrivers(t *testing.T) {
	for _, d := range []Designation{Authentication, Enrolment, Recovery} {
		if !d.Driven() {
			t.Errorf("%s is reported as not driven, but the engine executes it", d)
		}
	}
	for _, d := range []Designation{Unenrolment} {
		if d.Driven() {
			t.Errorf("%s is reported as driven. If a self-service unenrolment "+
				"journey was built, update this test with it -- and if one was NOT "+
				"built, the CLI is now telling operators their flow runs when there "+
				"is no endpoint for it to run at", d)
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
