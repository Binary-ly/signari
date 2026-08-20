package authzen

import (
	"encoding/json"
	"strings"
	"testing"
)

// AuthZEN 1.0 Final §6.2: the Access Evaluation response "consists of the
// Decision entity", whose `decision` field is REQUIRED and boolean.
//
// This tests the WIRE FORMAT, not the semantics. The semantics have tests
// already — `semantics_test.go` covers short-circuiting and how a failure is
// represented — but every one of them reads the Go struct field. None would
// notice if `decision` stopped appearing in the JSON.
//
// The way it stops appearing is one word. `json:"decision,omitempty"` on a bool
// omits it whenever it is false, so **every deny would serialise as `{}`** while
// every permit kept working, and the whole test suite would stay green. A PDP
// that answers `{}` to a deny is not conformant — §6.2 makes the field required
// — and what a PEP does with a missing field is its own business, not something
// to rely on.
//
// It is the deny direction that would break, which is the direction where being
// wrong grants access.
func TestADenySerialisesTheDecisionFieldRatherThanOmittingIt(t *testing.T) {
	b, err := json.Marshal(Response{Decision: false})
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, `"decision":false`) {
		t.Fatalf("a deny serialised as %s. §6.2 makes `decision` required, and a "+
			"response that omits it on false is a PDP answering `{}` to every deny. "+
			"The usual cause is `omitempty` on the bool", got)
	}

	// And a permit still says so explicitly.
	b, err = json.Marshal(Response{Decision: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"decision":true`) {
		t.Fatalf("a permit serialised as %s", b)
	}

	// The batch form carries the same entity per entry, so the same hazard
	// applies to each element rather than to the envelope.
	b, err = json.Marshal(EvaluationsResponse{Evaluations: []Response{
		{Decision: false}, {Decision: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), `"decision"`) != 2 {
		t.Errorf("the batch response dropped a decision field: %s", b)
	}

	// Round-trip: a deny must survive being parsed back by a PEP.
	var back Response
	if err := json.Unmarshal([]byte(`{"decision":false}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.Decision {
		t.Error("a deny round-tripped into a permit")
	}
}
