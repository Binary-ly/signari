package authzen

import (
	"strings"
	"testing"
)

// The authorization model.
//
// Every refusal here is a model that would have loaded and then been wrong in a
// way nobody would notice until somebody was let in or kept out.

const goodModel = `
types:
  document:
    relations:
      owner: []
      editor: [owner]
      viewer: [editor]
    permissions:
      read: [viewer]
      write: [editor]
      delete: [owner]
    require:
      delete: {mfa: true}
tests:
  - name: an owner may read, through editor and viewer
    subject: user:alice
    action: read
    resource: document:1
    relations: [owner]
    allow: true
  - name: a viewer may not write
    subject: user:bob
    action: write
    resource: document:1
    relations: [viewer]
    allow: false
  - name: an owner without a second factor may not delete
    subject: user:alice
    action: delete
    resource: document:1
    relations: [owner]
    mfa: false
    allow: false
  - name: an owner with a second factor may delete
    subject: user:alice
    action: delete
    resource: document:1
    relations: [owner]
    mfa: true
    allow: true
`

func TestRelationsComposeTransitively(t *testing.T) {
	m, err := ParseModel([]byte(goodModel))
	if err != nil {
		t.Fatalf("the model did not load: %v", err)
	}

	// `read` is granted to viewer; owner implies editor implies viewer. Without
	// transitive expansion an owner cannot read their own document, which is
	// the first thing anybody notices and the last thing anybody expects.
	rels, ok := m.RelationsFor("document", "read")
	if !ok {
		t.Fatal("document.read is not defined")
	}
	want := map[string]bool{"owner": true, "editor": true, "viewer": true}
	if len(rels) != 3 {
		t.Fatalf("read is granted to %v, want owner, editor and viewer", rels)
	}
	for _, r := range rels {
		if !want[r] {
			t.Fatalf("read is granted to unexpected relation %q", r)
		}
	}

	// delete is owner only, and must NOT expand downward.
	rels, _ = m.RelationsFor("document", "delete")
	if len(rels) != 1 || rels[0] != "owner" {
		t.Fatalf("delete is granted to %v, want owner alone -- expanding the "+
			"wrong way round would let every viewer delete", rels)
	}
}

// A model whose own examples fail must not load.
func TestAModelThatFailsItsOwnTestsDoesNotLoad(t *testing.T) {
	broken := strings.Replace(goodModel,
		`  - name: a viewer may not write
    subject: user:bob
    action: write
    resource: document:1
    relations: [viewer]
    allow: false`,
		`  - name: a viewer may write
    subject: user:bob
    action: write
    resource: document:1
    relations: [viewer]
    allow: true`, 1)

	_, err := ParseModel([]byte(broken))
	if err == nil {
		t.Fatal("a model whose own test fails loaded; the tests are decoration")
	}
	if !strings.Contains(err.Error(), "a viewer may write") {
		t.Fatalf("err = %v, want it to name the failing test", err)
	}
}

func TestTheModelRefusesItsOwnFailureModes(t *testing.T) {
	for _, c := range []struct{ name, yaml, want string }{
		{
			// A permission granted by nothing reads exactly like a permission
			// that works, and is almost always a half-finished edit.
			"a permission nobody can hold",
			"types:\n  doc:\n    relations:\n      owner: []\n    permissions:\n      read: []\n",
			"granted by no relation",
		},
		{
			// Granting to a relation that does not exist grants to nobody.
			"a permission granted to a relation that does not exist",
			"types:\n  doc:\n    relations:\n      owner: []\n    permissions:\n      read: [viewr]\n",
			"not a relation",
		},
		{
			// A condition on an action nobody defined never runs, and reads as
			// a restriction that is in force.
			"a condition on an action that does not exist",
			"types:\n  doc:\n    relations:\n      owner: []\n    permissions:\n      read: [owner]\n    require:\n      delete: {mfa: true}\n",
			"would never be applied",
		},
		{
			// A cycle makes expansion loop. Refused rather than bounded: a
			// bound turns a broken model into a slow one instead of a rejected one.
			"a relation cycle",
			"types:\n  doc:\n    relations:\n      a: [b]\n      b: [a]\n    permissions:\n      read: [a]\n",
			"cycle",
		},
		{
			// A misspelled key silently dropped would leave a type granting
			// nothing, which looks at a glance like one granting everything.
			"a misspelled key",
			"types:\n  doc:\n    relations:\n      owner: []\n    permisions:\n      read: [owner]\n",
			"did not parse",
		},
		{
			"no types at all",
			"types: {}\n",
			"defines no types",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseModel([]byte(c.yaml))
			if err == nil {
				t.Fatal("it loaded")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// Conditions are about the SESSION, and an absent session must not satisfy one.
func TestAnAbsentFactDoesNotSatisfyACondition(t *testing.T) {
	c := Condition{MFA: true}
	if c.SatisfiedBy(Facts{}) {
		t.Fatal("a second-factor requirement was met by knowing nothing")
	}
	if !c.SatisfiedBy(Facts{MFA: true, FromSession: true}) {
		t.Fatal("a proved second factor did not satisfy the requirement")
	}

	c = Condition{AnyGroup: []string{"finance", "audit"}}
	if c.SatisfiedBy(Facts{Groups: []string{"engineering"}}) {
		t.Fatal("the wrong group satisfied a group requirement")
	}
	if !c.SatisfiedBy(Facts{Groups: []string{"engineering", "audit"}}) {
		t.Fatal("one matching group of several did not satisfy it")
	}

	// MaxRisk is an upper bound, so equal is allowed and above is not.
	c = Condition{MaxRisk: 50}
	if !c.SatisfiedBy(Facts{Risk: 50}) {
		t.Fatal("risk exactly at the limit was refused")
	}
	if c.SatisfiedBy(Facts{Risk: 51}) {
		t.Fatal("risk above the limit was allowed")
	}
}

func TestMergeAppliesBatchDefaultsFieldByField(t *testing.T) {
	defaults := Evaluations{
		Subject:  &Subject{Type: "user", ID: "alice"},
		Resource: &Resource{Type: "document", ID: "1"},
		Action:   &Action{Name: "read"},
	}

	// An entry that names only a resource id must still inherit the TYPE. An
	// all-or-nothing merge would leave it typeless and unmatchable, and the
	// decision would be a confident denial about a resource of no kind.
	got := Request{Resource: Resource{ID: "42"}}.Merge(defaults)
	if got.Resource.Type != "document" || got.Resource.ID != "42" {
		t.Fatalf("resource = %+v, want type document and the entry's own id", got.Resource)
	}
	if got.Subject.ID != "alice" || got.Action.Name != "read" {
		t.Fatalf("the unset fields did not inherit: %+v %+v", got.Subject, got.Action)
	}

	// An entry that sets a field must keep it.
	got = Request{Action: Action{Name: "write"}}.Merge(defaults)
	if got.Action.Name != "write" {
		t.Fatalf("the entry's own action was overwritten by the default")
	}
}

// A malformed request is refused, not denied.
func TestValidateNamesEveryMissingField(t *testing.T) {
	err := Request{}.Validate()
	if err == nil {
		t.Fatal("an empty request validated")
	}
	for _, want := range []string{"subject.type", "subject.id", "action.name", "resource.type"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to name %q", err, want)
		}
	}

	// resource.id is NOT required: a search or a type-level question does not
	// have one, and demanding it would refuse valid requests.
	if err := (Request{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document"},
	}).Validate(); err != nil {
		t.Fatalf("a request without resource.id was refused: %v", err)
	}
}

func TestReasonsAreSplitBetweenAdminAndUser(t *testing.T) {
	ctx := Reasons("failed policy C076E82F on document:42", "You do not have access.")
	admin, ok := ctx["reason_admin"].(map[string]any)
	if !ok || admin["403"] != "failed policy C076E82F on document:42" {
		t.Fatalf("reason_admin = %v", ctx["reason_admin"])
	}
	user, ok := ctx["reason_user"].(map[string]any)
	if !ok || user["403"] != "You do not have access." {
		t.Fatalf("reason_user = %v", ctx["reason_user"])
	}

	// Collapsing them means either the user is told which policy refused them
	// -- which tells an attacker what to change -- or the administrator is told
	// "insufficient privileges", which tells them nothing.
	if admin["403"] == user["403"] {
		t.Fatal("the two reasons are the same string")
	}
	if Reasons("", "") != nil {
		t.Fatal("an empty context should be absent, not an empty object")
	}
}
