package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
)

const walkModel = `
types:
  doc:
    relations:
      owner: []
      parent: []
      editor: [owner]
      viewer: [editor, parent->viewer]
    permissions:
      edit: [editor]
      view: [viewer]
  team:
    relations:
      member: []
    permissions:
      join: [member]
  level:
    relations:
      member: []
    permissions:
      hold: [member]
  resource:
    relations:
      level: []
      owner: []
      is_owner: [owner->member]
      viewer: [owner->member]
      cleared: [level->member]
    permissions:
      read: [viewer, is_owner]
      update: [is_owner]
      delete: [is_owner]
    also:
      delete: [cleared]
  acl:
    relations:
      allow: []
      deny: []
    permissions:
      access: [allow]
    except:
      access: [deny]
`

func walkFixture(t *testing.T) (orgID string, m *authzen.Model, grant func(subject, relation, object string)) {
	t.Helper()
	conn := connect(t)
	orgID, _, _, _ = fixture(t, conn)
	m, err := authzen.ParseModel([]byte(walkModel))
	if err != nil {
		t.Fatal(err)
	}
	return orgID, m, func(subject, relation, object string) {
		t.Helper()
		st, si, _ := authzen.ParseRef(subject)
		ot, oi, _ := authzen.ParseRef(object)
		if err := GrantRelation(context.Background(), conn, orgID, Relation{SubjectType: st, SubjectID: si,
			Relation: relation, ObjectType: ot, ObjectID: oi}, ""); err != nil {
			t.Fatal(err)
		}
	}
}

// Union, a relation through another object, a hierarchy four deep, a set of subjects,
// a group's members, intersection and exclusion, with the people each should leave
// out. A decision is the relation half and the narrowing together, so that is what
// is asked, through Explain, which is what an operator reads the answer from.
func TestARelationIsHeldThroughWhatTheModelSays(t *testing.T) {
	orgID, m, grant := walkFixture(t)
	conn := connect(t)
	ctx := context.Background()

	grant("user:ann", "owner", "doc:document")
	grant("user:ann", "owner", "doc:folder")
	grant("doc:folder", "parent", "doc:doc_in_folder")
	grant("user:bo", "owner", "doc:folder_a")
	grant("doc:folder_a", "parent", "doc:folder_b")
	grant("doc:folder_b", "parent", "doc:folder_c")
	grant("doc:folder_c", "parent", "doc:file")
	grant("user:mark", "member", "team:editors")
	grant("user:mike", "member", "team:editors")
	grant("user:mark", "member", "level:superadmin")
	grant("user:sandy", "member", "level:superadmin")
	grant("team:editors", "owner", "resource:topsecret")
	grant("level:superadmin", "level", "resource:topsecret")
	grant("user:alice", "allow", "acl:document")
	grant("user:mallory", "allow", "acl:document")
	grant("user:mallory", "deny", "acl:document")
	grant("team:editors#member", "viewer", "doc:shared")
	grant("group:finance#member", "viewer", "doc:ledger")

	for _, tc := range []struct {
		subject, action, object string
		want                    bool
	}{
		{"user:ann", "edit", "doc:document", true},
		{"user:ann", "view", "doc:document", true},
		{"user:nobody", "edit", "doc:document", false},
		{"user:ann", "view", "doc:folder", true},
		{"user:ann", "view", "doc:doc_in_folder", true},
		{"user:nobody", "view", "doc:doc_in_folder", false},
		{"user:ann", "edit", "doc:doc_in_folder", false},
		{"user:ann", "view", "doc:another_doc", false},
		{"user:bo", "view", "doc:file", true},
		{"user:ann", "view", "doc:file", false},
		{"user:mark", "hold", "level:superadmin", true},
		{"user:mike", "hold", "level:superadmin", false},
		{"user:mark", "update", "resource:topsecret", true},
		{"user:mike", "update", "resource:topsecret", true},
		{"user:mark", "delete", "resource:topsecret", true},
		{"user:mike", "delete", "resource:topsecret", false},
		{"user:sandy", "delete", "resource:topsecret", false},
		{"user:alice", "access", "acl:document", true},
		{"user:mallory", "access", "acl:document", false},
		{"user:mark", "view", "doc:shared", true},
		{"user:bo", "view", "doc:shared", false},
	} {
		st, si, _ := authzen.ParseRef(tc.subject)
		ot, oi, _ := authzen.ParseRef(tc.object)
		e, defined, err := Explain(ctx, conn, orgID, m, st, si, tc.action, ot, oi)
		if err != nil || !defined {
			t.Fatalf("%s %s %s: %v (defined %v)", tc.subject, tc.action, tc.object, err, defined)
		}
		if got := e.Held != "" && e.Refused == ""; got != tc.want {
			t.Errorf("%s %s %s: %v, want %v (%+v)", tc.subject, tc.action, tc.object, got, tc.want, e)
		}
	}

	// How it got there, which is what somebody debugging a grant reads.
	e, _, err := Explain(ctx, conn, orgID, m, "user", "bo", "view", "doc", "file")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.Path, " "); !strings.Contains(got, "doc:file#viewer") ||
		!strings.Contains(got, "doc:folder_a#owner") {
		t.Errorf("the path reads %v", e.Path)
	}

	// A directory group's members are not rows, they are the groups a person is in.
	held, _, err := WalkRelations(ctx, conn, orgID, m, [][2]string{{"user", "x"}, {"group", "finance"}},
		[]string{"viewer"}, "doc", "ledger")
	if err != nil || held != "viewer" {
		t.Errorf("a member of the group holds %q (%v)", held, err)
	}
	if held, _, err := WalkRelations(ctx, conn, orgID, m, [][2]string{{"user", "x"}, {"group", "sales"}},
		[]string{"viewer"}, "doc", "ledger"); err != nil || held != "" {
		t.Errorf("a member of another group holds %q (%v)", held, err)
	}
}

// Only the data can make a loop, so the model cannot refuse one. Visited goals end it.
func TestAFolderThatIsItsOwnParentIsAnAnswer(t *testing.T) {
	orgID, m, grant := walkFixture(t)
	conn := connect(t)
	grant("doc:a", "parent", "doc:b")
	grant("doc:b", "parent", "doc:a")
	grant("doc:c", "parent", "doc:c")
	for _, object := range []string{"a", "c"} {
		held, _, err := WalkRelations(context.Background(), conn, orgID, m, [][2]string{{"user", "x"}},
			[]string{"viewer"}, "doc", object)
		if err != nil || held != "" {
			t.Errorf("%s: held %q, %v", object, held, err)
		}
	}
}

// An expired grant is not a grant on the way there either, or a parent link that
// ran out would go on carrying everything above it.
func TestAnExpiredLinkCarriesNothing(t *testing.T) {
	orgID, m, grant := walkFixture(t)
	conn := connect(t)
	ctx := context.Background()
	grant("user:ann", "owner", "doc:folder")
	past := time.Now().Add(-time.Hour)
	if err := GrantRelation(ctx, conn, orgID, Relation{SubjectType: "doc", SubjectID: "folder", Relation: "parent",
		ObjectType: "doc", ObjectID: "file", ExpiresAt: &past}, ""); err != nil {
		t.Fatal(err)
	}
	if held, _, err := WalkRelations(ctx, conn, orgID, m, [][2]string{{"user", "ann"}}, []string{"viewer"},
		"doc", "file"); err != nil || held != "" {
		t.Errorf("held %q through a link that ended (%v)", held, err)
	}
}

// Deeper or wider than a walk will go is not a no. It is a decision that could not be
// made, and anybody denied by a bound would be told something false about the graph.
func TestAWalkPastItsBoundsIsNotAnAnswer(t *testing.T) {
	orgID, m, grant := walkFixture(t)
	conn := connect(t)
	ctx := context.Background()
	for i := 0; i <= maxWalkDepth+1; i++ {
		grant(fmt.Sprintf("doc:level-%d", i+1), "parent", fmt.Sprintf("doc:level-%d", i))
	}
	_, _, err := WalkRelations(ctx, conn, orgID, m, [][2]string{{"user", "x"}}, []string{"viewer"}, "doc", "level-0")
	if !errors.Is(err, ErrWalkBound) {
		t.Errorf("past the depth: %v", err)
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		SELECT $1::uuid, 'doc', 'wide-' || i, 'parent', 'doc', 'wide' FROM generate_series(1, $2::int) i`,
		orgID, maxWalkEdges+1); err != nil {
		t.Fatal(err)
	}
	_, _, err = WalkRelations(ctx, conn, orgID, m, [][2]string{{"user", "x"}}, []string{"viewer"}, "doc", "wide")
	if !errors.Is(err, ErrWalkBound) {
		t.Errorf("past the width: %v", err)
	}
}

// The model's own refusals, each of which would otherwise be a rule that reads as in
// force and never runs.
func TestAModelCannotNameWhatDoesNotExist(t *testing.T) {
	for name, src := range map[string]string{
		"through a relation it does not have": `
types:
  doc:
    relations: {viewer: [nope->viewer]}
    permissions: {view: [viewer]}`,
		"to a relation no type has": `
types:
  doc:
    relations: {parent: [], viewer: [parent->nothing]}
    permissions: {view: [viewer]}`,
		"also on no action": `
types:
  doc:
    relations: {viewer: []}
    permissions: {view: [viewer]}
    also: {edit: [viewer]}`,
		"except naming no relation": `
types:
  doc:
    relations: {viewer: []}
    permissions: {view: [viewer]}
    except: {view: [banned]}`,
	} {
		if _, err := authzen.ParseModel([]byte(src)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// A file's own tests see the narrowing, as a decision does.
	src := `
types:
  acl:
    relations: {allow: [], deny: []}
    permissions: {access: [allow]}
    except: {access: [deny]}
tests:
  - {name: refused, resource: "acl:a", action: access, relations: [allow, deny], allow: true}`
	if _, err := authzen.ParseModel([]byte(src)); err == nil {
		t.Error("a model test passed against its own except")
	}
}
