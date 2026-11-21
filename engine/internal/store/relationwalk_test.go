package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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

// walkStatements counts what a walk asks.
type walkStatements struct {
	q Querier
	n int
}

func (w *walkStatements) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	w.n++
	return w.q.Query(ctx, sql, args...)
}

// The questions of one request that meet the same folders walk them once (E.17): a
// document nine folders down costs a statement a folder, and a hundred in one folder
// cost that a hundred times over before. What a walk settles, held along the path it
// found and not held wherever it looked and found nothing, answers the next walk of the
// same subjects; another set of subjects is not answered by it.
func TestARequestsWalksMeetTheSameFoldersOnce(t *testing.T) {
	orgID, m, grant := walkFixture(t)
	conn := connect(t)
	ctx := context.Background()
	for n := 0; n < 8; n++ {
		grant(fmt.Sprintf("doc:memo-f%d", n+1), "parent", fmt.Sprintf("doc:memo-f%d", n))
	}
	grant("user:memo-boss", "owner", "doc:memo-f8")
	for i := 0; i < 10; i++ {
		grant("doc:memo-f0", "parent", fmt.Sprintf("doc:memo-leaf%d", i))
	}
	boss, nobody := [][2]string{{"user", "memo-boss"}}, [][2]string{{"user", "memo-nobody"}}
	counted := &walkStatements{q: conn}
	memo := NewWalkMemo()
	walk := func(who [][2]string, leaf int) (string, int) {
		t.Helper()
		before := counted.n
		held, _, err := WalkRelationsWith(ctx, counted, orgID, m, who, []string{"viewer"}, "doc",
			fmt.Sprintf("memo-leaf%d", leaf), memo)
		if err != nil {
			t.Fatal(err)
		}
		return held, counted.n - before
	}

	held, first := walk(boss, 0)
	if held != "viewer" || first < 9 {
		t.Fatalf("the first walk held %q in %d statements, want viewer in nine or more", held, first)
	}
	for leaf := 1; leaf < 10; leaf++ {
		if held, n := walk(boss, leaf); held != "viewer" || n > 1 {
			t.Errorf("leaf %d: held %q in %d statements, want viewer in one", leaf, held, n)
		}
	}
	// Nobody's first walk is a walk of its own, all the way up, and finds nothing; the
	// next stops at the first folder it already knows is not theirs.
	if held, n := walk(nobody, 0); held != "" || n < 9 {
		t.Errorf("another subject's first walk held %q in %d statements, want nothing after walking", held, n)
	}
	if held, n := walk(nobody, 1); held != "" || n > 1 {
		t.Errorf("another subject's second walk held %q in %d statements, want nothing in one", held, n)
	}
	// And the boss's answers are untouched by what was settled for nobody.
	if held, _ := walk(boss, 2); held != "viewer" {
		t.Errorf("the boss read %q after nobody's walks", held)
	}
	// Without a memo every walk is the whole way up, as before.
	before := counted.n
	if held, _, err := WalkRelations(ctx, counted, orgID, m, boss, []string{"viewer"}, "doc", "memo-leaf3"); err != nil || held != "viewer" {
		t.Fatalf("without a memo: %q %v", held, err)
	}
	if n := counted.n - before; n < 9 {
		t.Errorf("a walk with no memo asked %d statements, want the whole way up", n)
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

// A batch's walks take their first step together (E.17). A relation that step finds
// nothing behind is settled as not held, and its walk then asks nothing at all; one
// with something behind it, a row of its own or a parent to go through, is left to its
// walk, which answers as it did without the step. A step read to the edge bound settles
// nothing, since an answer cut short cannot say a relation has nothing behind it.
func TestABatchsWalksTakeTheirFirstStepTogether(t *testing.T) {
	orgID, m, grant := walkFixture(t)
	conn := connect(t)
	ctx := context.Background()
	grant("user:step-ann", "owner", "doc:step-mine")
	grant("user:step-ann", "owner", "doc:step-folder")
	grant("doc:step-folder", "parent", "doc:step-inside")
	ann := [][2]string{{"user", "step-ann"}}
	ids := []string{"step-mine", "step-inside"}
	for i := 0; i < 10; i++ {
		ids = append(ids, fmt.Sprintf("step-none%d", i))
	}
	var roots []WalkRoot
	for _, id := range ids {
		roots = append(roots, WalkRoot{Type: "doc", ID: id, Relations: []string{"viewer"}})
	}

	// What each answers with no first step, a walk of its own each.
	want := map[string]string{}
	for _, id := range ids {
		held, _, err := WalkRelations(ctx, conn, orgID, m, ann, []string{"viewer"}, "doc", id)
		if err != nil {
			t.Fatal(err)
		}
		want[id] = held
	}
	if want["step-mine"] == "" || want["step-inside"] == "" || want["step-none0"] != "" {
		t.Fatalf("the fixture answers %v", want)
	}

	counted := &walkStatements{q: conn}
	memo := NewWalkMemo()
	if err := SettleUnreached(ctx, counted, orgID, m, ann, roots, memo); err != nil {
		t.Fatal(err)
	}
	if counted.n != 1 {
		t.Fatalf("twelve first steps took %d statements, want one", counted.n)
	}
	for _, id := range ids {
		before := counted.n
		held, _, err := WalkRelationsWith(ctx, counted, orgID, m, ann, []string{"viewer"}, "doc", id, memo)
		if err != nil {
			t.Fatal(err)
		}
		if held != want[id] {
			t.Errorf("%s held %q after the first step, %q without it", id, held, want[id])
		}
		asked := counted.n - before
		switch {
		case want[id] == "" && asked != 0:
			t.Errorf("%s, with nothing behind it, still asked %d statements", id, asked)
		case want[id] != "" && asked == 0:
			t.Errorf("%s, held, was answered without its walk", id)
		}
	}

	// Read to the edge bound, the step settles nothing: 2,001 parents of one document
	// fill it, and a document with nothing behind it is then walked as before.
	if _, err := conn.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation,
		object_type, object_id) SELECT $1::uuid, 'doc', 'step-p' || i, 'parent', 'doc', 'step-wide'
		FROM generate_series(1, $2::int) i`, orgID, maxWalkEdges+1); err != nil {
		t.Fatal(err)
	}
	memo = NewWalkMemo()
	wide := []WalkRoot{{Type: "doc", ID: "step-wide", Relations: []string{"viewer"}},
		{Type: "doc", ID: "step-none0", Relations: []string{"viewer"}}}
	if err := SettleUnreached(ctx, conn, orgID, m, ann, wide, memo); err != nil {
		t.Fatal(err)
	}
	before := counted.n
	if held, _, err := WalkRelationsWith(ctx, counted, orgID, m, ann, []string{"viewer"}, "doc", "step-none0", memo); err != nil || held != "" {
		t.Fatalf("step-none0 after a cut-short step: %q %v", held, err)
	}
	if counted.n == before {
		t.Error("a step cut short at the edge bound settled a relation it could not have read all of")
	}
}
