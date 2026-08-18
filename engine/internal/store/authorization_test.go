package store

import (
	"context"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
)

// Relations and the facts a decision is made from, against a real database.

func TestARelationIsHeldDirectlyAndThroughAGroup(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	doc := "doc" + itoa(time.Now().UnixNano())

	if err := GrantRelation(ctx, conn, orgID, Relation{
		SubjectType: "user", SubjectID: userID, Relation: "owner",
		ObjectType: "document", ObjectID: doc,
	}, ""); err != nil {
		t.Fatalf("granting: %v", err)
	}

	held, err := HoldsAny(ctx, conn, orgID, "user", userID,
		[]string{"owner", "editor"}, "document", doc, nil)
	if err != nil {
		t.Fatalf("checking: %v", err)
	}
	if held != "owner" {
		t.Fatalf("held = %q, want owner", held)
	}

	// A relation nobody granted must not be held.
	held, err = HoldsAny(ctx, conn, orgID, "user", userID,
		[]string{"viewer"}, "document", doc, nil)
	if err != nil {
		t.Fatalf("checking viewer: %v", err)
	}
	if held != "" {
		t.Fatalf("held = %q for a relation that was never granted", held)
	}

	// Through a group. The caller does not say which groups the subject is in
	// -- we do -- which is the whole reason this lives in the identity provider.
	other := "docg" + itoa(time.Now().UnixNano())
	if err := GrantRelation(ctx, conn, orgID, Relation{
		SubjectType: "group", SubjectID: "finance", Relation: "viewer",
		ObjectType: "document", ObjectID: other,
	}, ""); err != nil {
		t.Fatalf("granting to a group: %v", err)
	}

	held, _ = HoldsAny(ctx, conn, orgID, "user", userID,
		[]string{"viewer"}, "document", other, nil)
	if held != "" {
		t.Fatal("a group grant applied to somebody who is not in the group")
	}
	held, err = HoldsAny(ctx, conn, orgID, "user", userID,
		[]string{"viewer"}, "document", other, []string{"finance"})
	if err != nil {
		t.Fatalf("checking through a group: %v", err)
	}
	if held != "viewer" {
		t.Fatalf("held = %q through group finance, want viewer", held)
	}
}

// An expired grant is not a grant, at the moment it expires -- not at the next
// janitor pass.
func TestAnExpiredRelationStopsWorkingImmediately(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	doc := "docx" + itoa(time.Now().UnixNano())

	soon := time.Now().Add(-time.Second)
	if err := GrantRelation(ctx, conn, orgID, Relation{
		SubjectType: "user", SubjectID: userID, Relation: "owner",
		ObjectType: "document", ObjectID: doc, ExpiresAt: &soon,
	}, ""); err != nil {
		t.Fatalf("granting: %v", err)
	}

	held, err := HoldsAny(ctx, conn, orgID, "user", userID,
		[]string{"owner"}, "document", doc, nil)
	if err != nil {
		t.Fatalf("checking: %v", err)
	}
	if held != "" {
		t.Fatal("an expired relation was still held; temporary access is not temporary")
	}

	// And a grant that has NOT expired still works, so the clause is not simply
	// excluding everything with an expiry.
	later := time.Now().Add(time.Hour)
	if err := GrantRelation(ctx, conn, orgID, Relation{
		SubjectType: "user", SubjectID: userID, Relation: "owner",
		ObjectType: "document", ObjectID: doc, ExpiresAt: &later,
	}, ""); err != nil {
		t.Fatalf("re-granting: %v", err)
	}
	held, _ = HoldsAny(ctx, conn, orgID, "user", userID,
		[]string{"owner"}, "document", doc, nil)
	if held != "owner" {
		t.Fatal("a grant expiring in an hour was treated as expired")
	}
}

// Relations do not cross an organisation. RLS does not catch this: the engine
// is exempt by design and this code runs as the engine.
func TestRelationsDoNotCrossAnOrganisation(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgA, userA, _, _ := fixture(t, conn)
	orgB, _, _, _ := fixture(t, conn)
	doc := "docorg" + itoa(time.Now().UnixNano())

	if err := GrantRelation(ctx, conn, orgA, Relation{
		SubjectType: "user", SubjectID: userA, Relation: "owner",
		ObjectType: "document", ObjectID: doc,
	}, ""); err != nil {
		t.Fatalf("granting: %v", err)
	}

	held, err := HoldsAny(ctx, conn, orgB, "user", userA,
		[]string{"owner"}, "document", doc, nil)
	if err != nil {
		t.Fatalf("checking in the other org: %v", err)
	}
	if held != "" {
		t.Fatal("a relation granted in one organisation answered in another")
	}
}

// The facts come from OUR records. This is the argument for the whole design.
func TestFactsComeFromTheSessionNotTheCaller(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)

	// No session named: nothing was proved in one.
	f, err := SubjectFacts(ctx, conn, orgID, userID, "")
	if err != nil {
		t.Fatalf("reading facts: %v", err)
	}
	if f.MFA || f.FromSession {
		t.Fatal("facts were claimed without a session to read them from")
	}

	pwd := "sid-pwd-" + itoa(time.Now().UnixNano())
	_, err = conn.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, sha256($2::bytea), $3, $4, '1', '{pwd}', now(), now() + interval '1 hour')`,
		pwd, pwd, orgID, userID)
	must(t, err)

	f, err = SubjectFacts(ctx, conn, orgID, userID, pwd)
	if err != nil {
		t.Fatalf("reading facts: %v", err)
	}
	if !f.FromSession {
		t.Fatal("a live session was not read")
	}
	if f.MFA {
		t.Fatal("a password-only session reported a second factor")
	}

	mfa := "sid-mfa-" + itoa(time.Now().UnixNano())
	_, err = conn.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, sha256($2::bytea), $3, $4, '2', '{pwd,otp}', now(), now() + interval '1 hour')`,
		mfa, mfa, orgID, userID)
	must(t, err)

	f, err = SubjectFacts(ctx, conn, orgID, userID, mfa)
	if err != nil {
		t.Fatalf("reading facts: %v", err)
	}
	if !f.MFA {
		t.Fatal("a session with otp in amr did not report a second factor")
	}

	// A REVOKED session proves nothing. Otherwise signing somebody out leaves
	// their authorization decisions intact, which is the difference between
	// revocation and the appearance of it.
	_, err = conn.Exec(ctx,
		`UPDATE core.sessions SET revoked_at = now(), revocation_reason = 'logout'
		  WHERE sid = $1`, mfa)
	must(t, err)

	f, err = SubjectFacts(ctx, conn, orgID, userID, mfa)
	if err != nil {
		t.Fatalf("reading facts after revocation: %v", err)
	}
	if f.FromSession || f.MFA {
		t.Fatal("a revoked session still supplied facts")
	}
}

// A group grant answers "who can read this" with people, not with the group.
func TestSubjectSearchExpandsGroupsToTheirMembers(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	doc := "docs" + itoa(time.Now().UnixNano())
	group := "grp" + itoa(time.Now().UnixNano()%1000000)

	var groupID string
	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1, $2, 'G') RETURNING id::text`, orgID, group).Scan(&groupID))
	_, err := conn.Exec(ctx,
		`INSERT INTO core.group_members (group_id, user_id, org_id) VALUES ($1::uuid,$2::uuid,$3)`,
		groupID, userID, orgID)
	must(t, err)

	if err := GrantRelation(ctx, conn, orgID, Relation{
		SubjectType: "group", SubjectID: group, Relation: "viewer",
		ObjectType: "document", ObjectID: doc,
	}, ""); err != nil {
		t.Fatalf("granting: %v", err)
	}

	subjects, _, err := SubjectsWith(ctx, conn, orgID, []string{"viewer"}, "document", doc, 0, "")
	if err != nil {
		t.Fatalf("searching: %v", err)
	}
	found := false
	for _, s := range subjects {
		if s == userID {
			found = true
		}
		if s == group {
			t.Fatal("the search returned the group itself; the question is about people")
		}
	}
	if !found {
		t.Fatalf("the group's member was not returned; got %v", subjects)
	}
}

func TestTheModelRoundTripsThroughTheDatabase(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, _, _ := fixture(t, conn)

	const src = `
types:
  document:
    relations:
      owner: []
      viewer: [owner]
    permissions:
      read: [viewer]
    require:
      read: {mfa: true}
`
	m, err := authzen.ParseModel([]byte(src))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if err := SaveModel(ctx, conn, orgID, src, m, ""); err != nil {
		t.Fatalf("saving: %v", err)
	}

	loaded, err := LoadModel(ctx, conn, orgID)
	if err != nil || loaded == nil {
		t.Fatalf("loading: %v (%v)", err, loaded)
	}
	rels, ok := loaded.RelationsFor("document", "read")
	if !ok || len(rels) != 2 {
		t.Fatalf("read is granted to %v after a round trip, want owner and viewer", rels)
	}
	// The condition must survive too. A model that loses its conditions grants
	// everything the relation grants, with no second factor and no error.
	if _, has := loaded.ConditionFor("document", "read"); !has {
		t.Fatal("the condition was lost in the round trip")
	}

	// And the source is kept verbatim, so `authz show-model` prints what was
	// written rather than a re-serialisation of what we parsed.
	got, err := ModelSource(ctx, conn, orgID)
	if err != nil {
		t.Fatalf("reading source: %v", err)
	}
	if got != src {
		t.Fatal("the stored source is not what was written")
	}

	// No model at all is nil, not an error and not an empty model -- the
	// decision path treats nil as "nothing is permitted".
	otherOrg, _, _, _ := fixture(t, conn)
	loaded, err = LoadModel(ctx, conn, otherOrg)
	if err != nil {
		t.Fatalf("loading an absent model: %v", err)
	}
	if loaded != nil {
		t.Fatal("an organisation with no model returned one")
	}
}

// AuthZEN §8.2.2: "if a response does not contain the entire result set, it
// MUST include this object [page]" with a next_token.
//
// The first implementation capped at 1000 and returned no token at all. A
// caller with 1001 accessible documents was told about 1000 and had no way to
// know -- which for an authorization search is worse than an error, because a
// truncated answer looks like a complete one.
func TestSearchPagesRatherThanTruncating(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	prefix := "pg" + itoa(time.Now().UnixNano())

	const total = 25
	for i := 0; i < total; i++ {
		// Zero-padded so lexical order matches creation order, which is what
		// keyset pagination walks.
		id := prefix + "-" + pad(i)
		if err := GrantRelation(ctx, conn, orgID, Relation{
			SubjectType: "user", SubjectID: userID, Relation: "owner",
			ObjectType: "pgdoc", ObjectID: id,
		}, ""); err != nil {
			t.Fatalf("granting %s: %v", id, err)
		}
	}

	// Walk it in pages of 10 and reassemble.
	seen := map[string]bool{}
	after := ""
	pages := 0
	for {
		ids, more, err := ObjectsWith(ctx, conn, orgID, "user", userID,
			[]string{"owner"}, "pgdoc", nil, 10, after)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		for _, id := range ids {
			if seen[id] {
				t.Fatalf("%s appeared on two pages", id)
			}
			seen[id] = true
		}
		if !more {
			break
		}
		if len(ids) == 0 {
			t.Fatal("more results were promised but none returned; this loops forever")
		}
		after = ids[len(ids)-1]
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}

	if len(seen) != total {
		t.Fatalf("walked %d objects across %d pages, want %d -- results were "+
			"lost or duplicated between pages", len(seen), pages, total)
	}
	if pages != 3 {
		t.Fatalf("took %d pages for %d results at 10 per page, want 3", pages, total)
	}

	// The last page must say there is no more. Without that signal a caller
	// cannot tell "this is the end" from "the token was lost".
	_, more, err := ObjectsWith(ctx, conn, orgID, "user", userID,
		[]string{"owner"}, "pgdoc", nil, 10, prefix+"-"+pad(total-1))
	if err != nil {
		t.Fatal(err)
	}
	if more {
		t.Fatal("the page after the last one still reported more results")
	}
}

func pad(n int) string {
	s := itoa(int64(n))
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}
