package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/store/storetest"
)

// delegationSubject is the person a drift route's body names, by grantee.
var delegationSubject = map[string]string{}

func newDriftDelegation(t *testing.T, s *Server) store.RelationDelegation {
	t.Helper()
	d := store.RelationDelegation{OrgID: newDriftOrg(t, s), GranteeOrgID: newDriftOrg(t, s), ObjectType: "app",
		ObjectID: store.EveryObject, Relations: []string{"user"}}
	id, err := store.NewRelationDelegation(context.Background(), s.db, d)
	if err != nil {
		t.Fatal(err)
	}
	d.ID = id
	return d
}

func newDelegationPerson(t *testing.T, s *Server, org string) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, gen_random_uuid()::text || '@example.test',
		        sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea))
		RETURNING id::text`, org).Scan(&id); err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, s.db, org)
	return id
}

// The whole of it, from both sides of the boundary: an operator delegates, the
// grantee hands out only what it was given and only to its own people, the owner's
// decisions see it, and every way it can end ends it.
func TestAnOrganisationHandsOutWhatAnotherDelegated(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	owner, grantee, third := newDriftOrg(t, s), newDriftOrg(t, s), newDriftOrg(t, s)
	scopes := []string{ScopeRelationsRead, ScopeRelationsWrite}
	ownerToken := mintToken(t, s, "owner-"+owner, owner, scopes, nil)
	granteeToken := mintToken(t, s, "grantee-"+grantee, grantee, scopes, nil)
	thirdToken := mintToken(t, s, "third-"+third, third, scopes, nil)
	person, stranger, ownPerson := newDelegationPerson(t, s, grantee), newDelegationPerson(t, s, third),
		newDelegationPerson(t, s, owner)
	base := "/admin/organizations/" + owner + "/relation-delegations"
	body := map[string]any{"grantee_org_id": grantee, "object": "document:42", "relations": []string{"viewer", "editor"}}

	// No tenant reaches across on its own say, not even the owner.
	for name, token := range map[string]string{"the owner": ownerToken, "the grantee": granteeToken} {
		if rec := call(t, s, http.MethodPost, base, token, body); rec.Code != http.StatusForbidden {
			t.Errorf("%s's token delegated: %d %s", name, rec.Code, rec.Body)
		}
	}
	for _, bad := range []map[string]any{
		{"grantee_org_id": owner, "object": "document:42", "relations": []string{"viewer"}},
		{"grantee_org_id": grantee, "object": "document", "relations": []string{"viewer"}},
		{"grantee_org_id": grantee, "object": "document:42", "relations": []string{}},
		{"grantee_org_id": grantee, "object": "document:42", "relations": []string{"Not A Name"}},
	} {
		if rec := call(t, s, http.MethodPost, base, testToken, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v answered %d: %s", bad, rec.Code, rec.Body)
		}
	}
	rec := call(t, s, http.MethodPost, base, testToken, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("delegating answered %d: %s", rec.Code, rec.Body)
	}
	got, err := store.RelationDelegationsOf(ctx, s.db, grantee)
	if err != nil || len(got) != 1 {
		t.Fatalf("the grantee's delegations are %+v, %v", got, err)
	}
	id := got[0].ID
	ofGrantee := "/admin/organizations/" + grantee + "/relation-delegations/" + id + "/relations"
	ofOwner := base + "/" + id + "/relations"

	// Both sides see it, and nobody else does.
	for name, c := range map[string]struct{ org, token string }{"owner": {owner, ownerToken}, "grantee": {grantee, granteeToken}} {
		rec := call(t, s, http.MethodGet, "/admin/organizations/"+c.org+"/relation-delegations", c.token, nil)
		if !strings.Contains(rec.Body.String(), id) {
			t.Errorf("the %s does not see it: %s", name, rec.Body)
		}
	}
	rec = call(t, s, http.MethodGet, "/admin/organizations/"+third+"/relation-delegations", thirdToken, nil)
	if strings.Contains(rec.Body.String(), id) {
		t.Errorf("a third organisation sees it: %s", rec.Body)
	}

	grant := func(path, token, subject, relation, object string) int {
		t.Helper()
		return call(t, s, http.MethodPut, path, token, map[string]any{"subject": "user:" + subject,
			"relation": relation, "object": object}).Code
	}
	for name, c := range map[string]struct {
		path, token, subject, relation, object string
		want                                   int
	}{
		"a relation it was not given":    {ofGrantee, granteeToken, person, "owner", "document:42", http.StatusForbidden},
		"another object":                 {ofGrantee, granteeToken, person, "viewer", "document:43", http.StatusForbidden},
		"another type":                   {ofGrantee, granteeToken, person, "viewer", "folder:42", http.StatusForbidden},
		"somebody of another":            {ofGrantee, granteeToken, stranger, "viewer", "document:42", http.StatusForbidden},
		"somebody of the owner":          {ofGrantee, granteeToken, ownPerson, "viewer", "document:42", http.StatusForbidden},
		"a person named by address":      {ofGrantee, granteeToken, "alice@example.test", "viewer", "document:42", http.StatusForbidden},
		"the owner, through its side":    {ofOwner, ownerToken, person, "viewer", "document:42", http.StatusNotFound},
		"a third, through the grantee's": {ofGrantee, thirdToken, person, "viewer", "document:42", http.StatusForbidden},
	} {
		if got := grant(c.path, c.token, c.subject, c.relation, c.object); got != c.want {
			t.Errorf("%s answered %d, want %d", name, got, c.want)
		}
	}
	if rows, _ := store.DelegatedRelations(ctx, s.db, got[0]); len(rows) != 0 {
		t.Fatalf("a refused grant was stored: %+v", rows)
	}

	if code := grant(ofGrantee, granteeToken, person, "viewer", "document:42"); code != http.StatusOK {
		t.Fatalf("handing it out answered %d", code)
	}

	// The owner's decision reads its own table, and finds the grantee's person.
	holds := func(relation string) bool {
		t.Helper()
		held, err := store.HoldsAny(ctx, s.db, owner, "user", person, []string{relation}, "document", "42", nil)
		if err != nil {
			t.Fatal(err)
		}
		return held != ""
	}
	if !holds("viewer") {
		t.Fatal("the owner's decision does not see a delegated relation")
	}
	if held, _ := store.HoldsAny(ctx, s.db, grantee, "user", person, []string{"viewer"}, "document", "42", nil); held != "" {
		t.Error("the relation landed in the grantee rather than the owner")
	}

	// What it reads back is what it handed out, and none of the owner's others.
	if err := store.GrantRelation(ctx, s.db, owner, store.Relation{SubjectType: "user", SubjectID: "the-owners-secret",
		Relation: "viewer", ObjectType: "document", ObjectID: "42"}, ""); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodGet, ofGrantee, granteeToken, nil); !strings.Contains(rec.Body.String(), person) ||
		strings.Contains(rec.Body.String(), "the-owners-secret") {
		t.Errorf("the grantee reads %s", rec.Body)
	}
	if rec := call(t, s, http.MethodGet, ofGrantee, thirdToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a third read what was handed out: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, http.MethodGet, "/admin/organizations/"+grantee+"/relations", granteeToken, nil); strings.Contains(rec.Body.String(), "document:42") {
		t.Errorf("the grantee's relations show the owner's: %s", rec.Body)
	}

	// A relation the owner gave them itself is not the delegation's to take away.
	if err := store.GrantRelation(ctx, s.db, owner, store.Relation{SubjectType: "user", SubjectID: person,
		Relation: "editor", ObjectType: "document", ObjectID: "42"}, ""); err != nil {
		t.Fatal(err)
	}
	if code := grant(ofGrantee, granteeToken, person, "editor", "document:42"); code != http.StatusOK {
		t.Fatalf("handing out what the owner already gave answered %d", code)
	}
	revoke := func(token, relation string) int {
		t.Helper()
		q := url.Values{"subject": {"user:" + person}, "relation": {relation}, "object": {"document:42"}}
		return call(t, s, http.MethodDelete, ofGrantee+"?"+q.Encode(), token, nil).Code
	}
	if code := revoke(granteeToken, "editor"); code != http.StatusNotFound {
		t.Errorf("the grantee revoked what the owner gave: %d", code)
	}
	if !holds("editor") {
		t.Error("what the owner gave went with the grantee's revocation")
	}
	if code := revoke(granteeToken, "viewer"); code != http.StatusOK {
		t.Errorf("revoking answered %d", code)
	}
	if holds("viewer") {
		t.Error("a revoked relation is still held")
	}

	// Taking the delegation away takes what was handed out, and only that.
	if code := grant(ofGrantee, granteeToken, person, "viewer", "document:42"); code != http.StatusOK {
		t.Fatalf("handing it out again answered %d", code)
	}
	if rec := call(t, s, http.MethodDelete, base+"/"+id, ownerToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token took a delegation away: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, http.MethodDelete, base+"/"+id, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing it answered %d: %s", rec.Code, rec.Body)
	}
	if holds("viewer") {
		t.Error("a relation outlived the delegation it was handed out under")
	}
	if !holds("editor") {
		t.Error("taking the delegation away took what the owner gave")
	}
	if code := grant(ofGrantee, granteeToken, person, "viewer", "document:42"); code != http.StatusNotFound {
		t.Errorf("handing out under a removed delegation answered %d", code)
	}
}

// A person who goes takes what they held elsewhere with them.
func TestADeletedPersonLosesWhatWasDelegatedToThem(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	d := newDriftDelegation(t, s)
	person := newDelegationPerson(t, s, d.GranteeOrgID)
	if err := store.GrantDelegated(ctx, s.db, d, store.Relation{SubjectType: "user", SubjectID: person,
		Relation: "user", ObjectType: "app", ObjectID: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, person); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.DelegatedRelations(ctx, s.db, d); err != nil || len(rows) != 0 {
		t.Errorf("a deleted person still holds %s: %+v, %v", fmt.Sprint(d.ID), rows, err)
	}
}

// The every-object form is what a software company hands a customer, and it covers
// the type it names and no other.
func TestADelegationOfEveryObjectCoversItsTypeAlone(t *testing.T) {
	d := store.RelationDelegation{ObjectType: "app", ObjectID: store.EveryObject, Relations: []string{"user"}}
	if !d.Covers("user", "app", "anything") {
		t.Error("every object of the type is not covered")
	}
	if d.Covers("user", "folder", "anything") || d.Covers("admin", "app", "anything") {
		t.Error("a delegation covers what it does not name")
	}
	one := store.RelationDelegation{ObjectType: "app", ObjectID: "one", Relations: []string{"user"}}
	if one.Covers("user", "app", store.EveryObject) {
		t.Error("asking for the literal * reached every object")
	}
}
