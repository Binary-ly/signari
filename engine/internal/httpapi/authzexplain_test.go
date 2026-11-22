package httpapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
)

// What an operator is told about a question is what a decision answers, for every
// way a subject can come to hold a relation and for each way they cannot. The
// command answered by its own walk and did not try the resolved id, so a person
// asked about by address, holding a grant by id, read as DENIED and was allowed.
func TestAnExplanationAgreesWithTheDecision(t *testing.T) {
	a := newAuthzProviderFixture(t)
	ctx := context.Background()
	f := a.f
	var person string
	if err := f.pool.QueryRow(ctx, `SELECT email FROM core.users WHERE id = $1::uuid`, f.userID).Scan(&person); err != nil {
		t.Fatal(err)
	}
	groupName := fmt.Sprintf("explain-%d", time.Now().UnixNano())
	var group string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, 'E') RETURNING id::text`, f.orgID, groupName).Scan(&group); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.groups WHERE id = $1::uuid`, group)
	})
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id, expires_at)
		VALUES ($1::uuid, 'group', $4, 'owner', 'doc', 'by-group', NULL),
		       ($1::uuid, 'user', $2, 'owner', 'doc', 'by-id', NULL),
		       ($1::uuid, 'user', $3, 'owner', 'doc', 'by-address', NULL),
		       ($1::uuid, 'user', $2, 'owner', 'doc', 'expired', now() - interval '1 minute')`,
		f.orgID, f.userID, person, groupName); err != nil {
		t.Fatal(err)
	}
	model, err := store.LoadModel(ctx, f.pool, f.orgID)
	if err != nil || model == nil {
		t.Fatalf("no model: %v", err)
	}

	checked := 0
	for _, subject := range []string{person, f.userID, a.subject, "nobody-we-know"} {
		for _, resource := range []string{"by-group", "by-id", "by-address", "expired", a.resource, "absent"} {
			e, defined, err := store.Explain(ctx, f.pool, f.orgID, model, "user", subject, "can_edit", "doc", resource)
			if err != nil || !defined {
				t.Fatalf("explaining: %v, %v", defined, err)
			}
			got, derr := f.srv.decide(ctx, f.orgID, authzen.Request{
				Subject:  authzen.Subject{Type: "user", ID: subject},
				Action:   authzen.Action{Name: "can_edit"},
				Resource: authzen.Resource{Type: "doc", ID: resource}})
			if derr != nil {
				t.Fatal(derr)
			}
			if (e.Held != "") != got.Decision {
				t.Errorf("%s on %s: the explanation holds %q (%s), the decision says %v", subject, resource, e.Held, e.Via, got.Decision)
			}
			if got.Decision {
				checked++
			}
		}
	}
	if checked != 6 {
		t.Errorf("%d questions were allowed, want 6", checked)
	}

	e, _, err := store.Explain(ctx, f.pool, f.orgID, model, "user", person, "can_edit", "doc", "by-group")
	if err != nil || e.Via != "group:"+groupName {
		t.Errorf("the grant through a group reads as %q, %v", e.Via, err)
	}
	e, _, err = store.Explain(ctx, f.pool, f.orgID, model, "user", person, "can_edit", "doc", "by-id")
	if err != nil || e.Via != "user:"+f.userID {
		t.Errorf("the grant by id reads as %q, %v", e.Via, err)
	}

	rows, more, err := store.ListRelations(ctx, f.pool, f.orgID, "user", f.userID, "", "", 10)
	if err != nil || more || len(rows) != 1 || rows[0].Object != "doc:by-id" {
		t.Errorf("a person's live relations read %+v, more %v, %v", rows, more, err)
	}
	rows, more, err = store.ListRelations(ctx, f.pool, f.orgID, "", "", "doc", "by-group", 10)
	if err != nil || more || len(rows) != 1 || rows[0].Subject != "group:"+groupName {
		t.Errorf("an object's relations read %+v, more %v, %v", rows, more, err)
	}
	if _, more, err = store.ListRelations(ctx, f.pool, f.orgID, "", "", "", "", 1); err != nil || !more {
		t.Errorf("a listing cut short said more %v, %v", more, err)
	}
}
