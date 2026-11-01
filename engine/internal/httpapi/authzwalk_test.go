package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"signari.dev/engine/internal/authzen"
)

// newWalkingModel gives the fixture a model with a relation through a parent, and a
// document held by a set of subjects on a model that says nothing about sets.
func newWalkingModel(t *testing.T) *authzProviderFixture {
	t.Helper()
	a := newAuthzProviderFixture(t)
	model := authzen.Model{Types: map[string]authzen.Type{
		"doc": {
			Relations: map[string][]string{"owner": nil, "parent": nil, "viewer": {"owner", "parent->viewer"},
				"banned": nil},
			Permissions: map[string][]string{"can_edit": {"owner"}, "can_view": {"viewer"}},
			Except:      map[string][]string{"can_view": {"banned"}},
		},
		"team": {Relations: map[string][]string{"member": nil}},
		"page": {
			Relations:   map[string][]string{"reader": nil},
			Permissions: map[string][]string{"can_read": {"reader"}},
		},
	}}
	compiled, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := a.f.pool.Exec(ctx, `UPDATE core.authorization_models SET compiled = $2::jsonb WHERE org_id = $1::uuid`,
		a.f.orgID, compiled); err != nil {
		t.Fatal(err)
	}
	for _, r := range [][5]string{
		{"user", "ann", "owner", "doc", "folder"},
		{"doc", "folder", "parent", "doc", "report"},
		{"user", "bea", "owner", "doc", "folder"},
		{"user", "bea", "banned", "doc", "report"},
		{"user", "cal", "member", "team", "eng"},
		{"team", "eng#member", "reader", "page", "handbook"},
	} {
		if _, err := a.f.pool.Exec(ctx, `
			INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)`, a.f.orgID, r[0], r[1], r[2], r[3], r[4]); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func (a *authzProviderFixture) decision(t *testing.T, subject, action, typ, id string) bool {
	t.Helper()
	body := fmt.Sprintf(`{"subject":{"type":"user","id":%q},"action":{"name":%q},"resource":{"type":%q,"id":%q}}`,
		subject, action, typ, id)
	var out struct {
		Decision bool `json:"decision"`
	}
	if err := json.Unmarshal(a.post(t, "/access/v1/evaluation", body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Decision
}

// Through the endpoint an application calls: what the store's tests say about the
// walk, reached from a real decision, one at a time and in a batch.
func TestAnEvaluationFollowsTheModelAcrossObjects(t *testing.T) {
	a := newWalkingModel(t)
	for _, tc := range []struct {
		subject, action, typ, id string
		want                     bool
	}{
		{"ann", "can_view", "doc", "folder", true},
		{"ann", "can_view", "doc", "report", true},
		{"ann", "can_edit", "doc", "report", false},
		{"eve", "can_view", "doc", "report", false},
		{"bea", "can_view", "doc", "folder", true},
		{"bea", "can_view", "doc", "report", false},
		{"cal", "can_read", "page", "handbook", true},
		{"eve", "can_read", "page", "handbook", false},
	} {
		if got := a.decision(t, tc.subject, tc.action, tc.typ, tc.id); got != tc.want {
			t.Errorf("%s %s %s:%s answered %v", tc.subject, tc.action, tc.typ, tc.id, got)
		}
	}

	// A batch reads ahead, which has to leave these standing: a subject set on an
	// object the model says nothing about is only found in what it read.
	raw := a.post(t, "/access/v1/evaluations", `{"subject":{"type":"user","id":"cal"},"evaluations":[
		{"action":{"name":"can_read"},"resource":{"type":"page","id":"handbook"}},
		{"action":{"name":"can_view"},"resource":{"type":"doc","id":"report"}}]}`)
	var batch struct {
		Evaluations []struct {
			Decision bool `json:"decision"`
		} `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil || len(batch.Evaluations) != 2 {
		t.Fatalf("the batch answered %s", raw)
	}
	if !batch.Evaluations[0].Decision || batch.Evaluations[1].Decision {
		t.Errorf("the batch answered %s", raw)
	}
}

// A search gives the answers a decision gives. A document held through its folder has
// no row naming the person, so a search starting from rows naming them finds nothing,
// and an application listing what somebody can see would disagree with itself.
func TestASearchFindsWhatADecisionWould(t *testing.T) {
	a := newWalkingModel(t)
	found := func(raw []byte) string {
		t.Helper()
		var out struct {
			Results []struct {
				ID string `json:"id"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, r := range out.Results {
			ids = append(ids, r.ID)
		}
		return strings.Join(ids, " ")
	}
	got := found(a.post(t, "/access/v1/search/resource", `{"subject":{"type":"user","id":"ann"},
		"action":{"name":"can_view"},"resource":{"type":"doc"}}`))
	if !strings.Contains(got, "report") || !strings.Contains(got, "folder") {
		t.Errorf("ann may view %q", got)
	}
	got = found(a.post(t, "/access/v1/search/resource", `{"subject":{"type":"user","id":"bea"},
		"action":{"name":"can_view"},"resource":{"type":"doc"}}`))
	if strings.Contains(got, "report") {
		t.Errorf("a person the action excepts was listed: %q", got)
	}
	got = found(a.post(t, "/access/v1/search/subject", `{"subject":{"type":"user"},
		"action":{"name":"can_view"},"resource":{"type":"doc","id":"report"}}`))
	if !strings.Contains(got, "ann") || strings.Contains(got, "bea") || strings.Contains(got, "eve") {
		t.Errorf("those who may view the report: %q", got)
	}
	got = found(a.post(t, "/access/v1/search/subject", `{"subject":{"type":"user"},
		"action":{"name":"can_read"},"resource":{"type":"page","id":"handbook"}}`))
	if !strings.Contains(got, "cal") {
		t.Errorf("those who may read the handbook: %q", got)
	}
}
