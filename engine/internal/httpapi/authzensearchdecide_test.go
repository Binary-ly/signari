package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// AuthZEN's resource and subject searches answered from the relation graph
// alone. The action's condition, the operator's provider veto and everything
// else an evaluation checks were skipped, so a search listed documents an
// evaluation of the same triple refused. The property held here is the one a
// PEP relies on: everything a search returns, an evaluation allows.

type searchDecideFixture struct {
	f        *tokenFixture
	token    string
	docs     []string
	inactive string
}

func newSearchDecideFixture(t *testing.T) *searchDecideFixture {
	t.Helper()
	f := newTokenFixture(t)
	sf := &searchDecideFixture{f: f, token: newPDPCaller(t, f)}
	ctx := context.Background()

	model := `{"types":{"document":{"relations":{"reader":null},
	           "permissions":{"can_read":["reader"],"can_edit":["reader"],"can_view":["reader"]},
	           "require":{"can_edit":{"mfa":true},"can_view":{"subject_active":true}}}}}`
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.authorization_models (org_id, source, compiled)
		VALUES ($1::uuid, '# search decide test', $2::jsonb)
		ON CONFLICT (org_id) DO UPDATE SET compiled = $2::jsonb`, f.orgID, model); err != nil {
		t.Fatal(err)
	}

	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, status, user_handle)
		VALUES ($1::uuid, 'gone-' || gen_random_uuid() || '@example.test', 'deactivated',
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text), 'hex'))
		RETURNING id::text`, f.orgID).Scan(&sf.inactive); err != nil {
		t.Fatal(err)
	}
	n := time.Now().UnixNano()
	for i := 0; i < 3; i++ {
		doc := fmt.Sprintf("doc-%d-%d", n, i)
		sf.docs = append(sf.docs, doc)
		for _, who := range []string{f.userID, sf.inactive} {
			if err := store.GrantRelation(ctx, f.pool, f.orgID, store.Relation{
				SubjectType: "user", SubjectID: who, Relation: "reader",
				ObjectType: "document", ObjectID: doc}, ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	return sf
}

func (sf *searchDecideFixture) allowed(t *testing.T, subject, action, doc string) bool {
	t.Helper()
	code, body := postAuthz(t, sf.f, sf.token, "/access/v1/evaluation", fmt.Sprintf(
		`{"subject":{"type":"user","id":%q},"action":{"name":%q},
		  "resource":{"type":"document","id":%q}}`, subject, action, doc))
	if code != http.StatusOK {
		t.Fatalf("evaluation answered %d: %v", code, body)
	}
	d, _ := body["decision"].(bool)
	return d
}

func results(body map[string]any) []string {
	var out []string
	items, _ := body["results"].([]any)
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				out = append(out, id)
			}
		}
	}
	return out
}

func TestEveryResourceASearchReturnsIsOneAnEvaluationAllows(t *testing.T) {
	sf := newSearchDecideFixture(t)
	for _, action := range []string{"can_read", "can_edit"} {
		code, body := postAuthz(t, sf.f, sf.token, "/access/v1/search/resource", fmt.Sprintf(
			`{"subject":{"type":"user","id":%q},"action":{"name":%q},"resource":{"type":"document"}}`,
			sf.f.userID, action))
		if code != http.StatusOK {
			t.Fatalf("%s: search answered %d: %v", action, code, body)
		}
		got := results(body)
		for _, doc := range got {
			if !sf.allowed(t, sf.f.userID, action, doc) {
				t.Errorf("%s: the search returned %s, which an evaluation of the same "+
					"subject and action refuses", action, doc)
			}
		}
		// The control: without a condition, the person's documents are found.
		if action == "can_read" && len(got) < len(sf.docs) {
			t.Errorf("can_read found %d of the person's %d documents", len(got), len(sf.docs))
		}
	}
}

func TestEverySubjectASearchReturnsIsOneAnEvaluationAllows(t *testing.T) {
	sf := newSearchDecideFixture(t)
	code, body := postAuthz(t, sf.f, sf.token, "/access/v1/search/subject", fmt.Sprintf(
		`{"subject":{"type":"user"},"action":{"name":"can_view"},
		  "resource":{"type":"document","id":%q}}`, sf.docs[0]))
	if code != http.StatusOK {
		t.Fatalf("search answered %d: %v", code, body)
	}
	got := results(body)
	for _, who := range got {
		if !sf.allowed(t, who, "can_view", sf.docs[0]) {
			t.Errorf("the search returned subject %s, whom an evaluation refuses", who)
		}
		if who == sf.inactive {
			t.Error("a deactivated account was listed for an action that requires an active one")
		}
	}
	found := false
	for _, who := range got {
		found = found || who == sf.f.userID
	}
	if !found {
		t.Error("the active reader was not found")
	}
}
