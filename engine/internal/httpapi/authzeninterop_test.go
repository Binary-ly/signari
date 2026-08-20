package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"signari.dev/engine/internal/authzen"
)

func TestAuthZENInteropSuite(t *testing.T) {
	path := os.Getenv("SIGNARI_AUTHZEN_INTEROP")
	if path == "" {
		t.Skip("SIGNARI_AUTHZEN_INTEROP not set; see the comment for where to get " +
			"decisions-authorization-api-1_0-02.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the interop suite: %v", err)
	}
	var suite struct {
		Evaluation []struct {
			Request  authzen.Request `json:"request"`
			Expected bool            `json:"expected"`
		} `json:"evaluation"`
		Evaluations []struct {
			Request  json.RawMessage `json:"request"`
			Expected []struct {
				Decision bool `json:"decision"`
			} `json:"expected"`
		} `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("parsing the interop suite: %v", err)
	}

	f := newTokenFixture(t)
	token := newPDPCaller(t, f)
	ctx := context.Background()

	// The model. `can_update_todo` and `can_delete_todo` are granted by either
	// `owner` or `admin`; the flattening described above decides which tuples
	// exist.
	model := authzen.Model{Types: map[string]authzen.Type{
		"user": {
			Relations:   map[string][]string{"reader": nil},
			Permissions: map[string][]string{"can_read_user": {"reader"}},
		},
		"todo": {
			Relations: map[string][]string{
				"reader": nil, "creator": nil, "owner": nil, "admin": nil,
			},
			Permissions: map[string][]string{
				"can_read_todos":  {"reader"},
				"can_create_todo": {"creator"},
				"can_update_todo": {"owner", "admin"},
				"can_delete_todo": {"owner", "admin"},
			},
		},
	}}
	compiled, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.authorization_models (org_id, source, compiled)
		VALUES ($1::uuid, $2, $3::jsonb)
		ON CONFLICT (org_id) DO UPDATE SET source = $2, compiled = $3::jsonb`,
		f.orgID, "# AuthZEN interop suite\n", compiled); err != nil {
		t.Fatalf("storing the model: %v", err)
	}

	const (
		rick   = "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
		morty  = "CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
		summer = "CiRmZDI2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
		beth   = "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
		jerry  = "CiRmZDQ2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"

		todoRick   = "7240d0db-8ff0-41ec-98b2-34a096273b92"
		todoMorty  = "7240d0db-8ff0-41ec-98b2-34a096273b91"
		todoSummer = "7240d0db-8ff0-41ec-98b2-34a096273b93"
		todoBeth   = "7240d0db-8ff0-41ec-98b2-34a096273b94"
		todoJerry  = "7240d0db-8ff0-41ec-98b2-34a096273b95"
	)
	everyone := []string{rick, morty, summer, beth, jerry}
	editors := []string{rick, morty, summer} // may create
	allTodos := []string{todoRick, todoMorty, todoSummer, todoBeth, todoJerry}

	type tuple struct{ sub, rel, otype, oid string }
	var tuples []tuple
	for _, u := range everyone {
		// can_read_user: every user, on every user object in the suite.
		for _, target := range []string{
			"beth@the-smiths.com", "rick@the-citadel.com", "morty@the-citadel.com",
			"summer@the-smiths.com", "jerry@the-smiths.com",
		} {
			tuples = append(tuples, tuple{u, "reader", "user", target})
		}
		tuples = append(tuples, tuple{u, "reader", "todo", "todo-1"})
	}
	for _, u := range editors {
		tuples = append(tuples, tuple{u, "creator", "todo", "todo-1"})
	}
	// The flattened conjunction: an `owner` tuple exists only where the owner is
	// also permitted to edit. beth and jerry own todos and get none, which is
	// what makes their own-todo cases deny.
	tuples = append(tuples,
		tuple{morty, "owner", "todo", todoMorty},
		tuple{summer, "owner", "todo", todoSummer},
		tuple{rick, "owner", "todo", todoRick},
	)
	// admin: rick, on every todo. The per-object rows are the cost of having no
	// wildcard — HoldsAny matches object_id exactly.
	for _, td := range allTodos {
		tuples = append(tuples, tuple{rick, "admin", "todo", td})
	}

	for _, tp := range tuples {
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
			VALUES ($1::uuid, 'user', $2, $3, $4, $5)`,
			f.orgID, tp.sub, tp.rel, tp.otype, tp.oid); err != nil {
			t.Fatalf("writing tuple %v: %v", tp, err)
		}
	}

	names := map[string]string{
		rick: "rick", morty: "morty", summer: "summer", beth: "beth", jerry: "jerry",
	}

	var passed, failed int
	t.Run("evaluation", func(t *testing.T) {
		for i, sc := range suite.Evaluation {
			body, err := json.Marshal(sc.Request)
			if err != nil {
				t.Fatal(err)
			}
			code, resp := postAuthz(t, f, token, "/access/v1/evaluation", string(body))
			label := fmt.Sprintf("#%d %s %s %s:%s", i+1, names[sc.Request.Subject.ID],
				sc.Request.Action.Name, sc.Request.Resource.Type, sc.Request.Resource.ID)
			if code != http.StatusOK {
				failed++
				t.Errorf("%s: HTTP %d, want 200", label, code)
				continue
			}
			if resp["decision"] != sc.Expected {
				failed++
				t.Errorf("%s: decision = %v, interop suite expects %v",
					label, resp["decision"], sc.Expected)
				continue
			}
			passed++
		}
	})

	t.Run("evaluations", func(t *testing.T) {
		for i, sc := range suite.Evaluations {
			code, resp := postAuthz(t, f, token, "/access/v1/evaluations", string(sc.Request))
			if code != http.StatusOK {
				failed++
				t.Errorf("batch #%d: HTTP %d, want 200", i+1, code)
				continue
			}
			list, _ := resp["evaluations"].([]any)
			if len(list) != len(sc.Expected) {
				failed++
				t.Errorf("batch #%d: %d results, interop suite expects %d",
					i+1, len(list), len(sc.Expected))
				continue
			}
			ok := true
			for j, want := range sc.Expected {
				got, _ := list[j].(map[string]any)
				if got["decision"] != want.Decision {
					ok = false
					t.Errorf("batch #%d entry %d: decision = %v, want %v",
						i+1, j+1, got["decision"], want.Decision)
				}
			}
			if ok {
				passed++
			} else {
				failed++
			}
		}
	})

	t.Logf("OpenID AuthZEN interop suite: %d passed, %d failed, of %d scenarios",
		passed, failed, len(suite.Evaluation)+len(suite.Evaluations))
}
