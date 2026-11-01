package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// A relation through a fake that keeps rows as the Admin API does: a PUT replaces,
// a DELETE names it in the query, and a list is by filter.
func TestARelationLivesThroughAnApply(t *testing.T) {
	var mu sync.Mutex
	rows := map[string]map[string]any{}
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("ETag", `"7"`)
		key := func(s, rel, o string) string { return s + "|" + rel + "|" + o }
		switch r.Method {
		case http.MethodPut:
			raw, _ := io.ReadAll(r.Body)
			var b map[string]any
			_ = json.Unmarshal(raw, &b)
			rows[key(b["subject"].(string), b["relation"].(string), b["object"].(string))] = b
			fmt.Fprint(w, `{"config_version":7}`)
		case http.MethodDelete:
			q := r.URL.Query()
			deleted = append(deleted, q.Get("subject")+" "+q.Get("relation")+" "+q.Get("object"))
			delete(rows, key(q.Get("subject"), q.Get("relation"), q.Get("object")))
			fmt.Fprint(w, `{"config_version":7}`)
		default:
			q := r.URL.Query()
			out := []map[string]any{}
			if row, ok := rows[key(q.Get("subject"), q.Get("relation"), q.Get("object"))]; ok {
				if at, has := row["expires_at"].(string); has {
					// The server answers a moment in its own zone.
					parsed, _ := time.Parse(time.RFC3339, at)
					row["expires_at"] = parsed.UTC().Format(time.RFC3339)
				}
				out = append(out, row)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"relations": out})
		}
	}))
	t.Cleanup(srv.Close)
	h := newHarness[relationModel](t, &relationResource{}, &providerData{client: &signari.Client{Endpoint: srv.URL,
		Token: "t"}, conditional: true})

	want := relationModel{OrgID: types.StringValue("o"), Subject: types.StringValue("team:eng#member"),
		Relation: types.StringValue("viewer"), Object: types.StringValue("document:42"),
		ExpiresAt: types.StringNull(), ID: types.StringUnknown(), ConfigVersion: types.Int64Unknown()}
	state, d := h.create(want)
	if d.HasError() {
		t.Fatal(d)
	}
	made := h.model(state)
	if made.ID.ValueString() != "o|team:eng#member|viewer|document:42" || made.ConfigVersion.ValueInt64() != 7 {
		t.Fatalf("made %+v", made)
	}

	// A moment written in one zone and answered in another is not a change: a plan
	// that read one would rewrite the grant on every apply.
	changed := made
	changed.ExpiresAt = types.StringValue("2099-01-02T05:00:00+02:00")
	state, d = h.update(state, changed)
	if d.HasError() {
		t.Fatal(d)
	}
	if got := h.model(state).ExpiresAt.ValueString(); got != "2099-01-02T05:00:00+02:00" {
		t.Errorf("the expiry came back as %q, which the next plan reads as a change", got)
	}
	refreshed, found, d := h.read(state)
	if d.HasError() || !found {
		t.Fatalf("read: %v %v", found, d)
	}
	if got := h.model(refreshed).ExpiresAt.ValueString(); got != "2099-01-02T05:00:00+02:00" {
		t.Errorf("a refresh moved the expiry to %q", got)
	}

	if d := h.destroy(refreshed); d.HasError() {
		t.Fatal(d)
	}
	if len(deleted) != 1 || deleted[0] != "team:eng#member viewer document:42" {
		t.Fatalf("the destroy named %v", deleted)
	}

	// One gone from the server is gone from state, so the next plan grants it.
	if _, found, d := h.read(refreshed); d.HasError() || found {
		t.Errorf("a relation nobody holds stayed in state: %v %v", found, d)
	}

	if _, d := h.create(relationModel{OrgID: types.StringValue("o"), Subject: types.StringValue("user:ada"),
		Relation: types.StringValue("owner"), Object: types.StringValue("document:1"), ExpiresAt: types.StringNull(),
		ID: types.StringUnknown(), ConfigVersion: types.Int64Unknown()}); d.HasError() {
		t.Fatal(d)
	}
	imported, d := h.imported("o|user:ada|owner|document:1")
	if d.HasError() {
		t.Fatal(d)
	}
	if m := h.model(imported); m.Subject.ValueString() != "user:ada" || m.Object.ValueString() != "document:1" {
		t.Errorf("imported %+v", m)
	}
	if _, d := h.imported("o/user:ada/owner/document:1"); !d.HasError() {
		t.Error("an id of the wrong shape was imported")
	}
}

// Against a real Admin API (6.17): the fake cannot say the server takes this body
// and answers a read this way. Needs what the other E2E runs need.
func TestE2EARelationLivesThroughAnApply(t *testing.T) {
	endpoint, token, org := os.Getenv("SIGNARI_E2E_ENDPOINT"), os.Getenv("SIGNARI_E2E_TOKEN"), os.Getenv("SIGNARI_E2E_ORG_ID")
	if endpoint == "" || token == "" || org == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_ORG_ID not set")
	}
	api := &signari.Client{Endpoint: endpoint, Token: token}
	h := newHarness[relationModel](t, &relationResource{}, &providerData{client: api, conditional: true})
	subject := fmt.Sprintf("team:e2e-%d#member", time.Now().UnixNano())
	state, d := h.create(relationModel{OrgID: types.StringValue(org), Subject: types.StringValue(subject),
		Relation: types.StringValue("viewer"), Object: types.StringValue("document:e2e"),
		ExpiresAt: types.StringNull(), ID: types.StringUnknown(), ConfigVersion: types.Int64Unknown()})
	if d.HasError() {
		t.Fatal(d)
	}
	made := h.model(state)
	if made.ConfigVersion.ValueInt64() == 0 || made.ID.IsNull() || made.ID.ValueString() == "" {
		t.Fatalf("the server gave no version or id: %+v", made)
	}

	later := time.Now().Add(48 * time.Hour).In(time.FixedZone("", 7200)).Format(time.RFC3339)
	changed := made
	changed.ExpiresAt = types.StringValue(later)
	if state, d = h.update(state, changed); d.HasError() {
		t.Fatal(d)
	}
	refreshed, found, d := h.read(state)
	if d.HasError() || !found {
		t.Fatalf("the relation is not on the server: %v %v", found, d)
	}
	if got := h.model(refreshed).ExpiresAt.ValueString(); got != later {
		t.Errorf("the expiry read back as %q, want %q", got, later)
	}

	if d := h.destroy(refreshed); d.HasError() {
		t.Fatal(d)
	}
	if _, found, d := h.read(refreshed); d.HasError() || found {
		t.Errorf("the relation survived its destroy: %v %v", found, d)
	}
}
