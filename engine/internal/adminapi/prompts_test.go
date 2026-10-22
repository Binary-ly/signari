package adminapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A prompt is defined, reworded and disabled through the Admin API as `signari
// prompt` does it (6.07): checked before it is stored, versioned when what a
// person reads changes and not when its order does, and kept when disabled.
func TestAPromptIsDefinedRewordedAndDisabledThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/prompts"
	terms := func(title string, order int) map[string]any {
		return map[string]any{"title": title, "order": order, "fields": []map[string]any{
			{"name": "agree", "type": "checkbox", "label": "I agree", "required": true}}}
	}
	put := func(body map[string]any) (int, map[string]any) {
		t.Helper()
		rec := call(t, s, http.MethodPut, base+"/terms", testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	list := func() []promptView {
		t.Helper()
		rec := call(t, s, http.MethodGet, base, testToken, nil)
		var out struct {
			Prompts []promptView `json:"prompts"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("listing prompts: %d %s", rec.Code, rec.Body.String())
		}
		return out.Prompts
	}

	for _, bad := range []map[string]any{
		{"title": "No fields"},
		{"fields": terms("x", 0)["fields"]},
		{"title": "Unlabelled", "fields": []map[string]any{{"name": "agree", "type": "checkbox"}}},
		{"title": "Undeclared", "fields": []map[string]any{{"name": "dept", "type": "text", "label": "Department",
			"attribute": "no_such_attribute"}}},
	} {
		if code, out := put(bad); code != http.StatusBadRequest || out["error"] != "invalid_prompt" {
			t.Errorf("%v answered %d %v", bad, code, out)
		}
	}
	if len(list()) != 0 {
		t.Fatal("a refused prompt was stored")
	}

	code, out := put(terms("Terms of use", 1))
	if code != http.StatusOK || out["version"] != float64(1) {
		t.Fatalf("defining the prompt: %d %v", code, out)
	}
	if _, out := put(terms("Terms of use", 2)); out["version"] != float64(1) {
		t.Errorf("moving the prompt in the order moved its version to %v", out["version"])
	}
	if _, out := put(terms("Terms of use, revised", 2)); out["version"] != float64(2) {
		t.Errorf("rewording the prompt left its version at %v", out["version"])
	}
	got := list()
	if len(got) != 1 || got[0].Title != "Terms of use, revised" || !got[0].Enabled || !got[0].Once || got[0].Order != 2 {
		t.Fatalf("the prompt reads %+v", got)
	}

	if rec := call(t, s, http.MethodPatch, base+"/terms", testToken, map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disabling the prompt: %d %s", rec.Code, rec.Body.String())
	}
	if got := list(); len(got) != 1 || got[0].Enabled {
		t.Errorf("after disabling, the prompts read %+v", got)
	}
	if rec := call(t, s, http.MethodPatch, base+"/nobody", testToken, map[string]any{"enabled": true}); rec.Code != http.StatusNotFound {
		t.Errorf("enabling a prompt nobody defined answered %d", rec.Code)
	}
}
