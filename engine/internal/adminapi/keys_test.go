package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
)

// An instance's signing keys are rotated through the Admin API as `signari keys
// rotate|retire` rotates them (6.07): one safe step at a time, a promotion
// before the publication wait only when forced, the outgoing key kept
// published, nothing retired early, and no private half read back.
func TestAnInstancesKeysAreRotatedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	id := newDriftKeyedInstance(t, s)
	base := "/admin/instances/" + id + "/keys"
	rotate := func(body map[string]any) []rotationStepView {
		t.Helper()
		rec := call(t, s, http.MethodPost, base+"/rotate", testToken, body)
		var out struct {
			Steps []rotationStepView `json:"steps"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK || len(out.Steps) != 1 {
			t.Fatalf("rotating %v: %d %s", body, rec.Code, rec.Body.String())
		}
		return out.Steps
	}
	states := func() map[string]string {
		t.Helper()
		set, err := keys.LoadSet(ctx, s.db, id, s.root)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, k := range set.Keys() {
			out[k.KID()] = string(k.State())
		}
		return out
	}

	first := rotate(map[string]any{})[0]
	if first.Published == "" || first.Promoted != "" {
		t.Fatalf("the first step was %+v, want a next key published", first)
	}
	if st := rotate(map[string]any{})[0]; st.Promoted != "" || st.WaitS <= 0 {
		t.Errorf("rotating again at once was %+v, want the publication wait reported and nothing promoted", st)
	}
	if states()[first.Published] != string(keys.StateNext) {
		t.Errorf("the published key is %s", states()[first.Published])
	}

	forced := rotate(map[string]any{"promote_now": true})[0]
	if forced.Promoted != first.Published || !forced.Forced || forced.Demoted == "" {
		t.Fatalf("a forced promotion was %+v", forced)
	}
	got := states()
	if got[forced.Promoted] != string(keys.StateActive) || got[forced.Demoted] != string(keys.StatePassive) {
		t.Errorf("after promotion the keys are %v; the old one stays published as passive", got)
	}

	rec := call(t, s, http.MethodPost, base+"/retire", testToken, nil)
	var retired struct {
		Retired []string `json:"retired"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &retired)
	if rec.Code != http.StatusOK || len(retired.Retired) != 0 {
		t.Errorf("retiring before the dwell answered %d and retired %v", rec.Code, retired.Retired)
	}
	if states()[forced.Demoted] != string(keys.StatePassive) {
		t.Error("a passive key was retired before its dwell was over")
	}

	list := call(t, s, http.MethodGet, base, testToken, nil)
	var listed map[string]any
	_ = json.Unmarshal(list.Body.Bytes(), &listed)
	for _, k := range listed["keys"].([]any) {
		for _, private := range []string{"d", "p", "q", "private_key", "sealed"} {
			if _, ok := k.(map[string]any)[private]; ok {
				t.Errorf("a key was read back with %q: %v", private, k)
			}
		}
	}

	if rec := call(t, s, http.MethodPost, base+"/rotate", testToken, map[string]any{"algorithm": "EdDSA"}); rec.Code != http.StatusBadRequest {
		t.Errorf("rotating an algorithm nothing signs with answered %d", rec.Code)
	}
	tenant := mintToken(t, s, fmt.Sprintf("keys-tenant-%d", time.Now().UnixNano()), anyOrgID(t, s),
		[]string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	if rec := call(t, s, http.MethodPost, base+"/rotate", tenant, map[string]any{}); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token rotated the instance's keys: %d", rec.Code)
	}
}
