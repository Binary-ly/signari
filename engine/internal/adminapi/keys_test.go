package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

	if rec := call(t, s, http.MethodPost, base+"/rotate", testToken, map[string]any{"algorithm": "HS256"}); rec.Code != http.StatusBadRequest {
		t.Errorf("rotating an algorithm this server does not make answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPost, base+"/rotate", testToken, map[string]any{"algorithm": "ES256",
		"rsa_bits": 2048}); rec.Code != http.StatusBadRequest {
		t.Errorf("sizing a key with no modulus answered %d", rec.Code)
	}
	// Nothing signs with it yet, and this is how it comes to.
	if rec := call(t, s, http.MethodPost, base+"/rotate", testToken, map[string]any{"algorithm": "EdDSA"}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"published"`) {
		t.Errorf("publishing an algorithm's first key answered %d %s", rec.Code, rec.Body)
	}
	tenant := mintToken(t, s, fmt.Sprintf("keys-tenant-%d", time.Now().UnixNano()), anyOrgID(t, s),
		[]string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	if rec := call(t, s, http.MethodPost, base+"/rotate", tenant, map[string]any{}); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token rotated the instance's keys: %d", rec.Code)
	}
}

// What a wallet encrypts to is a key of its own: making one touches no signing key, and
// each one keeps a single generation behind it.
func TestAWalletsEncryptionKeyIsMadeThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	id := newDriftKeyedInstance(t, s)
	path := "/admin/instances/" + id + "/credential-encryption-key"
	signing := func() string {
		t.Helper()
		set, err := keys.LoadSet(ctx, s.db, id, s.root)
		if err != nil {
			t.Fatal(err)
		}
		out := ""
		for _, k := range set.Keys() {
			out += k.KID() + "=" + string(k.State()) + " "
		}
		return out
	}
	before := signing()
	made := func() string {
		t.Helper()
		rec := call(t, s, http.MethodPost, path, testToken, nil)
		var out struct {
			KID string `json:"kid"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK || out.KID == "" {
			t.Fatalf("it answered %d %s", rec.Code, rec.Body)
		}
		return out.KID
	}
	first, second, third := made(), made(), made()
	if got := signing(); got != before {
		t.Errorf("the signing keys went from %s to %s", before, got)
	}
	set, err := keys.LoadSetFor(ctx, s.db, id, keys.PurposeEncryption, s.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := set.ByKID(first); kept {
		t.Error("two rotations later the first key still opens")
	}
	for kid, want := range map[string]keys.State{second: keys.StatePassive, third: keys.StateActive} {
		if k, kept := set.ByKID(kid); !kept || k.State() != want {
			t.Errorf("%s is %v, want %s", kid, k, want)
		}
	}
	tenant := mintToken(t, s, fmt.Sprintf("encryption-tenant-%d", time.Now().UnixNano()), anyOrgID(t, s),
		[]string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	if rec := call(t, s, http.MethodPost, path, tenant, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token made the instance's key: %d", rec.Code)
	}
	unknown := "/admin/instances/00000000-0000-0000-0000-000000000001/credential-encryption-key"
	if rec := call(t, s, http.MethodPost, unknown, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown instance answered %d", rec.Code)
	}
}
