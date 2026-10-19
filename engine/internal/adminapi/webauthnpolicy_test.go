package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// The authenticator policy can be read and set through this API, by the same
// writer as `signari webauthn policy`. It was CLI-only, so nothing on the API
// could see or change which devices an organisation trusts, and the
// cloned-authenticator refusal could not be set anywhere (2.06).
func TestTheWebAuthnPolicyIsReadAndSetThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	var before []byte
	_ = s.db.QueryRow(context.Background(), `SELECT row_to_json(p)::text::bytea FROM core.webauthn_policy p
		WHERE org_id = $1::uuid`, org).Scan(&before)
	t.Cleanup(func() {
		// Put the organisation back as it was, so a shared database keeps its policy.
		ctx := context.Background()
		_, _ = s.db.Exec(ctx, `DELETE FROM core.webauthn_policy WHERE org_id = $1::uuid`, org)
		if before != nil {
			_, _ = s.db.Exec(ctx, `INSERT INTO core.webauthn_policy
				SELECT * FROM json_populate_record(NULL::core.webauthn_policy, $1::json)`, string(before))
		}
	})
	path := "/admin/organizations/" + org + "/webauthn-policy"
	read := func() map[string]any {
		t.Helper()
		rec := call(t, s, http.MethodGet, path, testToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET gave %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	const yubi = "ee882879-721c-4913-9775-3dfcce97072a"
	rec := call(t, s, http.MethodPut, path, testToken, map[string]any{
		"attestation": "direct", "allowed_aaguids": []string{yubi}, "refuse_cloned": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT gave %d %s", rec.Code, rec.Body.String())
	}
	got := read()
	if got["attestation"] != "direct" || got["refuse_cloned"] != false {
		t.Errorf("after PUT the policy reads %v", got)
	}
	if ids, _ := got["allowed_aaguids"].([]any); len(ids) != 1 || ids[0] != yubi {
		t.Errorf("the approved models read %v", got["allowed_aaguids"])
	}

	// An absent refuse_cloned is the default, on.
	if rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"attestation": "none"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT gave %d", rec.Code)
	}
	if got := read(); got["refuse_cloned"] != true {
		t.Errorf("a PUT that left refuse_cloned out set it to %v", got["refuse_cloned"])
	}

	for name, body := range map[string]map[string]any{
		"an allow-list without attestation": {"attestation": "none", "allowed_aaguids": []string{yubi}},
		"a malformed model id":              {"attestation": "direct", "allowed_aaguids": []string{"yubikey"}},
		"an unknown conveyance":             {"attestation": "please"},
	} {
		if rec := call(t, s, http.MethodPut, path, testToken, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s gave %d %s", name, rec.Code, rec.Body.String())
		}
	}
}
