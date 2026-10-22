package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// A token cannot mint, rotate or revoke one wider than itself (6.04).

func restrictedToken(t *testing.T, s *Server, orgID string, scopes, clients []string, life time.Duration) (secret, id string) {
	t.Helper()
	name := fmt.Sprintf("width-%d", time.Now().UnixNano())
	expires := time.Now().Add(life)
	secret, id, err := NewToken(context.Background(), s.db, name, orgID, scopes, &expires, clients, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE name = $1`, name)
	})
	return secret, id
}

func TestATokenCannotMintAWiderOne(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	other := newDriftMigrationOrg(t, s, false)
	minter, _ := restrictedToken(t, s, org, []string{ScopeTokensWrite, ScopeUsersRead}, []string{"c1"}, 48*time.Hour)

	mint := func(body map[string]any) (int, map[string]any) {
		t.Helper()
		if _, ok := body["name"]; !ok {
			name := fmt.Sprintf("minted-%d", time.Now().UnixNano())
			body["name"] = name
			t.Cleanup(func() {
				_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE name = $1`, name)
			})
		}
		rec := call(t, s, http.MethodPost, "/admin/tokens", minter, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	for _, c := range []struct {
		why  string
		body map[string]any
	}{
		{"a scope it does not hold", map[string]any{"scopes": []string{ScopeUsersWrite}, "client_ids": []string{"c1"}, "expires_in_s": 3600}},
		{"another organisation", map[string]any{"scopes": []string{ScopeUsersRead}, "org_id": other, "client_ids": []string{"c1"}, "expires_in_s": 3600}},
		{"every client", map[string]any{"scopes": []string{ScopeUsersRead}, "expires_in_s": 3600}},
		{"a client it cannot reach", map[string]any{"scopes": []string{ScopeUsersRead}, "client_ids": []string{"c2"}, "expires_in_s": 3600}},
		{"outliving it", map[string]any{"scopes": []string{ScopeUsersRead}, "client_ids": []string{"c1"}, "expires_in_s": 30 * 86400}},
	} {
		if code, out := mint(c.body); code != http.StatusForbidden || out["error"] != "wider_than_caller" {
			t.Errorf("minting %s answered %d %v", c.why, code, out)
		}
	}

	code, out := mint(map[string]any{"scopes": []string{ScopeUsersRead, ScopeTokensWrite},
		"client_ids": []string{"c1"}, "expires_in_s": 3600})
	if code != http.StatusCreated || out["secret"] == "" || out["org_id"] != org {
		t.Fatalf("a token within the minter was refused: %d %v", code, out)
	}
	// And what it minted is held to it in turn.
	child, _ := out["secret"].(string)
	grandchild := fmt.Sprintf("grandchild-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE name = $1`, grandchild)
	})
	rec := call(t, s, http.MethodPost, "/admin/tokens", child, map[string]any{"name": grandchild,
		"scopes": []string{ScopeUsersRead}, "client_ids": []string{"c1"}, "expires_in_s": 7200})
	if rec.Code != http.StatusForbidden {
		t.Errorf("a minted token minted one outliving itself: %d %s", rec.Code, rec.Body.String())
	}

	// A token minted here always expires: the default, and never beyond the cap.
	rec = call(t, s, http.MethodPost, "/admin/tokens", testToken, map[string]any{"name": "too-long",
		"scopes": []string{ScopeConfigRead}, "expires_in_s": 400 * 86400})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a token for more than a year answered %d", rec.Code)
	}
	name := fmt.Sprintf("defaulted-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE name = $1`, name)
	})
	rec = call(t, s, http.MethodPost, "/admin/tokens", testToken, map[string]any{"name": name,
		"scopes": []string{ScopeConfigRead}})
	var minted map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &minted)
	exp, _ := time.Parse(time.RFC3339, fmt.Sprint(minted["expires_at"]))
	if rec.Code != http.StatusCreated || exp.Sub(time.Now()) < 89*24*time.Hour || exp.Sub(time.Now()) > 91*24*time.Hour {
		t.Errorf("a token minted with no lifetime: %d expires %v", rec.Code, minted["expires_at"])
	}
}

func TestATokenRotatesAndRevokesOnlyWhatItCouldHaveMinted(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	narrow, narrowID := restrictedToken(t, s, org, []string{ScopeTokensWrite, ScopeConfigRead}, nil, 48*time.Hour)
	wide, wideID := restrictedToken(t, s, org, []string{ScopeTokensWrite, ScopeUsersWrite, ScopeConfigRead}, nil, 48*time.Hour)

	if rec := call(t, s, http.MethodPost, "/admin/tokens/"+wideID+"/rotate", narrow, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a narrow token rotated a wide one, and would hold its secret: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, "/admin/tokens/"+wideID, narrow, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a narrow token revoked a wide one: %d", rec.Code)
	}

	// Itself, with no grace: the replacement works and the old secret stops.
	rec := call(t, s, http.MethodPost, "/admin/tokens/"+narrowID+"/rotate", narrow, map[string]any{"grace_s": 0, "expires_in_s": 3600})
	var rotated map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rec.Code != http.StatusOK || rotated["secret"] == "" {
		t.Fatalf("rotating itself: %d %s", rec.Code, rec.Body.String())
	}
	replacement, _ := rotated["secret"].(string)
	if rec := call(t, s, http.MethodGet, "/admin/tokens", replacement, nil); rec.Code != http.StatusOK {
		t.Errorf("the replacement does not work: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodGet, "/admin/tokens", narrow, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the rotated-out secret with no grace still works: %d", rec.Code)
	}

	// The list is its organisation's, without secrets or hashes.
	rec = call(t, s, http.MethodGet, "/admin/tokens", replacement, nil)
	var list struct {
		Tokens []map[string]any `json:"tokens"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	for _, tk := range list.Tokens {
		if tk["org_id"] != org {
			t.Errorf("a scoped token listed another organisation's token %v", tk["id"])
		}
		if _, ok := tk["token_hash"]; ok {
			t.Error("the list carries a hash")
		}
	}

	// A wide enough caller revokes, and the revoked token stops at once.
	if rec := call(t, s, http.MethodDelete, "/admin/tokens/"+wideID, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoking: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodGet, "/admin/tokens", wide, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token still works: %d", rec.Code)
	}
}
