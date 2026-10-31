package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/provision"
)

// From the Admin API to a sync that really asks: the grant is what is registered,
// the client secret is sealed as a token is, and it never comes back.
func TestATargetAuthenticatesByTheGrantItWasRegisteredWith(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	fake := newFakeTarget(t)
	s.targetClient = func() (*http.Client, error) { return fake.Client(), nil }
	base := "/admin/organizations/" + org + "/scim-targets"

	for name, body := range map[string]map[string]any{
		"a client and no token URL": {"oauth_client_id": "c"},
		"a token URL and no client": {"oauth_token_url": "https://auth.example.test/token"},
		"a scope alone":             {"oauth_scope": "s"},
		"a plain token URL":         {"oauth_token_url": "http://auth.example.test/token", "oauth_client_id": "c"},
	} {
		req := map[string]any{"slug": "bad", "base_url": "https://scim.example.test/v2", "token": "t"}
		for k, v := range body {
			req[k] = v
		}
		if rec := call(t, s, http.MethodPost, base, testToken, req); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// Where the secret goes is held to where the people go.
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "bad",
		"base_url": "https://scim.example.test/v2", "token": "t", "oauth_token_url": "https://10.0.0.9/token",
		"oauth_client_id": "c"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_url") {
		t.Errorf("a token URL inside the network answered %d %s", rec.Code, rec.Body.String())
	}

	const secret = "a-client-secret-the-target-issued"
	if err := provision.AddTarget(ctx, s.db, s.root, org, provision.TargetSpec{Slug: "drift", BaseURL: fake.URL,
		Token: secret, OAuthTokenURL: fake.URL + "/oauth/token", OAuthClientID: "our-client",
		OAuthScope: "scim.write"}); err != nil {
		t.Fatal(err)
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), secret) {
		t.Errorf("the secret came back: %s", list.Body.String())
	}
	var got struct {
		Targets []struct {
			OAuthTokenURL string `json:"oauth_token_url"`
			OAuthClientID string `json:"oauth_client_id"`
			OAuthScope    string `json:"oauth_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 1 || got.Targets[0].OAuthClientID != "our-client" || got.Targets[0].OAuthScope != "scim.write" {
		t.Errorf("the target reads %+v", got.Targets)
	}

	var person string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, username, email, status, user_handle)
		VALUES ($1::uuid, 'ada', 'ada@example.test', 'active', decode(md5(random()::text) || md5(random()::text) ||
		        md5(random()::text) || md5(random()::text), 'hex')) RETURNING id::text`, org).Scan(&person); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, person) })
	rec := call(t, s, http.MethodPost, base+"/drift/sync", testToken, map[string]any{"apply": true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"created":1`) {
		t.Fatalf("syncing: %d %s", rec.Code, rec.Body.String())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.bearers) == 0 {
		t.Fatal("nothing reached the target")
	}
	for _, b := range fake.bearers {
		if b != fakeIssuedToken {
			t.Errorf("the target was sent %q, want the token it issued", b)
		}
	}
	if fake.clientID != "our-client" || fake.clientSecret != secret {
		t.Errorf("the token endpoint saw %q, %q", fake.clientID, fake.clientSecret)
	}
}

func TestAChangeOfGrantNeedsTheSecret(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if err := provision.AddTarget(ctx, s.db, s.root, org, provision.TargetSpec{Slug: "drift",
		BaseURL: "https://scim.example.test/v2", Token: "t"}); err != nil {
		t.Fatal(err)
	}
	grant := provision.TargetOAuth{TokenURL: "https://auth.example.test/token", ClientID: "c"}
	err := provision.UpdateTarget(ctx, s.db, s.root, org, "drift", "scim", provision.TargetChange{OAuth: &grant})
	if err == nil {
		t.Error("the secret of the old grant would go to the new address")
	}
	secret := "new"
	if err := provision.UpdateTarget(ctx, s.db, s.root, org, "drift", "scim",
		provision.TargetChange{OAuth: &grant, Token: &secret}); err != nil {
		t.Fatal(err)
	}
	// All "" ends it, back to a bearer token.
	end := provision.TargetOAuth{}
	if err := provision.UpdateTarget(ctx, s.db, s.root, org, "drift", "scim",
		provision.TargetChange{OAuth: &end, Token: &secret}); err != nil {
		t.Fatal(err)
	}
	var left *string
	if err := s.db.QueryRow(ctx, `SELECT oauth_token_url FROM core.scim_targets WHERE org_id = $1::uuid`, org).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != nil {
		t.Errorf("the grant is still %q", *left)
	}
}
