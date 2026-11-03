package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// Grant Management from a client's side: a grant made by an authorization request, added
// to and replaced by others, read back and revoked.

type grantClient struct {
	*signInFixture
	secret string
	cookie string
}

func newGrantClient(t *testing.T) *grantClient {
	t.Helper()
	f := newSignInFixture(t)
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET first_party = true, client_type = 'confidential',
		client_secret_hash = $2, scopes = ARRAY['openid', 'profile', 'email', 'offline_access', 'grant_management_query', 'grant_management_revoke']
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	return &grantClient{signInFixture: f, secret: secret, cookie: f.signInAndReturnCookie(t)}
}

// sign is an authorization request and the redemption of its code.
func (g *grantClient) sign(t *testing.T, scope string, extra url.Values) map[string]any {
	t.Helper()
	query := url.Values{"scope": {scope}}
	for name, values := range extra {
		query[name] = values
	}
	rec := g.authorizeWith(t, g.cookie, query)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("no code: %d %q %.300s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	status, body := g.tokenRequest(t, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://rp.test/cb"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}})
	if status != http.StatusOK {
		t.Fatalf("the redemption answered %d %v", status, body)
	}
	return body
}

func (g *grantClient) tokenRequest(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("client_id", g.clientID)
	form.Set("client_secret", g.secret)
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	g.srv.Routes().ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// api calls the grant's resource URL.
func (g *grantClient) api(t *testing.T, method, grantID, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, oidc.PathGrantManagement+"/"+grantID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	g.srv.Routes().ServeHTTP(rec, req)
	return rec
}

func (g *grantClient) grantScopes(t *testing.T, grantID, token string) []string {
	t.Helper()
	rec := g.api(t, http.MethodGet, grantID, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("querying answered %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Scopes []struct {
			Scope string `json:"scope"`
		} `json:"scopes"`
		CreatedAt int64 `json:"created_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Scopes) != 1 || out.CreatedAt == 0 {
		t.Fatalf("%s %v", rec.Body, err)
	}
	return strings.Fields(out.Scopes[0].Scope)
}

func action(name, grantID string) url.Values {
	out := url.Values{"grant_management_action": {name}}
	if grantID != "" {
		out["grant_id"] = []string{grantID}
	}
	return out
}

func TestAGrantComesToExistWhenItsTokensAreClaimed(t *testing.T) {
	g := newGrantClient(t)
	ctx := context.Background()
	count := func() int {
		t.Helper()
		var n int
		if err := g.pool.QueryRow(ctx, `SELECT count(*) FROM core.client_grants WHERE client_id = $1`, g.clientID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rec := g.authorizeWith(t, g.cookie, action("create", ""))
	if !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("no code: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if count() != 0 {
		t.Error("a grant exists with no token claimed")
	}
	body := g.sign(t, "openid grant_management_query", action("create", ""))
	grantID, _ := body["grant_id"].(string)
	if len(grantID) < 32 || count() != 1 {
		t.Fatalf("grant %q, %d in the table", grantID, count())
	}
	token, _ := body["access_token"].(string)
	if got := g.grantScopes(t, grantID, token); !slices.Equal(got, []string{"openid", "grant_management_query"}) {
		t.Errorf("the grant holds %v", got)
	}
	if rec := g.api(t, http.MethodGet, grantID, token); rec.Header().Get("Cache-Control") != "no-cache, no-store" {
		t.Errorf("Cache-Control is %q", rec.Header().Get("Cache-Control"))
	}
}

// A request that asks nothing of grants is what it was.
func TestARequestThatNamesNoActionHasNoGrant(t *testing.T) {
	g := newGrantClient(t)
	if body := g.sign(t, "openid", nil); body["grant_id"] != nil {
		t.Errorf("a grant_id came back: %v", body)
	}
}

// §5.2: a merge keeps what is there and adds, and "shall invalidate existing refresh
// tokens associated with the updated grant". §10 wants the access tokens gone too.
func TestAMergeAddsToAGrantAndEndsItsTokens(t *testing.T) {
	g := newGrantClient(t)
	first := g.sign(t, "openid offline_access grant_management_query", action("create", ""))
	grantID, _ := first["grant_id"].(string)
	oldAccess, _ := first["access_token"].(string)
	oldRefresh, _ := first["refresh_token"].(string)
	if oldRefresh == "" {
		t.Fatalf("no refresh token: %v", first)
	}

	second := g.sign(t, "openid profile", action("merge", grantID))
	if second["grant_id"] != grantID {
		t.Fatalf("a merge came back as %v", second["grant_id"])
	}
	token, _ := second["access_token"].(string)
	want := []string{"grant_management_query", "offline_access", "openid", "profile"}
	got := g.grantScopes(t, grantID, token)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("the grant holds %v", got)
	}
	if scope, _ := second["scope"].(string); !strings.Contains(scope, "grant_management_query") {
		t.Errorf("the new token's scope is %q: it should carry the whole grant", scope)
	}
	if status, _ := g.tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {oldRefresh}}); status == http.StatusOK {
		t.Error("the refresh token from before the merge still works")
	}
	if rec := g.api(t, http.MethodGet, grantID, oldAccess); rec.Code != http.StatusUnauthorized {
		t.Errorf("the access token from before the merge answered %d", rec.Code)
	}
}

// §5.2: "ONLY the permissions requested by the client and consented" this time.
func TestAReplaceLeavesOnlyWhatWasAskedFor(t *testing.T) {
	g := newGrantClient(t)
	first := g.sign(t, "openid profile grant_management_query", action("create", ""))
	grantID, _ := first["grant_id"].(string)
	second := g.sign(t, "openid email grant_management_query", action("replace", grantID))
	token, _ := second["access_token"].(string)
	got := g.grantScopes(t, grantID, token)
	slices.Sort(got)
	if !slices.Equal(got, []string{"email", "grant_management_query", "openid"}) {
		t.Errorf("the grant holds %v", got)
	}
}

// §6.5: the grant, its refresh tokens, and its access tokens.
func TestARevokedGrantTakesItsTokensWithIt(t *testing.T) {
	g := newGrantClient(t)
	first := g.sign(t, "openid offline_access grant_management_query grant_management_revoke", action("create", ""))
	grantID, _ := first["grant_id"].(string)
	access, _ := first["access_token"].(string)
	refresh, _ := first["refresh_token"].(string)
	if rec := g.api(t, http.MethodDelete, grantID, access); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("revoking answered %d %s", rec.Code, rec.Body)
	}
	if status, _ := g.tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}); status == http.StatusOK {
		t.Error("its refresh token still works")
	}
	if rec := g.api(t, http.MethodGet, grantID, access); rec.Code != http.StatusUnauthorized {
		t.Errorf("its access token answered %d", rec.Code)
	}
	other := g.sign(t, "openid grant_management_query", action("create", ""))
	token, _ := other["access_token"].(string)
	if rec := g.api(t, http.MethodGet, grantID, token); rec.Code != http.StatusNotFound {
		t.Errorf("a revoked grant answered %d", rec.Code)
	}
}

// With no offline_access there is no refresh token, and the access token still goes.
func TestAGrantReachesAnAccessTokenWithNoRefreshToken(t *testing.T) {
	g := newGrantClient(t)
	first := g.sign(t, "openid grant_management_query grant_management_revoke", action("create", ""))
	grantID, _ := first["grant_id"].(string)
	if first["refresh_token"] != nil {
		t.Fatalf("a refresh token: %v", first)
	}
	access, _ := first["access_token"].(string)
	if rec := g.api(t, http.MethodDelete, grantID, access); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking answered %d %s", rec.Code, rec.Body)
	}
	if rec := g.api(t, http.MethodGet, grantID, access); rec.Code != http.StatusUnauthorized {
		t.Errorf("the access token answered %d", rec.Code)
	}
}

// §6.1 and §6.6.
func TestTheAPIAsksForItsScopes(t *testing.T) {
	g := newGrantClient(t)
	body := g.sign(t, "openid", action("create", ""))
	grantID, _ := body["grant_id"].(string)
	token, _ := body["access_token"].(string)
	if rec := g.api(t, http.MethodGet, grantID, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token answered %d", rec.Code)
	}
	if rec := g.api(t, http.MethodGet, grantID, "nonsense"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a bad token answered %d", rec.Code)
	}
	if rec := g.api(t, http.MethodGet, grantID, token); rec.Code != http.StatusForbidden {
		t.Errorf("a token with no query scope answered %d", rec.Code)
	}
	if rec := g.api(t, http.MethodDelete, grantID, token); rec.Code != http.StatusForbidden {
		t.Errorf("a token with no revoke scope answered %d", rec.Code)
	}
	query := g.sign(t, "openid grant_management_query", action("create", ""))
	reader, _ := query["access_token"].(string)
	if rec := g.api(t, http.MethodDelete, grantID, reader); rec.Code != http.StatusForbidden {
		t.Errorf("a token that may only query revoked: %d", rec.Code)
	}
	if rec := g.api(t, http.MethodGet, "no-such-grant", reader); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown grant answered %d", rec.Code)
	}
}

// §5.1 and §5.4, each sent back to the client.
func TestABadGrantRequestIsSentBack(t *testing.T) {
	g := newGrantClient(t)
	created := g.sign(t, "openid", action("create", ""))
	grantID, _ := created["grant_id"].(string)
	for name, c := range map[string]struct {
		query url.Values
		code  string
	}{
		"create with an id":  {action("create", grantID), "invalid_request"},
		"an id with nothing": {url.Values{"grant_id": {grantID}}, "invalid_request"},
		"merge with no id":   {action("merge", ""), "invalid_request"},
		"replace with no id": {action("replace", ""), "invalid_request"},
		"an unknown action":  {action("destroy", grantID), "invalid_request"},
		"an unknown grant":   {action("merge", "no-such-grant"), "invalid_grant_id"},
	} {
		rec := g.authorizeWith(t, g.cookie, c.query)
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || loc.Query().Get("error") != c.code {
			t.Errorf("%s answered %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	if _, err := g.pool.Exec(context.Background(), `UPDATE core.clients SET client_type = 'public', client_secret_hash = NULL
		WHERE client_id = $1`, g.clientID); err != nil {
		t.Fatal(err)
	}
	rec := g.authorizeWith(t, g.cookie, action("create", ""))
	if loc, err := url.Parse(rec.Header().Get("Location")); err != nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("a public client answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// §5.4: "logged in user doesn't match a resource owner", and another client's grant.
func TestAGrantIsOnlyItsOwnersToName(t *testing.T) {
	g := newGrantClient(t)
	created := g.sign(t, "openid", action("create", ""))
	grantID, _ := created["grant_id"].(string)
	ctx := context.Background()
	var other string
	if err := g.pool.QueryRow(ctx, `INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, gen_random_uuid()::text || '@example.test', sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea))
		RETURNING id::text`, g.orgID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = g.pool.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, other) })
	held, err := store.ClientGrantHeld(ctx, g.pool, grantID, g.clientID, other)
	if err != nil || held {
		t.Errorf("another person's held it: %v %v", held, err)
	}
	if held, err := store.ClientGrantHeld(ctx, g.pool, grantID, "somebody-else", g.userID); err != nil || held {
		t.Errorf("another client's held it: %v %v", held, err)
	}
	if _, err := store.ClientGrantOf(ctx, g.pool, grantID, "somebody-else"); err == nil {
		t.Error("another client read it")
	}
}

// A grant left behind by a withdrawal could be merged into and hand it all back.
func TestWithdrawingConsentTakesTheGrants(t *testing.T) {
	g := newGrantClient(t)
	created := g.sign(t, "openid", action("create", ""))
	grantID, _ := created["grant_id"].(string)
	ctx := context.Background()
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.WithdrawConsent(ctx, tx, g.userID, g.clientID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if held, err := store.ClientGrantHeld(ctx, g.pool, grantID, g.clientID, g.userID); err != nil || held {
		t.Errorf("the grant outlived the consent: %v %v", held, err)
	}
}

func TestDiscoveryNamesTheEndpoint(t *testing.T) {
	g := newGrantClient(t)
	md, err := g.srv.buildDiscovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(md.GrantManagementEndpoint, oidc.PathGrantManagement) ||
		!slices.Equal(md.GrantManagementActionsSupported, []string{"query", "revoke", "create", "merge", "replace"}) {
		t.Errorf("%q %v", md.GrantManagementEndpoint, md.GrantManagementActionsSupported)
	}
}

func TestOnlyAGrantNothingStandsOnIsSwept(t *testing.T) {
	g := newGrantClient(t)
	body := g.sign(t, "openid", action("create", ""))
	grantID, _ := body["grant_id"].(string)
	ctx := context.Background()
	if _, err := g.pool.Exec(ctx, `UPDATE core.client_grants SET updated_at = now() - interval '2 days' WHERE grant_id = $1`, grantID); err != nil {
		t.Fatal(err)
	}
	sweep := func() {
		t.Helper()
		tx, err := g.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.SweepClientGrants(ctx, tx, 24*time.Hour, 100); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	held := func() bool {
		t.Helper()
		ok, err := store.ClientGrantHeld(ctx, g.pool, grantID, g.clientID, g.userID)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	sweep()
	if !held() {
		t.Error("a grant with a live lineage was swept")
	}
	if _, err := g.pool.Exec(ctx, `UPDATE core.refresh_token_families SET revoked_at = now(), revocation_reason = 'logout'
		WHERE client_grant = $1`, grantID); err != nil {
		t.Fatal(err)
	}
	sweep()
	if held() {
		t.Error("a grant nothing stands on stayed")
	}
}
