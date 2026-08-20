package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)


type scimFixture struct {
	srv    *Server
	pool   *pgxpool.Pool
	orgID  string
	token  string
	userA  string // /Users resource id
	userB  string
	nameA  string
	nameB  string
	srcID  string
	groups []string
}

func newSCIMFixture(t *testing.T) *scimFixture {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(oidc.Config{Issuer: "https://scim-test.example", Keys: set,
		AllowInsecureIssuer: true}, pool,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &scimFixture{srv: srv, pool: pool}
	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://scim-' || gen_random_uuid() || '.test', 'S') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 's' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i
		RETURNING id::text`).Scan(&f.orgID); err != nil {
		t.Fatalf("fixture org: %v", err)
	}

	f.token = "scim-token-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	sum := sha256.Sum256([]byte(f.token))
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.scim_sources (org_id, slug, display_name, token_hash)
		VALUES ($1::uuid, 'client-test', 'Client', $2) RETURNING id::text`,
		f.orgID, sum[:]).Scan(&f.srcID); err != nil {
		t.Fatalf("fixture source: %v", err)
	}

	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(c, `DELETE FROM core.scim_sources WHERE id = $1::uuid`, f.srcID)
		_, _ = pool.Exec(c, `DELETE FROM core.organizations WHERE id = $1::uuid`, f.orgID)
	})

	// Two users, provisioned through the endpoint itself rather than planted, so
	// the resource ids are the ones an upstream would actually hold.
	f.nameA, f.userA = f.provisionUser(t, "alice")
	f.nameB, f.userB = f.provisionUser(t, "bob")
	return f
}

func (f *scimFixture) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", "application/scim+json")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (f *scimFixture) provisionUser(t *testing.T, name string) (userName, resourceID string) {
	t.Helper()
	userName = fmt.Sprintf("%s-%d@example.test", name, time.Now().UnixNano())
	status, body := f.do(t, http.MethodPost, "/scim/v2/Users", fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		  "externalId":%q,"userName":%q,"active":true,
		  "emails":[{"value":%q,"primary":true}]}`,
		"ext-"+userName, userName, userName))
	if status != http.StatusCreated {
		t.Fatalf("provisioning %s gave %d: %v", name, status, body)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("no resource id for %s: %v", name, body)
	}
	return userName, id
}

// memberIDs reads the member resource ids out of a Group response.
func memberIDs(body map[string]any) []string {
	out := []string{}
	members, _ := body["members"].([]any)
	for _, m := range members {
		mm, _ := m.(map[string]any)
		if v, ok := mm["value"].(string); ok {
			out = append(out, v)
		}
	}
	return out
}

// inGroup reports whether the database records the membership.
//
// Asserted against the DATABASE, not against the response body. A handler that
// echoes back what it was sent without writing anything passes every
// response-shaped assertion, and the membership is what a token carries.
func (f *scimFixture) inGroup(t *testing.T, groupResourceID, userResourceID string) bool {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*)
		FROM core.group_members gm
		JOIN core.scim_source_group_links gl
		  ON gl.group_id = gm.group_id AND gl.source_id = $1::uuid
		JOIN core.scim_source_links ul
		  ON ul.user_id = gm.user_id AND ul.source_id = $1::uuid
		WHERE gl.resource_id::text = $2 AND ul.resource_id::text = $3`,
		f.srcID, groupResourceID, userResourceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func (f *scimFixture) createGroup(t *testing.T, displayName string, members ...string) string {
	t.Helper()
	list := make([]string, 0, len(members))
	for _, m := range members {
		list = append(list, fmt.Sprintf(`{"value":%q}`, m))
	}
	body := fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		  "externalId":%q,"displayName":%q,"members":[%s]}`,
		"ext-grp-"+displayName+fmt.Sprint(time.Now().UnixNano()),
		displayName, strings.Join(list, ","))

	status, resp := f.do(t, http.MethodPost, "/scim/v2/Groups", body)
	if status != http.StatusCreated {
		t.Fatalf("creating group %q gave %d: %v", displayName, status, resp)
	}
	id, _ := resp["id"].(string)
	if id == "" {
		t.Fatalf("no group resource id: %v", resp)
	}
	return id
}

func TestGroupProvisioningLifecycle(t *testing.T) {
	f := newSCIMFixture(t)

	gid := f.createGroup(t, "Engineering Team", f.userA)
	if !f.inGroup(t, gid, f.userA) {
		t.Fatal("the member the group was created with is not in it")
	}

	// The display name has a space, which core.groups.name forbids. The derived
	// name is what a token carries.
	var name string
	if err := f.pool.QueryRow(context.Background(), `
		SELECT g.name FROM core.groups g
		JOIN core.scim_source_group_links l ON l.group_id = g.id
		WHERE l.resource_id::text = $1`, gid).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Engineering-Team" {
		t.Errorf("group name = %q, want Engineering-Team derived from the display name", name)
	}

	// Add, Entra's dialect.
	status, body := f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		  "Operations":[{"op":"add","path":"members","value":[{"value":%q}]}]}`, f.userB))
	if status != http.StatusOK {
		t.Fatalf("adding a member gave %d: %v", status, body)
	}
	if !f.inGroup(t, gid, f.userB) {
		t.Fatal("the added member is not in the group")
	}
	if !f.inGroup(t, gid, f.userA) {
		t.Fatal("adding one member removed the other")
	}

	status, body = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid,
		pathFilterRemoveMember(t, f.userA))
	if status != http.StatusOK {
		t.Fatalf("path-filter removal gave %d: %v", status, body)
	}
	if f.inGroup(t, gid, f.userA) {
		t.Fatal("the removed member is still in the group, and the upstream was " +
			"told the removal succeeded — it will never send it again")
	}
	if !f.inGroup(t, gid, f.userB) {
		t.Fatal("removing one member removed the other too")
	}
	if got := memberIDs(body); len(got) != 1 || got[0] != f.userB {
		t.Errorf("members in the response = %v, want only %s", got, f.userB)
	}

	// Rename. The token-visible name must follow, or every application still
	// matches on a string nobody uses.
	status, body = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid,
		`{"Operations":[{"op":"replace","value":{"displayName":"Engineering EU"}}]}`)
	if status != http.StatusOK {
		t.Fatalf("rename gave %d: %v", status, body)
	}
	if err := f.pool.QueryRow(context.Background(), `
		SELECT g.name FROM core.groups g
		JOIN core.scim_source_group_links l ON l.group_id = g.id
		WHERE l.resource_id::text = $1`, gid).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Engineering-EU" {
		t.Errorf("after rename the group name is %q", name)
	}
	// And the membership survived the rename, which is the reason external_id is
	// the match key rather than displayName.
	if !f.inGroup(t, gid, f.userB) {
		t.Fatal("renaming the group emptied it")
	}

	// Deprovision.
	status, _ = f.do(t, http.MethodDelete, "/scim/v2/Groups/"+gid, "")
	if status != http.StatusNoContent {
		t.Fatalf("DELETE gave %d", status)
	}
	if f.inGroup(t, gid, f.userB) {
		t.Fatal("a deprovisioned group still grants membership")
	}
}

// `replace` on the member list removes everybody not named. Read as an add, a
// departed employee stays in the group while the upstream reports success.
func TestReplacingTheMemberListRemovesAbsentMembers(t *testing.T) {
	f := newSCIMFixture(t)
	gid := f.createGroup(t, "Ops", f.userA, f.userB)

	status, body := f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, fmt.Sprintf(
		`{"Operations":[{"op":"replace","path":"members","value":[{"value":%q}]}]}`, f.userB))
	if status != http.StatusOK {
		t.Fatalf("replace gave %d: %v", status, body)
	}
	if f.inGroup(t, gid, f.userA) {
		t.Fatal("a member absent from a whole-list replacement stayed in the group")
	}
	if !f.inGroup(t, gid, f.userB) {
		t.Fatal("the named member is not in the group")
	}
}

// A PATCH the parser cannot read must be refused, not answered 200.
func TestAnUnreadableGroupPatchIsRefused(t *testing.T) {
	f := newSCIMFixture(t)
	gid := f.createGroup(t, "Support", f.userA)

	status, _ := f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid,
		`{"Operations":[{"op":"remove","path":"members[displayName eq \"Alice\"]"}]}`)
	if status == http.StatusOK {
		t.Fatal("a removal naming an attribute we cannot resolve was answered 200; " +
			"the upstream records it as done and never retries")
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
	// And nothing changed.
	if !f.inGroup(t, gid, f.userA) {
		t.Error("a refused PATCH still changed the membership")
	}
}

// A member naming a user this source never provisioned is a 400 with the reason,
// not a 500. An upstream retries a 500 unchanged forever.
func TestAMemberThatIsNotProvisionedIsRefusedWithAReason(t *testing.T) {
	f := newSCIMFixture(t)
	gid := f.createGroup(t, "Finance")

	status, body := f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid,
		`{"Operations":[{"op":"add","path":"members",
		  "value":[{"value":"00000000-0000-0000-0000-000000000000"}]}]}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", status, body)
	}
	if d, _ := body["detail"].(string); !strings.Contains(d, "provision") {
		t.Errorf("the error does not say what to do about it: %v", body)
	}
}

// Filtering by displayName is what an upstream does before creating a group.
// An unrecognised filter must be refused rather than ignored: ignoring it
// returns the whole collection, and the upstream then matches the wrong group.
func TestGroupFiltering(t *testing.T) {
	f := newSCIMFixture(t)
	f.createGroup(t, "Alpha")
	f.createGroup(t, "Beta")

	status, body := f.do(t, http.MethodGet,
		`/scim/v2/Groups?filter=displayName+eq+%22Alpha%22`, "")
	if status != http.StatusOK {
		t.Fatalf("filtered list gave %d: %v", status, body)
	}
	total, _ := body["totalResults"].(float64)
	if total != 1 {
		t.Errorf("totalResults = %v, want 1: %v", total, body)
	}

	status, _ = f.do(t, http.MethodGet,
		`/scim/v2/Groups?filter=id+eq+%22whatever%22`, "")
	if status != http.StatusBadRequest {
		t.Errorf("an unrecognised filter gave %d; ignoring it returns everything "+
			"and the upstream matches the wrong group", status)
	}
}

// Groups appear in /ResourceTypes only because they are implemented. The rule
// this project holds everywhere: an upstream acts on what it reads there.
func TestGroupsAreAdvertisedInResourceTypes(t *testing.T) {
	f := newSCIMFixture(t)
	status, body := f.do(t, http.MethodGet, "/scim/v2/ResourceTypes", "")
	if status != http.StatusOK {
		t.Fatalf("ResourceTypes gave %d", status)
	}
	resources, _ := body["Resources"].([]any)
	found := false
	for _, r := range resources {
		rr, _ := r.(map[string]any)
		if rr["id"] == "Group" {
			found = true
			if rr["endpoint"] != "/Groups" {
				t.Errorf("Group endpoint = %v", rr["endpoint"])
			}
		}
	}
	if !found {
		t.Error("Groups are implemented and not advertised, so no upstream will sync them")
	}
	// And what is advertised must answer.
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Groups", ""); status != http.StatusOK {
		t.Errorf("/Groups is advertised and answered %d", status)
	}
}

// Unauthenticated requests reach nothing.
func TestGroupEndpointsRequireAuthentication(t *testing.T) {
	f := newSCIMFixture(t)
	for _, path := range []string{"/scim/v2/Groups", "/scim/v2/Groups/whatever"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token gave %d, want 401", path, rec.Code)
		}
	}
}

func pathFilterRemoveMember(t *testing.T, resourceID string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{
			"op":   "remove",
			"path": fmt.Sprintf(`members[value eq "%s"]`, resourceID),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestSCIMGroupMembershipReachesATokenAndIsRevokedByRemoval(t *testing.T) {
	f := newSCIMFixture(t)
	ctx := context.Background()

	gid := f.createGroup(t, "Engineering Team", f.userA)

	// A client, and the release policy that permits it to see groups at all.
	// Release is an allow-list: a client with no row gets nothing, so without
	// this the test would pass for the wrong reason.
	clientID := "scim-grp-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1,$2::uuid,'T','public','', ARRAY['authorization_code'],
		        ARRAY['openid','groups'], true)`, clientID, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = f.pool.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, clientID)
	})
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.client_group_release (client_id, org_id, only_groups)
		VALUES ($1, $2::uuid, ARRAY[]::text[])`, clientID, f.orgID); err != nil {
		t.Fatal(err)
	}

	// The local user id behind the SCIM resource id, which is what the token
	// path is keyed on.
	var localUserID string
	if err := f.pool.QueryRow(ctx, `
		SELECT user_id::text FROM core.scim_source_links
		WHERE source_id = $1::uuid AND resource_id::text = $2`,
		f.srcID, f.userA).Scan(&localUserID); err != nil {
		t.Fatal(err)
	}

	groups, err := store.GroupsForUser(ctx, f.pool, localUserID, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != "Engineering-Team" {
		t.Fatalf("groups in a token = %v, want [Engineering-Team]: SCIM provisioned "+
			"the membership and the token path does not see it", groups)
	}

	status, _ := f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, pathFilterRemoveMember(t, f.userA))
	if status != http.StatusOK {
		t.Fatalf("removal gave %d", status)
	}
	groups, err = store.GroupsForUser(ctx, f.pool, localUserID, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Fatalf("groups in a token = %v after the upstream removed the member; "+
			"the person keeps whatever the group grants and a provisioning client shows them as "+
			"removed", groups)
	}
}

// The operations cap on the wire, RFC 7644 §3.12's scimType included.
//
// Asserted against a group id that does NOT exist, deliberately. The cap has to
// fire before the lookup, because the point of it is to refuse the work rather
// than to do it and report afterwards -- a 404 here would mean the server had
// already gone to the database once for a request it was always going to
// refuse. Getting "tooMany" rather than "not found" is the evidence for that
// ordering.
func TestAnOversizedPatchIsRefusedBeforeAnyLookup(t *testing.T) {
	f := newSCIMFixture(t)

	var ops []string
	for i := 0; i <= scim.MaxPatchOperations; i++ { // one over
		ops = append(ops, fmt.Sprintf(
			`{"op":"add","path":"members","value":[{"value":"u-%d"}]}`, i))
	}
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	          "Operations":[` + strings.Join(ops, ",") + `]}`

	status, resp := f.do(t, http.MethodPatch,
		"/scim/v2/Groups/00000000-0000-0000-0000-000000000000", body)

	if status != http.StatusBadRequest {
		t.Fatalf("%d operations answered %d %v; want 400", scim.MaxPatchOperations+1,
			status, resp)
	}
	if resp["scimType"] != "tooMany" {
		t.Errorf("scimType = %v, want tooMany (RFC 7644 §3.12) so the client knows "+
			"to split the batch rather than treat it as permanent", resp["scimType"])
	}
	// A group PATCH at the limit reaches the lookup and 404s, which is the
	// proof that 100 is not itself being refused.
	ok := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	        "Operations":[` + strings.Join(ops[:scim.MaxPatchOperations], ",") + `]}`
	status, _ = f.do(t, http.MethodPatch,
		"/scim/v2/Groups/00000000-0000-0000-0000-000000000000", ok)
	if status == http.StatusBadRequest {
		t.Errorf("a PATCH at exactly the limit was refused as malformed; the cap "+
			"must admit the documented number, got %d", status)
	}
}
