package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// protectionClients lets the fixture's two clients act as resource servers: the
// client credentials grant, and uma_protection among their scopes.
func (f *cibaFixture) protectionClients(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients
		SET grant_types = array_append(grant_types, 'client_credentials'),
		    scopes = array_append(scopes, 'uma_protection')
		WHERE client_id = ANY($1)`, []string{f.clientID, f.otherClient}); err != nil {
		t.Fatal(err)
	}
}

// orgPAT is a PAT the organisation granted, by the client credentials grant at the
// real token endpoint.
func (f *cibaFixture) orgPAT(t *testing.T, clientID, secret string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"uma_protection"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var got struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.AccessToken == "" {
		t.Fatalf("no PAT (%d): %s", rec.Code, rec.Body.String())
	}
	return got.AccessToken
}

// personPAT is a PAT a person granted the fixture client, minted as a sign-in
// would mint it, with a live session behind it.
func (f *cibaFixture) personPAT(t *testing.T, userID string, scopes ...string) string {
	t.Helper()
	ctx := context.Background()
	sid := "pat-sid-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, '1', ARRAY['pwd'], now(), now() + interval '1 hour')`,
		sid, store.HashToken(sid), f.orgID, userID); err != nil {
		t.Fatal(err)
	}
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) == 0 {
		scopes = []string{"uma_protection"}
	}
	var raw string
	if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		resp, _, err := f.srv.mintSet(ctx, tx, c, f.orgID, userID, sid, "", scopes, nil, nil, "")
		if err == nil {
			raw = resp.AccessToken
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

// protect calls the protection API with a PAT.
func (f *cibaFixture) protect(t *testing.T, method, path, pat, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

const reportResource = `{"resource_scopes":["read"],"type":"document","name":"Q3 report","description":"the board pack"}`

// The five operations of Federated Authorization §3.2, each held to the resource
// server that registered the resource; a type the model does not have, a scope it
// has no action for, and a type changed after registration are refused, since the
// model is what decides about it; deregistering takes what was granted on it.
func TestAResourceServerRegistersAndManagesItsResources(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.protectionClients(t)
	ctx := context.Background()
	pat := f.orgPAT(t, f.clientID, f.secret)

	if rec, _ := f.protect(t, http.MethodPost, umaResourcePath, "", reportResource); rec.Code != http.StatusUnauthorized {
		t.Errorf("no PAT answered %d", rec.Code)
	}
	if rec, _ := f.protect(t, http.MethodPost, umaResourcePath, f.personPAT(t, f.userID, "openid"),
		reportResource); rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("a token without uma_protection answered %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	for name, c := range map[string]struct{ body, says string }{
		// error_description holds no double quote (RFC 6749 §5.2), so a name is in single ones.
		"a type the model has not got": {`{"resource_scopes":["read"],"type":"photo"}`, `'photo' is not a type`},
		"a scope it has no action for": {`{"resource_scopes":["read","print"],"type":"document"}`, `'print' is not an action`},
	} {
		rec, out := f.protect(t, http.MethodPost, umaResourcePath, pat, c.body)
		if desc, _ := out["error_description"].(string); rec.Code != http.StatusBadRequest || out["error"] != "invalid_request" ||
			!strings.Contains(desc, c.says) {
			t.Errorf("%s answered %d %v", name, rec.Code, out)
		}
	}

	rec, out := f.protect(t, http.MethodPost, umaResourcePath, pat, reportResource)
	id, _ := out["_id"].(string)
	if rec.Code != http.StatusCreated || id == "" || rec.Header().Get("Location") != f.srv.umaResourceURL(id) {
		t.Fatalf("create answered %d %v at %q", rec.Code, out, rec.Header().Get("Location"))
	}
	if _, has := out["user_access_policy_uri"]; has {
		t.Errorf("the organisation's resource was given a person's page: %v", out)
	}
	if rec, _ := f.protect(t, http.MethodGet, umaResourcePath, pat, ""); rec.Code != http.StatusOK ||
		strings.TrimSpace(rec.Body.String()) != `["`+id+`"]` {
		t.Errorf("list answered %d %s", rec.Code, rec.Body.String())
	}
	if _, out := f.protect(t, http.MethodGet, umaResourcePath+"/"+id, pat, ""); out["_id"] != id || out["name"] != "Q3 report" ||
		out["type"] != "document" {
		t.Errorf("read answered %v", out)
	}
	if rec, out := f.protect(t, http.MethodPut, umaResourcePath+"/"+id, pat,
		`{"resource_scopes":["read"],"type":"invoice"}`); rec.Code != http.StatusBadRequest || !strings.Contains(out["error_description"].(string), "keeps its type") {
		t.Errorf("a new type answered %d %v", rec.Code, out)
	}
	// A PUT replaces: what it does not say is gone.
	if rec, out := f.protect(t, http.MethodPut, umaResourcePath+"/"+id, pat, `{"resource_scopes":["read"],"type":"document"}`); rec.Code != http.StatusOK || out["_id"] != id {
		t.Errorf("update answered %d %v", rec.Code, out)
	}
	if _, out := f.protect(t, http.MethodGet, umaResourcePath+"/"+id, pat, ""); out["name"] != nil {
		t.Errorf("the replaced description kept %v", out)
	}
	if rec, out := f.protect(t, http.MethodPatch, umaResourcePath+"/"+id, pat, "{}"); rec.Code != http.StatusMethodNotAllowed ||
		out["error"] != "unsupported_method_type" || rec.Header().Get("Allow") == "" {
		t.Errorf("PATCH answered %d %v", rec.Code, out)
	}

	// Another resource server cannot see it, change it or ask about it.
	other := f.orgPAT(t, f.otherClient, f.otherSecret)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if rec, out := f.protect(t, m, umaResourcePath+"/"+id, other, reportResource); rec.Code != http.StatusNotFound ||
			out["error"] != "not_found" {
			t.Errorf("another resource server's %s answered %d %v", m, rec.Code, out)
		}
	}
	if rec, _ := f.protect(t, http.MethodGet, umaResourcePath, other, ""); strings.TrimSpace(rec.Body.String()) != `[]` {
		t.Errorf("another resource server lists %s", rec.Body.String())
	}

	// §4.1: a permission by the id alone, held to what was registered.
	permit := func(token, body string) (int, map[string]any) {
		rec, out := f.protect(t, http.MethodPost, "/uma2/permission", token, body)
		return rec.Code, out
	}
	code, got := permit(pat, `{"resource_id":"`+id+`","resource_scopes":["read"]}`)
	ticket, _ := got["ticket"].(string)
	if code != http.StatusCreated || ticket == "" {
		t.Fatalf("a permission on the registered resource answered %d %v", code, got)
	}
	held, err := store.RedeemPermissionTicket(ctx, f.pool, store.HashToken(ticket))
	if err != nil || len(held.Permissions) != 1 || held.Permissions[0].ResourceType != "document" ||
		held.Permissions[0].ResourceID != id {
		t.Errorf("the ticket holds %+v (%v)", held, err)
	}
	for name, c := range map[string]struct{ token, body, want string }{
		"a scope it was not registered with": {pat, `{"resource_id":"` + id + `","resource_scopes":["write"]}`, "invalid_scope"},
		"an id nobody registered":            {pat, `{"resource_id":"nothing","resource_scopes":["read"]}`, "invalid_resource_id"},
		"another resource server's":          {other, `{"resource_id":"` + id + `","resource_scopes":["read"]}`, "invalid_resource_id"},
	} {
		if code, got := permit(c.token, c.body); code != http.StatusBadRequest || got["error"] != c.want {
			t.Errorf("%s answered %d %v, want %s", name, code, got, c.want)
		}
	}

	// Deregistered, with what was granted on it.
	if err := store.GrantRelation(ctx, f.pool, f.orgID, store.Relation{SubjectType: "user", SubjectID: f.email,
		Relation: "viewer", ObjectType: "document", ObjectID: id}, ""); err != nil {
		t.Fatal(err)
	}
	if rec, _ := f.protect(t, http.MethodDelete, umaResourcePath+"/"+id, pat, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete answered %d %s", rec.Code, rec.Body.String())
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.relations WHERE org_id = $1::uuid AND object_type = 'document'
		AND object_id = $2`, f.orgID, id).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d relations outlived the resource (%v)", left, err)
	}
	if rec, _ := f.protect(t, http.MethodGet, umaResourcePath+"/"+id, pat, ""); rec.Code != http.StatusNotFound {
		t.Errorf("a deregistered resource reads %d", rec.Code)
	}
	if code, got := permit(pat, `{"resource_id":"`+id+`","resource_scopes":["read"]}`); got["error"] != "invalid_resource_id" {
		t.Errorf("a deregistered resource was asked about: %d %v", code, got)
	}
	var recorded int
	if err := f.pool.QueryRow(ctx, `SELECT count(DISTINCT event_type) FROM core.audit_events WHERE org_id = $1::uuid
		AND event_type IN ('uma.resource_registered', 'uma.resource_updated', 'uma.resource_deregistered')
		AND detail->>'resource_id' = $2`, f.orgID, id).Scan(&recorded); err != nil || recorded != 3 {
		t.Errorf("%d of the three changes were recorded (%v)", recorded, err)
	}
}

// A person shares what a resource server registered as theirs, from their page, as
// one of the relations the model gives its type, and stops; nobody else can share
// it, as nothing else, with an address that is not one, or from another site.
func TestAPersonSharesWhatTheyOwnFromTheirPage(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.protectionClients(t)
	ctx := context.Background()
	_, out := f.protect(t, http.MethodPost, umaResourcePath, f.personPAT(t, f.userID), reportResource)
	id, _ := out["_id"].(string)
	if id == "" {
		t.Fatalf("no resource: %v", out)
	}
	owner, stranger := f.browserSession(t, f.userID), f.browserSession(t, f.otherUserID)

	page := func(cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, umaResourcePage, nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	mine := page(owner)
	if body := mine.Body.String(); mine.Code != http.StatusOK || !strings.Contains(body, "Q3 report") ||
		!strings.Contains(body, `<option>viewer</option>`) || !strings.Contains(body, "Shared with nobody") {
		t.Fatalf("the owner's page (%d):\n%s", mine.Code, body)
	}
	if body := page(stranger).Body.String(); strings.Contains(body, "Q3 report") {
		t.Error("somebody else's page lists it")
	}

	post := func(cookie, path string, form url.Values, csrf bool) string {
		t.Helper()
		token := csrfFrom(t, page(cookie))
		if csrf {
			form.Set(csrfFormField, token)
		}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code == http.StatusSeeOther {
			return rec.Header().Get("Location")
		}
		return strconv.Itoa(rec.Code)
	}
	shares := func() []string {
		rows, _, err := store.ListRelations(ctx, f.pool, f.orgID, "", "", "document", id, 10)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Subject+" "+r.Relation)
		}
		return out
	}
	share := func(email, relation string) url.Values {
		return url.Values{"resource": {id}, "email": {email}, "relation": {relation}}
	}

	for name, c := range map[string]struct {
		cookie string
		form   url.Values
		csrf   bool
		want   string
	}{
		"from another site":         {owner, share("grace@example.test", "viewer"), false, "400"},
		"by somebody else":          {stranger, share("grace@example.test", "viewer"), true, "m=refused"},
		"as a relation it has none": {owner, share("grace@example.test", "owner"), true, "m=refused"},
		"with no address":           {owner, share("grace", "viewer"), true, "m=refused"},
	} {
		if got := post(c.cookie, umaResourcePage+"/share", c.form, c.csrf); !strings.Contains(got, c.want) {
			t.Errorf("%s answered %q", name, got)
		}
	}
	if got := shares(); len(got) != 0 {
		t.Fatalf("refused shares were made: %v", got)
	}

	if got := post(owner, umaResourcePage+"/share", share(" Grace@Example.TEST ", "viewer"), true); !strings.Contains(got, "m=shared") {
		t.Fatalf("sharing answered %q", got)
	}
	if got := shares(); len(got) != 1 || got[0] != "user:grace@example.test viewer" {
		t.Errorf("shared as %v", got)
	}
	if body := page(owner).Body.String(); !strings.Contains(body, "grace@example.test") {
		t.Errorf("the page does not show the share:\n%s", body)
	}
	if got := post(owner, umaResourcePage+"/unshare", share("grace@example.test", "viewer"), true); !strings.Contains(got, "m=unshared") {
		t.Fatalf("unsharing answered %q", got)
	}
	if got := shares(); len(got) != 0 {
		t.Errorf("still shared: %v", got)
	}
}

// What a person registers through a PAT they granted is theirs: neither the
// organisation's PAT nor another person's reaches it, a request mixes no two
// owners, and a PAT stops standing for somebody deactivated.
func TestAPersonsResourcesAreTheirsAlone(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.protectionClients(t)
	ctx := context.Background()
	ada, other, org := f.personPAT(t, f.userID), f.personPAT(t, f.otherUserID), f.orgPAT(t, f.clientID, f.secret)

	rec, out := f.protect(t, http.MethodPost, umaResourcePath, ada, reportResource)
	id, _ := out["_id"].(string)
	if rec.Code != http.StatusCreated || !strings.HasSuffix(out["user_access_policy_uri"].(string), umaResourcePage+"#"+id) {
		t.Fatalf("a person's create answered %d %v", rec.Code, out)
	}
	for name, pat := range map[string]string{"the organisation's PAT": org, "another person's": other} {
		if rec, _ := f.protect(t, http.MethodGet, umaResourcePath+"/"+id, pat, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s read it: %d", name, rec.Code)
		}
	}
	_, out = f.protect(t, http.MethodPost, umaResourcePath, org, reportResource)
	orgs, _ := out["_id"].(string)

	// With the client's own credentials, the first registered resource decides the owner.
	if code, got := f.permission(t, f.clientID, f.secret, `{"resource_id":"`+id+`","resource_scopes":["read"]}`); code != http.StatusCreated {
		t.Errorf("a permission on a person's resource by client credentials answered %d %v", code, got)
	}
	for _, body := range []string{
		`[{"resource_id":"` + id + `","resource_scopes":["read"]},{"resource_id":"` + orgs + `","resource_scopes":["read"]}]`,
		`[{"resource_id":"` + orgs + `","resource_scopes":["read"]},{"resource_id":"` + id + `","resource_scopes":["read"]}]`,
	} {
		if code, got := f.permission(t, f.clientID, f.secret, body); code != http.StatusBadRequest || got["error"] != "invalid_resource_id" {
			t.Errorf("two owners in one request answered %d %v", code, got)
		}
	}
	if rec, out := f.protect(t, http.MethodPost, "/uma2/permission", other, `{"resource_id":"`+id+`","resource_scopes":["read"]}`); out["error"] != "invalid_resource_id" {
		t.Errorf("another person's PAT asked about it: %d %v", rec.Code, out)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `UPDATE core.users SET status = 'active' WHERE id = $1::uuid`, f.userID)
	})
	if rec, _ := f.protect(t, http.MethodGet, umaResourcePath, ada, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("a deactivated person's PAT answered %d %s", rec.Code, rec.Body.String())
	}
}
