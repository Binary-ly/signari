package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/plancheck"
	"signari.dev/engine/internal/store/storetest"
)

// requestReadsWhole are the tables a request may read whole, each with why.
var requestReadsWhole = map[string]string{
	"sign_in_flows": "one goroutine reads them all every thirty seconds, for the cache ADR-008 declares",
}

// The first organisation of an instance is found by seeking it, not by sorting them
// all. Its statement has an index to seek by either way, so the other guard here
// cannot tell: what cost a thousand organisations a sort each sign-in is the Sort.
func TestTheFirstOrganisationIsNotSorted(t *testing.T) {
	f := newSignInFixture(t)
	plan, err := plancheck.Explain(context.Background(), f.pool, plancheck.Statement{SQL: firstOrgOfIssuer,
		Args: []any{f.srv.cfg.Issuer}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "Sort") || !strings.Contains(plan, "organizations_instance_age_idx") {
		t.Errorf("the first organisation is not read from its index:\n%s", plan)
	}
}

// What a person does, run past the planner (0.74). An organisation's budgets were
// read through the text of its key on every sign-in, and its first organisation was
// read and sorted twice, each a cost in the number of tenants, and neither shows in a
// test or at one organisation: it took a thousand of them and a count of the rows
// read. This sends the journey and asks about all of it, so that the next statement
// on it with nothing under it is found here and not by the first large deployment.
func TestNoRequestReadsATableWhole(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET first_party = true,
		grant_types = ARRAY['authorization_code','refresh_token'], scopes = ARRAY['openid','offline_access']
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	seen := &plancheck.Recorder{}
	cfg.ConnConfig.Tracer = seen
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.srv.db = pool

	// More than one organisation, and counted. With a table of one in its statistics
	// the planner walks the primary key and filters, which is what this looks for and
	// costs nothing there. Fixtures tidy enough to leave one row, and autovacuum
	// counting it part-way through a run, turned that into a failure on a clean tree.
	rows, err := f.pool.Query(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'Others'
		  FROM core.organizations, generate_series(1, 20) WHERE id = $1::uuid
		RETURNING id::text`, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	others, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, f.pool, others...)
	owner, err := pgx.Connect(ctx, os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close(ctx) }()
	if _, err := owner.Exec(ctx, `ANALYZE core.organizations`); err != nil {
		t.Fatal(err)
	}

	b := newTestBrowser(t, f.srv.Routes())
	wrong := b.post("/login", b.get("/login"), url.Values{"username": {f.email}, "password": {"not-the-password"}})
	if b.value(SessionCookieName) != "" {
		t.Fatalf("a wrong password signed in: %d", wrong.Code)
	}
	b.post("/login", b.get("/login"), url.Values{"username": {f.email}, "password": {signInTestPassword}})
	if b.value(SessionCookieName) == "" {
		t.Fatal("the fixture did not sign in")
	}

	q, err := url.ParseQuery(f.plainAuthz())
	if err != nil {
		t.Fatal(err)
	}
	q.Set("scope", "openid offline_access")
	coded := b.get(oidc.PathAuthorize + "?" + q.Encode())
	tokens := f.redeemPlain(t, coded)

	post := func(path string, form url.Values, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	refreshed := post(oidc.PathToken, url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID},
		"refresh_token": {tokens["refresh_token"].(string)}}, "")
	var again map[string]any
	if err := json.Unmarshal(refreshed.Body.Bytes(), &again); err != nil || refreshed.Code != http.StatusOK {
		t.Fatalf("the refresh answered %d: %.200s", refreshed.Code, refreshed.Body.String())
	}
	access := again["access_token"].(string)
	userinfo := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
	userinfo.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, userinfo)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo answered %d: %.200s", rec.Code, rec.Body.String())
	}
	b.get(oidc.PathEndSession + "?client_id=" + url.QueryEscape(f.clientID))

	found, checked, err := plancheck.Find(ctx, f.pool, seen.Take(), func(table, _ string) bool {
		return requestReadsWhole[table] != ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 20 {
		t.Fatalf("only %d statements came through the journey, so this looked at nothing", checked)
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("no index can serve this, so the request reads the table: %s", f)
	}
}
