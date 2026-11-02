package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/plancheck"
)

// adminReadsWhole are the tables an Admin API read may go through, each with why. A
// table belongs here for what bounds it, which is that somebody makes its rows by
// hand: nothing that grows with people, sign-ins or events.
var adminReadsWhole = map[string]string{
	"admin_tokens":                  "made by hand, and listed without a page because nobody has hundreds",
	"clients":                       "how many applications use an alias, on an operator's page; applications are thousands at most",
	"config_version":                "one row",
	"federation_trust_marks_issued": "each issued by an operator's command, and listed without a page",
	"identity_providers":            "an organisation's, a handful, on an operator's page",
	"instances":                     "the deployments on this database, a handful",
	"organizations":                 "the list of them is what was asked for, or a count of the suspended for readiness",
	"outbox":                        "one person's export, asked for by hand, of a table the janitor keeps short",
	"registration_tokens":           "made by hand, and listed without a page",
	"ssf_streams":                   "an organisation's receivers, a handful",
}

// pagesAllowed are the statements that may sort a page, each with why.
var pagesAllowed = []struct{ statement, why string }{
	{"FROM core.consents", "one person's, which a person has few of"},
	{"FROM core.credential_configurations", "the longest-lived of an instance's credential types, a handful"},
	{"FROM core.sessions", "one person's live sessions, which the session cap bounds"},
}

// heldOpenAllowed are the pages that may keep a condition with an OR, each with why.
var heldOpenAllowed = []struct{ statement, why string }{
	{"FROM core.audit_events", "a dozen optional filters, and the server moves to a generic plan only when it costs " +
		"no more, which reading the trail and sorting it does"},
	{"FROM core.relations", "its organisation and its cursor seek whatever else is asked, and the rest narrow the walk"},
	{"FROM core.sessions", "one person's live sessions, which the session cap bounds"},
}

var (
	// comparedAsText is a cursor kept by the text of its key.
	comparedAsText = regexp.MustCompile(`\w::text\s*>\s*\$\d`)
	// heldOpen is a condition written to hold when its parameter is empty.
	heldOpen = regexp.MustCompile(`\$\d+(?:::[a-z_\[\]]+)?\s+(?:IS NULL|=\s*'')\s+OR\b`)
)

func statementsOf(sent []plancheck.Statement) []string {
	out := make([]string, 0, len(sent))
	for _, s := range sent {
		out = append(out, s.SQL)
	}
	sort.Strings(out)
	return out
}

// newGroupOfPeople plants a group of five in an organisation, and answers it and the
// five in the order the lists page them.
func newGroupOfPeople(t *testing.T, s *Server, org string) (string, []string) {
	t.Helper()
	ctx := context.Background()
	var group string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'five', 'Five') RETURNING id::text`, org).Scan(&group); err != nil {
		t.Fatal(err)
	}
	var people []string
	for range 5 {
		person := newDelegationPerson(t, s, org)
		if _, err := s.db.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, person, org); err != nil {
			t.Fatal(err)
		}
		people = append(people, person)
	}
	sort.Strings(people)
	return group, people
}

// An organisation's page has an index in the order it pages, or it walks the primary
// key past everybody else's rows. The plans cannot say so: with sorting turned off
// that walk is what the planner answers with, and on a table this size it costs the
// same, so dropping any of these left the guard below green. Measured, an organisation
// of 1,000 among 100,000 people took three times as long without one.
func TestEveryOrganisationsPageHasAnIndexInItsOrder(t *testing.T) {
	s, _ := newTestServer(t)
	for _, page := range []struct{ table, key string }{
		{"users", "id"}, {"groups", "id"}, {"invitations", "id"}, {"clients", "client_id"},
	} {
		var held bool
		if err := s.db.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM pg_indexes
			                WHERE schemaname = 'core' AND tablename = $1
			                  AND indexdef NOT LIKE '% WHERE %' AND indexdef LIKE '%(org_id, ' || $2 || ')')`,
			page.table, page.key).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if !held {
			t.Errorf("core.%s has no index on (org_id, %s), which is the order its page reads", page.table, page.key)
		}
	}
}

// A page starts where the last one stopped, each row once and nobody else's, which
// the plans above say nothing of: a list that seeks to the wrong place is as fast. The
// conditions a statement leaves out are the organisation's among them, so a token of
// one organisation seeing exactly its own five is the tenant boundary too.
func TestAPageStartsWhereTheLastStopped(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftOrg(t, s)
	token := mintToken(t, s, "paging", org, []string{ScopeUsersRead, ScopeGroupsRead}, nil)
	group, people := newGroupOfPeople(t, s, org)

	var groups []string
	for i := range 4 {
		var id string
		if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
			VALUES ($1::uuid, $2, $2) RETURNING id::text`, org, fmt.Sprintf("more-%d", i)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		groups = append(groups, id)
	}
	groups = append(groups, group)
	sort.Strings(groups)

	for _, list := range []struct {
		path, key string
		want      []string
	}{
		{"/admin/users", "users", people},
		{"/admin/groups/" + group + "/members", "members", people},
		{"/admin/groups", "groups", groups},
	} {
		var got []string
		cursor := ""
		for page := range 4 {
			rec := call(t, s, http.MethodGet, list.path+"?limit=2&cursor="+cursor, token, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s answered %d: %.200s", list.path, rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			for _, row := range body[list.key].([]any) {
				got = append(got, row.(map[string]any)["id"].(string))
			}
			cursor, _ = body["next_cursor"].(string)
			if cursor == "" {
				break
			}
			if page == 3 {
				t.Fatalf("%s had not finished after four pages of two", list.path)
			}
		}
		if !slices.Equal(got, list.want) {
			t.Errorf("%s paged through\n %v\nwant\n %v", list.path, got, list.want)
		}
	}

	// Compared as a uuid, a cursor that could not be one would otherwise be an error
	// from the database, and a 500 for a client that sent nonsense.
	for _, path := range []string{"/admin/users", "/admin/groups", "/admin/groups/" + group + "/members", "/admin/invitations"} {
		rec := call(t, s, http.MethodGet, path+"?cursor=not-a-page", testToken, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_cursor") {
			t.Errorf("%s took a cursor that could not be one: %d %.200s", path, rec.Code, rec.Body.String())
		}
	}
}

// Every Admin API read, run past the planner (0.83). A page of an organisation's
// people read all of them and sorted them, one hundred rows or one, because `SELECT
// id::text ... ORDER BY id` orders by the text and no index holds that, and a later
// page walked from the start, because `id::text > $1` is not a seek. Neither shows at
// a test's size: it took 100,000 people and the first run of the load driver, which
// answered 18 pages a second at best.
func TestNoAdminReadReadsATableOrSortsAPage(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
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
	s.db = pool

	var sent []plancheck.Statement
	ask := func(path, token string) {
		t.Helper()
		seen.Take()
		if rec := call(t, s, http.MethodGet, path, token, nil); rec.Code != http.StatusOK {
			t.Errorf("GET %s answered %d: %.200s", path, rec.Code, rec.Body.String())
		}
		sent = append(sent, seen.Take()...)
	}
	for _, rt := range allReadRoutes() {
		ask(rt.path(t, s), testToken)
	}

	// The statements a page has only with a cursor or a filter, and only for a token
	// of one organisation, which is the one that seeks by it. A deployment-wide token
	// reads the primary key in order and is a different statement.
	const after = "?cursor=00000000-0000-4000-8000-000000000000"
	org := newDriftOrg(t, s)
	token := mintToken(t, s, "list-plans", org,
		[]string{ScopeUsersRead, ScopeClientsRead, ScopeGroupsRead, ScopeAuditRead}, nil)
	group, _ := newGroupOfPeople(t, s, org)
	// One group of two, and counted. A table the planner believes is empty has every
	// index cost the same, and it walks the wrong one.
	if _, err := s.db.Exec(ctx, `
		WITH g AS (
			INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, 'many', 'Many') RETURNING id
		), u AS (
			INSERT INTO core.users (org_id, email, user_handle)
			SELECT $1::uuid, gen_random_uuid()::text || '@example.test',
			       sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea)
			  FROM generate_series(1, 300)
			RETURNING id
		)
		INSERT INTO core.group_members (group_id, user_id, org_id) SELECT g.id, u.id, $1::uuid FROM g, u`, org); err != nil {
		t.Fatal(err)
	}
	// On a connection of its own: the role this pool takes owns nothing, and ANALYZE
	// by anybody but the owner skips the table with only a warning.
	owner, err := pgx.Connect(ctx, os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close(ctx) }()
	if _, err := owner.Exec(ctx, `ANALYZE core.group_members`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/users", "/admin/groups", "/admin/invitations", "/admin/clients",
		"/admin/users" + after, "/admin/groups" + after, "/admin/invitations" + after, "/admin/clients?cursor=m",
		"/admin/groups/" + group + "/members" + after, "/admin/audit-events?limit=5"} {
		ask(path, token)
		ask(path, testToken)
	}
	ask("/admin/invitations?org_id="+org, testToken)

	found, checked, err := plancheck.SortsToPage(ctx, s.db, sent, func(sql string) bool {
		return slices.ContainsFunc(pagesAllowed, func(a struct{ statement, why string }) bool {
			return strings.Contains(sql, a.statement)
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("only %d paged statements came through the reads, so this looked at nothing", checked)
	}
	whole, read, err := plancheck.Find(ctx, s.db, sent, func(table, _ string) bool { return adminReadsWhole[table] != "" })
	if err != nil {
		t.Fatal(err)
	}
	if read < 100 {
		t.Fatalf("only %d statements came through the reads, so this looked at nothing", read)
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("a page sorts or reads everything it could be taken from: %s", f)
	}
	// What a plan here cannot show. A page of one group that seeks the group and walks
	// it from the start to the cursor looks just like one that goes to the cursor. And a
	// statement that is prepared moves to a generic plan after a few runs, where a
	// condition held open by an OR is a filter and not a seek: a small organisation's
	// page walks the key past everybody else's rows, at a cost a test's table cannot
	// show, so it is the shape that is refused and not the plan.
	for _, sql := range slices.Compact(statementsOf(sent)) {
		if comparedAsText.MatchString(sql) {
			t.Errorf("a key compared as its text is no place to start from: %s", strings.Join(strings.Fields(sql), " "))
		}
		if strings.Contains(sql, "LIMIT") && heldOpen.MatchString(sql) &&
			!slices.ContainsFunc(heldOpenAllowed, func(a struct{ statement, why string }) bool {
				return strings.Contains(sql, a.statement)
			}) {
			t.Errorf("a page's condition is held open by an OR, so a generic plan cannot seek by it: %s",
				strings.Join(strings.Fields(sql), " "))
		}
	}
	sort.Strings(whole)
	for _, f := range whole {
		t.Errorf("no index can serve this, so the read goes through the table: %s", f)
	}
}
