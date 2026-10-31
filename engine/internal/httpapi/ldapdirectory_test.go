package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
)

type directoryFixture struct {
	pool    *pgxpool.Pool
	queries *statementCount
	auth    *LDAPAuthenticator
	orgID   string
}

// newDirectoryFixture is an organisation of n people, in a database that holds
// plenty of others, past the 500 the directory used to read.
func newDirectoryFixture(t *testing.T, n int) *directoryFixture {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
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
	queries := &statementCount{}
	cfg.ConnConfig.Tracer = queries
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	f := &directoryFixture{pool: pool, queries: queries}
	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://ldapdir-' || gen_random_uuid() || '.test', 'L') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'ld' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i
		RETURNING id::text`).Scan(&f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{`DELETE FROM core.users WHERE org_id = $1::uuid`,
			`DELETE FROM core.groups WHERE org_id = $1::uuid`,
			`DELETE FROM core.organizations WHERE id = $1::uuid`} {
			if _, err := pool.Exec(ctx, q, f.orgID); err != nil {
				t.Errorf("removing what the test made: %v", err)
			}
		}
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.users (org_id, user_handle, username, email, display_name)
		SELECT $1::uuid, sha256(convert_to($1::text || i::text, 'UTF8')), 'p' || i,
		       'mail' || i || '@example.test', 'Person ' || i
		FROM generate_series(1, $2::int) i`, f.orgID, n); err != nil {
		t.Fatal(err)
	}
	f.auth = NewLDAPAuthenticator(pool, passwords.Shared(), f.orgID,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return f
}

func (f *directoryFixture) serve(t *testing.T) *ldapclient.Conn {
	t.Helper()
	s := ldapd.New(ldapd.Config{BaseDN: "dc=example,dc=test", AllowAnonymousSearch: true, MaxResults: 100}, f.auth,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	c, err := ldapclient.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func directorySearch(filter string) *ldapclient.SearchRequest {
	return ldapclient.NewSearchRequest("dc=example,dc=test", ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, filter, []string{"uid", "mail", "memberOf"}, nil)
}

// Finding one person is one query, however many there are (7.01): it was the
// first 500 people read and filtered here, and anybody after them could not be
// found at all. Each way a filter can name somebody is asked of the database.
func TestOnePersonIsOneQueryThroughARealClient(t *testing.T) {
	f := newDirectoryFixture(t, 120)
	ctx := context.Background()
	var group string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, 'eng', 'Eng')
		RETURNING id::text`, f.orgID).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT $1::uuid, id, org_id FROM core.users WHERE org_id = $2::uuid AND username = 'p3'`,
		group, f.orgID); err != nil {
		t.Fatal(err)
	}
	c := f.serve(t)
	for filter, want := range map[string]string{
		"(uid=p119)":                                     "p119",
		"(UID=P119)":                                     "p119",
		"(mail=mail118@example.test)":                    "p118",
		"(cn=Person 117)":                                "p117",
		"(&(objectClass=person)(uid=p116))":              "p116",
		"(|(uid=nobody)(mail=mail115@example.test))":     "p115",
		"(memberOf=cn=eng,ou=groups,dc=example,dc=test)": "p3",
	} {
		before := f.queries.n.Load()
		res, err := c.Search(directorySearch(filter))
		if err != nil {
			t.Errorf("%s: %v", filter, err)
			continue
		}
		spent := f.queries.n.Load() - before
		if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("uid") != want {
			t.Errorf("%s found %d entries, want %s", filter, len(res.Entries), want)
		}
		if spent != 1 {
			t.Errorf("%s took %d statements, want 1", filter, spent)
		}
	}
	// Nothing to ask the database at all.
	before := f.queries.n.Load()
	if res, err := c.Search(directorySearch("(objectClass=device)")); err != nil || len(res.Entries) != 0 {
		t.Errorf("a class nobody is answered %v with %+v", err, res)
	}
	if spent := f.queries.n.Load() - before; spent != 0 {
		t.Errorf("a filter nobody can match took %d statements", spent)
	}
}

// A real client pages through everybody, each person once, with their groups,
// and a value is a value: nothing in it reaches the statement.
func TestTheWholeDirectoryPagesThroughARealClient(t *testing.T) {
	f := newDirectoryFixture(t, 120)
	ctx := context.Background()
	c := f.serve(t)
	res, err := c.SearchWithPaging(directorySearch("(objectClass=person)"), 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range res.Entries {
		seen[e.GetAttributeValue("uid")]++
	}
	if len(res.Entries) != 120 || len(seen) != 120 {
		t.Errorf("met %d entries and %d people of 120", len(res.Entries), len(seen))
	}

	// Without paging a list past the limit says so, rather than ending there.
	_, err = c.Search(directorySearch("(objectClass=person)"))
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultAdminLimitExceeded) {
		t.Errorf("reading 120 of a 100 limit answered %v", err)
	}

	for _, hostile := range []string{`' OR 1=1 --`, `p1'); DROP TABLE core.users; --`, `%`, `_1`} {
		found, err := f.auth.List(ctx, ldapd.Query{Limit: 10, Narrow: &ldapd.Condition{Op: ldapd.CondLogin, Value: hostile}})
		if err != nil || len(found) != 0 {
			t.Errorf("the value %q answered %v with %d people", hostile, err, len(found))
		}
	}
}

// A position is the directory's own, a person not listed stays unlisted, and a
// condition from across the boundary is held to the same limits as one made
// here.
func TestWhatListWillNotAnswer(t *testing.T) {
	f := newDirectoryFixture(t, 3)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.users SET status = 'deactivated' WHERE org_id = $1::uuid AND username = 'p1'`, f.orgID); err != nil {
		t.Fatal(err)
	}
	all, err := f.auth.List(ctx, ldapd.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("listed %d people, want the 2 active", len(all))
	}
	for _, id := range all {
		if id.Position == "" || id.Username == "p1" {
			t.Errorf("listed %+v", id)
		}
	}
	if got, err := f.auth.List(ctx, ldapd.Query{Limit: 10, After: all[0].Position}); err != nil || len(got) != 1 {
		t.Errorf("from the first position: %v, %d people", err, len(got))
	}
	if got, err := f.auth.List(ctx, ldapd.Query{Limit: 0}); err != nil || got != nil {
		t.Errorf("a limit of nothing: %v, %v", err, got)
	}
	if _, err := f.auth.List(ctx, ldapd.Query{Limit: 10, After: "not a position"}); !errors.Is(err, ldapd.ErrBadPosition) {
		t.Errorf("a made-up position answered %v", err)
	}

	deep := &ldapd.Condition{Op: ldapd.CondMail, Value: "x"}
	for i := 0; i < 40; i++ {
		deep = &ldapd.Condition{Op: ldapd.CondAnd, Of: []*ldapd.Condition{deep}}
	}
	for name, c := range map[string]*ldapd.Condition{
		"nested too deep":  deep,
		"of an unknown op": {Op: "drop"},
		"an empty AND":     {Op: ldapd.CondAnd},
	} {
		if _, err := f.auth.List(ctx, ldapd.Query{Limit: 10, Narrow: c}); err == nil ||
			!strings.Contains(err.Error(), "directory condition") {
			t.Errorf("a condition %s answered %v", name, err)
		}
	}

	if _, err := f.pool.Exec(ctx, `UPDATE core.organizations SET status = 'suspended' WHERE id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.auth.List(ctx, ldapd.Query{Limit: 10}); err != nil || len(got) != 0 {
		t.Errorf("a suspended organisation listed %d people: %v", len(got), err)
	}
}
