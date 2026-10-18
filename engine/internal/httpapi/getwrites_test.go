package httpapi

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Guard 0.08a: no route a link can open changes the signed-in person's rows.
//
// TestNoAccountPageChangesTheAccountOnAGet covers /account, where the TOTP
// defect was. This is the same sweep over every route that answers GET: the
// "GET /path" registrations and the ones registered with no method, which
// answer GET too. That second kind is how /account/requests escaped the
// account sweep, whose pattern only matched "GET /account". The fingerprint
// takes in the person's own core.users row as well as every table with a
// user_id, which the account sweep also did not.
//
// The requests carry the session cookie and no parameters, so this proves the
// routes do not write on the bare visit a cross-site link makes most cheaply.
// A route that writes only with particular parameters is covered by its own
// tests, not by this one.
//
// knownWritesOnGET is the list that may only shrink: routes that change the
// person's rows on a GET by design, each with the reason it is safe.
var knownWritesOnGET = map[string]string{}

func TestNoGETChangesTheSignedInPersonsRows(t *testing.T) {
	if os.Getenv("SIGNARI_TEST_DSN") == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	f, cookie := enrolFixture(t)
	giveTOTP(t, f)
	ctx := context.Background()

	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	registration := regexp.MustCompile(`mux\.Handle(?:Func)?\("((?:GET )?/[^"]*)"`)
	param := regexp.MustCompile(`\{[^}]+\}`)
	seen := map[string]bool{}
	var paths []string
	for _, m := range registration.FindAllStringSubmatch(string(src), -1) {
		p := strings.TrimPrefix(m[1], "GET ")
		p = param.ReplaceAllString(p, "nonexistent")
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	if len(paths) < 40 {
		t.Fatalf("found only %d routes answering GET in server.go; the pattern is not matching", len(paths))
	}
	for p := range knownWritesOnGET {
		if !seen[p] {
			t.Errorf("knownWritesOnGET excuses %s, which is no longer a GET route", p)
		}
	}

	rows, err := f.pool.Query(ctx, `
		SELECT c.table_name FROM information_schema.columns c
		  JOIN information_schema.tables t
		    ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		 WHERE c.table_schema = 'core' AND c.column_name = 'user_id' AND t.table_type = 'BASE TABLE'
		 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()

	fingerprint := func() map[string]string {
		out := map[string]string{}
		var self string
		if err := f.pool.QueryRow(ctx,
			`SELECT md5(u::text) FROM core.users u WHERE id = $1::uuid`, f.userID).Scan(&self); err != nil {
			t.Fatalf("fingerprinting core.users: %v", err)
		}
		out["users"] = self
		for _, tbl := range tables {
			var h *string
			if err := f.pool.QueryRow(ctx, `SELECT md5(string_agg(t::text, '|' ORDER BY t::text))
				FROM core.`+tbl+` t WHERE user_id = $1::uuid`, f.userID).Scan(&h); err != nil {
				t.Fatalf("fingerprinting core.%s: %v", tbl, err)
			}
			if h != nil {
				out[tbl] = *h
			}
		}
		return out
	}

	for _, p := range paths {
		if knownWritesOnGET[p] != "" {
			continue
		}
		before := fingerprint()
		accountGET(f, cookie, p)
		after := fingerprint()
		for tbl, h := range before {
			if after[tbl] != h {
				t.Errorf("GET %s changed this person's rows in core.%s; a route a link can "+
					"open must not, or must be listed in knownWritesOnGET with why it is safe", p, tbl)
			}
		}
		for tbl := range after {
			if _, ok := before[tbl]; !ok {
				t.Errorf("GET %s created rows for this person in core.%s", p, tbl)
			}
		}
	}
}
