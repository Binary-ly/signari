package docsync

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Guard 0.74: a uuid key is compared as itself.
//
// Through its text a uuid column can use no index, its primary key included, so
// `id::text = $1` reads the table to find one row. 0.53 turned most of them into
// store.ExactUUIDOrNil and left no guard, and an organisation's budgets went on
// being read that way, on every sign-in, at a cost in the number of tenants, until
// a run at a thousand organisations counted the rows. A cast costs nothing beside
// another column the table can be found by, which is why org_id is an excuse and
// the tables below are: each is small for the life of a deployment.
var fewRows = map[string]string{
	"instances":    "a deployment has a handful",
	"admin_tokens": "an operator's own credentials, tens at most",
}

var (
	keyAsText    = regexp.MustCompile(`(?i)(^|[^a-z_])([a-z_]+\.)?id::text\s*=\s*\$[0-9]+`)
	keySideTable = regexp.MustCompile(`(?i)\b(?:from|update|join)\s+core\.([a-z_]+)`)
	keyByPerson  = regexp.MustCompile(`(?i)\b([a-z_]+\.)?(user_id|client_id)\s*=\s*\$[0-9]+`)
)

// readsThroughItsText reports whether sql finds a row by the text of its key with
// nothing else to find it by.
func readsThroughItsText(sql string) bool {
	if !keyAsText.MatchString(sql) || orgCompared.MatchString(sql) || keyByPerson.MatchString(sql) {
		return false
	}
	tables := keySideTable.FindAllStringSubmatch(sql, -1)
	if len(tables) == 0 {
		return true
	}
	for _, m := range tables {
		if fewRows[m[1]] == "" {
			return true
		}
	}
	return false
}

func TestNoKeyIsReadThroughItsText(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var found []string
	err := filepath.Walk(filepath.Join(root, "engine"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, p)
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && readsThroughItsText(lit.Value) {
				found = append(found, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), fset.Position(lit.Pos()).Line,
					strings.Join(strings.Fields(lit.Value), " ")))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("%s\n\tThrough its text a uuid can use no index, so this reads the table to find one row. "+
			"Compare `id = $1::uuid` and bind store.ExactUUIDOrNil, or, for a table that stays small for the "+
			"life of a deployment, add it to fewRows with why", f)
	}
}

// What the guard has to tell apart, in both directions.
func TestTheTextKeyGuardReadsWhatItShould(t *testing.T) {
	for _, sql := range []string{
		`SELECT a FROM core.organizations WHERE id::text = $1`,
		`UPDATE core.sessions s SET a = 1 WHERE s.id::text = $2`,
		`id::text = $1`,
	} {
		if !readsThroughItsText(sql) {
			t.Errorf("not flagged: %s", sql)
		}
	}
	for _, sql := range []string{
		`SELECT a FROM core.organizations WHERE id = $1::uuid`,
		`SELECT a FROM core.saml_providers WHERE id::text = $1 AND org_id = $2::uuid`,
		`SELECT a FROM core.instances WHERE id::text = $1`,
		`SELECT a FROM core.clients WHERE instance_id::text = $1`,
		`SELECT id::text FROM core.users WHERE email_fold = $1`,
	} {
		if readsThroughItsText(sql) {
			t.Errorf("flagged: %s", sql)
		}
	}
}
