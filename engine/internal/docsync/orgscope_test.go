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

// Guard 0.08f: a lookup by a name scopes itself to an organisation.
//
// Names are chosen per tenant. An email, a username, a slug, a group name and
// an entity ID are unique within one organisation at most, so a query that
// finds a row by one of them and does not say which organisation's has picked
// whichever tenant the database happened to return. That was the RADIUS VLAN
// lookup handing out another tenant's VLAN for the same username (ST-M19), the
// federation slug matching across tenants (FE-8), and the password form looking
// an address up everywhere at once (1.13b).
//
// The rule is read off the SQL: a statement whose WHERE compares one of those
// columns to a parameter must also name org_id, or filter by a person's own
// user_id (a person belongs to one organisation), or be one of the keys below
// that are unique across the deployment on purpose.
var globalNameKeys = map[string]string{
	"identity_providers.slug": "unique across organisations since migration 0129: the " +
		"slug is in the callback URL, which the upstream provider does not scope",
	"saml_providers.entity_id": "unique across organisations since migration 0130: an " +
		"AuthnRequest names an entity ID, not a tenant",
}

var (
	sqlStatement = regexp.MustCompile(`(?is)\b(select|update|delete)\b.*\bwhere\b`)
	whereClause  = regexp.MustCompile(`(?is)\bwhere\b(.*)`)
	byName       = regexp.MustCompile(`(?i)(lower\(\s*)?\b([a-z_]+\.)?(email|username|slug|name|entity_id)\b\s*\)?\s*=\s*(lower\(\s*)?\$[0-9]+`)
	byPerson     = regexp.MustCompile(`(?i)\b([a-z_]+\.)?user_id\s*=\s*\$[0-9]+`)
	fromTable    = regexp.MustCompile(`(?i)\b(?:from|update|join|using)\s+core\.([a-z_]+)`)
)

func TestEveryLookupByNameIsScopedToAnOrganisation(t *testing.T) {
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
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			sql := lit.Value
			if !sqlStatement.MatchString(sql) {
				return true
			}
			where := whereClause.FindStringSubmatch(sql)[1]
			m := byName.FindStringSubmatch(where)
			if m == nil {
				return true
			}
			if strings.Contains(strings.ToLower(where), "org_id") || byPerson.MatchString(where) {
				return true
			}
			column := strings.ToLower(m[3])
			for _, tm := range fromTable.FindAllStringSubmatch(sql, -1) {
				if globalNameKeys[tm[1]+"."+column] != "" {
					return true
				}
			}
			found = append(found, fmt.Sprintf("%s:%d looks a row up by %s with no organisation: %s",
				rel, fset.Position(lit.Pos()).Line, column, strings.Join(strings.Fields(sql), " ")))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("%s\n\tA name is unique within one organisation at most, so this finds whichever "+
			"tenant's row the database returns first. Filter by org_id, or, if the key is "+
			"unique across the deployment by design, add it to globalNameKeys with the "+
			"migration that makes it so", f)
	}
	for key := range globalNameKeys {
		if !strings.Contains(key, ".") {
			t.Errorf("globalNameKeys entry %q is not table.column", key)
		}
	}
}
