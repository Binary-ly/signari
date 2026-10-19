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
// An issuer and a host are names in the same sense: two tenants can trust one
// upstream issuer, and a host is whatever an operator typed. The SSF receiver
// found its source by issuer alone and routed one tenant's events to another's
// (1.66), and this guard did not see it, because it knew neither column.
//
// The rule is read off the SQL: a statement whose WHERE compares one of those
// columns to a parameter must also compare org_id to something, or filter by a
// person's own user_id (a person belongs to one organisation), or be one of the
// keys below that do not belong to a tenant. Comparing, not mentioning: the
// first version passed any WHERE containing the word, so `org_id IS NOT NULL`
// or an `ORDER BY org_id` excused a lookup that still returned whichever tenant
// came first.
var globalNameKeys = map[string]string{
	"identity_providers.slug": "unique across organisations since migration 0129: the " +
		"slug is in the callback URL, which the upstream provider does not scope",
	"saml_providers.entity_id": "unique across organisations since migration 0130: an " +
		"AuthnRequest names an entity ID, not a tenant",
	"instances.issuer": "unique since migration 0002: the issuer is the instance's own " +
		"identity, above every organisation it hosts",
	"instance_issuer_aliases.issuer": "unique since migration 0002: an alias is claimed by " +
		"one instance, above every organisation it hosts, and the statements name the instance",
	"federation_trust_marks_held.issuer": "the table has no organisation: a trust mark is " +
		"held by the federation entity, which is the instance, and the statement names it",
}

// globalPairKeys are keys unique across organisations only together with a
// second column, so a statement comparing both selects one organisation's row
// and one comparing the first alone does not.
var globalPairKeys = map[string]struct{ with, reason string }{
	"ssf_sources.issuer": {"audience", "unique with lower(audience) across organisations " +
		"since migration 0138: two tenants can trust one transmitter, and the audience is " +
		"what it writes to say whose an event is; SourceFor refuses a token whose several " +
		"audiences reach two"},
}

var (
	sqlStatement = regexp.MustCompile(`(?is)\b(select|update|delete)\b.*\bwhere\b`)
	whereClause  = regexp.MustCompile(`(?is)\bwhere\b(.*)`)
	byName       = regexp.MustCompile(`(?i)(lower\(\s*)?\b([a-z_]+\.)?(email|username|slug|name|entity_id|issuer|host)\b\s*\)?\s*=\s*(lower\(\s*)?\$[0-9]+`)
	byPerson     = regexp.MustCompile(`(?i)\b([a-z_]+\.)?user_id\s*=\s*\$[0-9]+`)
	// org_id on either side of =, IN or = ANY, with or without a cast.
	orgCompared = regexp.MustCompile(`(?i)\b([a-z_]+\.)?org_id\b(\s*::\s*[a-z]+)?\s*(=|\bin\b)|(=|\bin\b)\s*([a-z_]+\.)?org_id\b`)
	fromTable   = regexp.MustCompile(`(?i)\b(?:from|update|join|using)\s+core\.([a-z_]+)`)
)

// compares reports whether where compares column to something.
func compares(where, column string) bool {
	return regexp.MustCompile(`(?i)\b([a-z_]+\.)?` + column + `\b\s*\)?\s*(=|\bin\b)`).MatchString(where)
}

// unscopedNameLookup returns the name column sql finds a row by without
// choosing an organisation, or "" when it chooses one or needs none.
func unscopedNameLookup(sql string) string {
	if !sqlStatement.MatchString(sql) {
		return ""
	}
	where := whereClause.FindStringSubmatch(sql)[1]
	m := byName.FindStringSubmatch(where)
	if m == nil {
		return ""
	}
	if orgCompared.MatchString(where) || byPerson.MatchString(where) {
		return ""
	}
	column := strings.ToLower(m[3])
	for _, tm := range fromTable.FindAllStringSubmatch(sql, -1) {
		if globalNameKeys[tm[1]+"."+column] != "" {
			return ""
		}
		if pair, ok := globalPairKeys[tm[1]+"."+column]; ok && compares(where, pair.with) {
			return ""
		}
	}
	return column
}

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
			if column := unscopedNameLookup(sql); column != "" {
				found = append(found, fmt.Sprintf("%s:%d looks a row up by %s with no organisation: %s",
					rel, fset.Position(lit.Pos()).Line, column, strings.Join(strings.Fields(sql), " ")))
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
		t.Errorf("%s\n\tA name is unique within one organisation at most, so this finds whichever "+
			"tenant's row the database returns first. Filter by org_id, or, if the key is "+
			"unique across the deployment by design, add it to globalNameKeys (or, unique "+
			"only with a second column, globalPairKeys) with the migration that makes it so", f)
	}
	for key := range globalNameKeys {
		if !strings.Contains(key, ".") {
			t.Errorf("globalNameKeys entry %q is not table.column", key)
		}
	}
	for key := range globalPairKeys {
		if !strings.Contains(key, ".") {
			t.Errorf("globalPairKeys entry %q is not table.column", key)
		}
	}
}

// The two ways the guard used to be satisfied without a tenant being chosen:
// a column it did not know, and a WHERE that mentioned org_id without
// comparing it. Each statement here must be flagged, and the scoped forms not.
func TestTheNameLookupGuardReadsComparisonsNotMentions(t *testing.T) {
	flagged := func(sql string) bool { return unscopedNameLookup(sql) != "" }
	for _, sql := range []string{
		`SELECT id FROM core.ssf_sources WHERE issuer = $1 AND enabled`,
		`SELECT id FROM core.ssf_sources WHERE issuer = $1 AND audience IS NOT NULL`,
		`SELECT id FROM core.proxy_hosts WHERE lower(host) = lower($1)`,
		`SELECT id FROM core.users WHERE email = $1 AND org_id IS NOT NULL`,
		`SELECT id FROM core.users WHERE email = $1 ORDER BY org_id LIMIT 1`,
	} {
		if !flagged(sql) {
			t.Errorf("not flagged, and it picks whichever tenant comes first: %s", sql)
		}
	}
	for _, sql := range []string{
		`SELECT id FROM core.users WHERE email = $1 AND org_id = $2`,
		`SELECT id FROM core.users WHERE email = $1 AND org_id::text = $2`,
		`SELECT id FROM core.users u WHERE u.email = $1 AND u.org_id = ANY($2)`,
		`SELECT id FROM core.users u JOIN core.clients c ON c.client_id = $2 WHERE u.email = $1 AND c.org_id = u.org_id`,
		`SELECT id FROM core.users WHERE email = $1 AND org_id IN (SELECT id FROM core.organizations)`,
		`SELECT id FROM core.ssf_sources WHERE issuer = $1 AND lower(audience) = ANY($2) AND enabled`,
	} {
		if flagged(sql) {
			t.Errorf("flagged, though it chooses an organisation: %s", sql)
		}
	}
}
