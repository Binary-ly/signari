package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// directMembershipReads are the statements that read core.group_members alone, by file
// and function, each with why it means the people put in a group by name and not
// everybody in it. Everything else that reads membership is a claim or a decision, and
// must follow groups inside groups through core.groups_of or core.groups_below.
var directMembershipReads = map[string]string{
	"internal/adminapi/groups.go:Server.deleteGroup": "counts the membership rows the delete is about " +
		"to remove, for the audit record; a nested group's members keep their own rows",
	"internal/adminapi/groups.go:Server.listGroupMembers": "GET .../members is the people put in the group " +
		"by name, the ones the route beside it can remove; the groups put in it are GET .../member-groups",
	"internal/directory/groups.go:LoadGroupState": "a directory sync compares the memberships it manages " +
		"with its upstream and must not propose removing one that comes through a nesting",
	"internal/store/groups.go:AddGroupMember": "tells 'already a member' from 'no such group' after an " +
		"insert of a direct membership did nothing",
	"internal/store/scimfilter.go:scimGroupMembers": "an inbound SCIM source's Group resource lists the " +
		"members that source put there (RFC 7643 4.2), which is what it reconciles",
	"internal/store/scimgroups.go:membersOf": "an inbound SCIM source reads back the memberships it wrote, " +
		"to answer and patch its own Group resources",
}

// TestEveryMembershipReadFollowsNesting fails when a statement reads core.group_members
// without core.groups_of or core.groups_below and is not declared direct above (11.09).
//
// Nested groups changed what "in a group" means, and the forty-odd statements that
// asked had been written for one level. One left behind answers for direct members only:
// the person in `oncall-eu` gets no `engineering` claim from it, or -- worse, where it
// guards something -- is not counted as holding what `engineering` grants, which is how
// a group inside one that may impersonate became a way to grant impersonation with
// groups:write. A write is not a read and is exempt; a statement that also walks the
// nesting is following it.
func TestEveryMembershipReadFollowsNesting(t *testing.T) {
	root := filepath.Join(repoRoot(t), "engine")
	mention := regexp.MustCompile(`core\.group_members\b`)
	write := regexp.MustCompile(`(?i)(INSERT\s+INTO|DELETE\s+FROM)\s+core\.group_members\b`)
	follows := regexp.MustCompile(`core\.(groups_of|groups_below)\(`)

	seen := map[string]bool{}
	var undeclared []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		check := func(where string, n ast.Node) {
			ast.Inspect(n, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || !mention.MatchString(lit.Value) {
					return true
				}
				if write.MatchString(lit.Value) || follows.MatchString(lit.Value) {
					return true
				}
				key := filepath.ToSlash(rel) + ":" + where
				seen[key] = true
				if _, ok := directMembershipReads[key]; !ok {
					undeclared = append(undeclared, fset.Position(lit.Pos()).String()+" ("+key+")")
				}
				return true
			})
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				name := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) == 1 {
					name = recvName(d.Recv.List[0].Type) + "." + name
				}
				check(name, d)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
						check(vs.Names[0].Name, vs)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(undeclared)
	for _, u := range undeclared {
		t.Errorf("%s reads core.group_members alone. If it decides access or writes a claim, read "+
			"core.groups_of(person) or join through core.groups_below(group), so a member of a group "+
			"inside this one counts; if it means only the people put in the group by name, declare it in "+
			"directMembershipReads with why", u)
	}
	for key := range directMembershipReads {
		if !seen[key] {
			t.Errorf("%s is declared a direct membership read and no longer reads core.group_members "+
				"alone; take it out of directMembershipReads", key)
		}
	}
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvName(t.X)
	}
	return "?"
}
