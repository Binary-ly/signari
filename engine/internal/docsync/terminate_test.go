package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every session ends through store.TerminateSessions.
//
// # The failure this guards against
//
// A session row ending is not a logout. The applications the person reached
// hold sessions of their own and learn of it only from the back-channel logout
// notice TerminateSessions queues, with the CAEP event and the refresh
// families, in the same transaction. Directory sync, SCIM PATCH and SCIM
// DELETE each revoked the rows with an UPDATE of their own and told nobody; a
// SCIM PUT, a SCIM POST and erasure deactivated without ending anything; and a
// SCIM or LDAP delete let the cascade take the sessions, and with them the
// list of who to tell. The admin API had been fixed for exactly this once
// already.
//
// So two shapes fail here, in any non-test function:
//   - SQL setting core.sessions.revoked_at outside TerminateSessions;
//   - SQL deleting a core.users row, or setting its status to anything but a
//     literal 'active', in a function that does not call TerminateSessions.
//
// SQL assembled outside a function, or from pieces, is not seen.
func TestEverySessionEndsThroughTerminateSessions(t *testing.T) {
	engine := filepath.Join(repoRoot(t), "engine")

	revokes := regexp.MustCompile(`(?is)\bUPDATE\s+core\.sessions\b.*?\bSET\b.*?\brevoked_at\s*=`)
	deletesUser := regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+core\.users\b`)
	deactivates := regexp.MustCompile(`(?is)\bUPDATE\s+core\.users\s+SET\b.*?\bstatus\s*=\s*(\$\d+|'[a-z]+')`)

	var found []string
	scanned := 0
	fset := token.NewFileSet()
	err := filepath.WalkDir(engine, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(engine, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() || !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		scanned++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			isTerminate := rel == "internal/store/sessions.go" && fn.Name.Name == "TerminateSessions"
			terminates := false
			var ends []string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					switch f := n.Fun.(type) {
					case *ast.Ident:
						terminates = terminates || f.Name == "TerminateSessions"
					case *ast.SelectorExpr:
						terminates = terminates || f.Sel.Name == "TerminateSessions"
					}
				case *ast.BasicLit:
					if n.Kind != token.STRING {
						return true
					}
					sql, err := strconv.Unquote(n.Value)
					if err != nil {
						return true
					}
					at := rel + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) + " (" + fn.Name.Name + ")"
					if revokes.MatchString(sql) && !isTerminate {
						found = append(found, at+" revokes sessions with an UPDATE of its own")
					}
					if deletesUser.MatchString(sql) {
						ends = append(ends, at+" deletes a person")
					}
					if m := deactivates.FindStringSubmatch(sql); m != nil && m[1] != "'active'" {
						ends = append(ends, at+" sets a person's status to "+m[1])
					}
				}
				return true
			})
			if !terminates {
				for _, e := range ends {
					found = append(found, e+" and never calls TerminateSessions")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d Go files; the walk is not finding the engine", scanned)
	}
	for _, f := range found {
		t.Errorf("%s.\n\tEnd the sessions through store.TerminateSessions, in the same transaction, "+
			"so every application the person reached is told.", f)
	}
}
