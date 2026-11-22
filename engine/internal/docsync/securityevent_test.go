package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// writesPassword matches SQL that gives a person a different password, or none.
var writesPassword = regexp.MustCompile(`(?s)INSERT INTO core\.password_credentials|` +
	`DELETE FROM core\.password_credentials|UPDATE core\.password_credentials\s+SET hash`)

// passwordWritesNoStreamHears are the writers that are not a change a receiver
// should hear of, by "file:function", each with why. The account in the first
// four is minutes old and no client has met it; the last two leave the password
// what it was.
var passwordWritesNoStreamHears = map[string]string{
	"engine/internal/adminapi/users.go:createUser":         "a new account",
	"engine/internal/httpapi/signup.go:createAccount":      "a new account",
	"engine/internal/httpapi/ldapwrite.go:Create":          "a new account",
	"engine/cmd/signari/main.go:userCreate":                "a new account",
	"engine/internal/httpapi/flow.go:handleLoginPost":      "a sign-in upgrading the hash of the same password",
	"engine/internal/store/migration.go:CompleteMigration": "the password the person just proved, captured from the old system",
}

// A receiver is told when a password changes, and a writer that forgets is silent
// in a way no test of the writers that remember can show. So every statement that
// writes one must sit in a function that queues the event, or be listed here with
// its reason. The importers are left out as a directory: they load accounts.
func TestEveryPasswordWriterTellsTheStreams(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var silent []string
	seen := map[string]bool{}
	for _, dir := range []string{"engine/internal", "engine/cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/internal/importer/") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				writes, tells := false, false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch v := n.(type) {
					case *ast.BasicLit:
						if v.Kind == token.STRING {
							s, _ := strconv.Unquote(v.Value)
							writes = writes || writesPassword.MatchString(s)
						}
					case *ast.SelectorExpr:
						tells = tells || v.Sel.Name == "QueueCredentialChange"
					case *ast.Ident:
						tells = tells || v.Name == "QueueCredentialChange"
					}
					return true
				})
				if !writes {
					continue
				}
				key := rel + ":" + fd.Name.Name
				seen[key] = true
				if _, listed := passwordWritesNoStreamHears[key]; !listed && !tells {
					silent = append(silent, key)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range silent {
		t.Errorf("%s writes a password and queues no credential-change event", key)
	}
	for key := range passwordWritesNoStreamHears {
		if !seen[key] {
			t.Errorf("%s is listed and writes no password: the list has gone stale", key)
		}
	}
}
