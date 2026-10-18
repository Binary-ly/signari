package httpapi

import (
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

// Guard 0.08e: no function takes a second pool connection while it holds a
// transaction.
//
// A second connection taken while holding one is a deadlock under load: with as
// many concurrent requests as the pool has connections, each holds one and
// waits for another that only someone else's completion frees. It happened at
// token minting (the groups claim), in desktop login, and wherever a refusal
// was recorded with auditDetached before the transaction was released. It
// hung the suite for eight minutes once.
//
// The first version saw only s.db and auditDetached written directly in the
// function. A review found an unauthenticated page that held a transaction
// while rendering, and rendering reads the brand from the pool: a few dozen
// requests stalled every endpoint. So a pool use is now anything that reaches
// s.db, followed through every call in the package (poolTakers). A call that
// passes the transaction along is the callee's to answer for, and the callee
// is checked in its own right. The transaction may be called anything, opened
// with Begin or BeginTx, or handed in as a pgx.Tx parameter, and adminapi is
// read as well.
//
// A release in one case of a switch does not count for the next case. What it
// still cannot see is a closure, which is read as part of the function around
// it; that errs towards silence, so pass transactions to helpers rather than
// relying on this.
func TestNothingTakesASecondConnectionWhileHoldingATransaction(t *testing.T) {
	checked := 0
	for _, dir := range []string{".", filepath.Join("..", "adminapi")} {
		checked += checkPoolHolding(t, dir)
	}
	if checked < 20 {
		t.Fatalf("only %d transaction-holding functions were found, so the pattern has "+
			"stopped matching", checked)
	}
}

func checkPoolHolding(t *testing.T, dir string) int {
	t.Helper()
	takers := poolTakers(t, dir)
	if len(takers) < 10 {
		t.Fatalf("%s: only %d functions reach the pool; the call walk is wrong", dir, len(takers))
	}
	names := make([]string, 0, len(takers))
	for n := range takers {
		names = append(names, regexp.QuoteMeta(n))
	}
	sort.Strings(names)
	alt := strings.Join(names, "|")
	// A direct use, a method reaching the pool, or a plain function that does.
	pool := regexp.MustCompile(`\bs\.db\b|\bs\.(?:` + alt + `)\(|(?:^|[^.\w])(?:` + alt + `)\(`)

	fn := regexp.MustCompile(`(?m)^func (?:\([a-z]+ \*?\w+\) )?(\w+)\(([^)]*)\)`)
	begin := regexp.MustCompile(`(\w+), \w+ :?= s\.db\.Begin(?:Tx)?\(`)
	txParam := regexp.MustCompile(`(\w+) pgx\.Tx\b`)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		// Comments blanked to spaces of the same length, so a comment that
		// explains why s.db is not used is not read as a use, and positions
		// and line numbers stay where they are.
		src := lineComment.ReplaceAllStringFunc(string(b), func(c string) string {
			return strings.Repeat(" ", len(c))
		})
		locs := fn.FindAllStringSubmatchIndex(src, -1)
		for i, loc := range locs {
			end := len(src)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			name, params := src[loc[2]:loc[3]], src[loc[4]:loc[5]]

			type held struct {
				start int
				tx    string
			}
			var starts []held
			if m := txParam.FindStringSubmatch(params); m != nil {
				starts = append(starts, held{loc[1], m[1]})
			}
			for _, m := range begin.FindAllStringSubmatchIndex(src[loc[1]:end], -1) {
				starts = append(starts, held{loc[1] + m[1], src[loc[1]+m[2] : loc[1]+m[3]]})
			}
			for _, h := range starts {
				checked++
				// To the end of the block the transaction lives in: past that
				// it is out of scope, released by its deferred rollback.
				window := src[h.start:end]
				if close := blockEnd(window); close >= 0 {
					window = window[:close]
				}
				// A transaction opened in one case of a switch is out of scope
				// in the next.
				if next := nextCase(window); next >= 0 {
					window = window[:next]
				}
				// The branch taken when Begin failed holds no transaction.
				if m := beginFailed.FindStringIndex(window); m != nil {
					if close := blockEnd(window[m[1]:]); close >= 0 {
						window = strings.Repeat(" ", m[1]+close) + window[m[1]+close:]
					}
				}
				release := regexp.MustCompile(`(?m)^[^\n]*\b` + h.tx + `\.(?:Commit|Rollback)\(`)
				var releases []int
				for _, m := range release.FindAllStringIndex(window, -1) {
					if !strings.Contains(window[m[0]:m[1]], "defer") {
						releases = append(releases, m[1])
					}
				}
				for _, use := range pool.FindAllStringIndex(window, -1) {
					if releasedBefore(window, releases, use[0]) {
						continue
					}
					// Handing the transaction on makes it the callee's, and
					// the callee is checked with it as a parameter.
					if strings.HasSuffix(window[use[0]:use[1]], "(") &&
						passesTx(window[use[1]:], h.tx) {
						continue
					}
					line := strings.Count(src[:h.start+use[0]], "\n") + 1
					t.Errorf("%s:%d: %s takes a second connection while holding a transaction (%s); "+
						"pass the transaction, or commit or roll it back first",
						filepath.Join(dir, e.Name()), line, name,
						strings.TrimSpace(window[use[0]:use[1]]))
				}
			}
		}
	}
	return checked
}

// poolTakers are the functions in dir that reach s.db, directly or through any
// chain of calls within the package.
func poolTakers(t *testing.T, dir string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	takes := map[string]bool{}
	calls := map[string][]string{}
	for name, fd := range funcs {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "s" && x.Sel.Name == "db" {
					takes[name] = true
				}
			case *ast.CallExpr:
				switch fn := x.Fun.(type) {
				case *ast.SelectorExpr:
					if id, ok := fn.X.(*ast.Ident); ok && id.Name == "s" && funcs[fn.Sel.Name] != nil {
						calls[name] = append(calls[name], fn.Sel.Name)
					}
				case *ast.Ident:
					if funcs[fn.Name] != nil {
						calls[name] = append(calls[name], fn.Name)
					}
				}
			}
			return true
		})
	}
	for changed := true; changed; {
		changed = false
		for name, callees := range calls {
			if takes[name] {
				continue
			}
			for _, c := range callees {
				if takes[c] {
					takes[name] = true
					changed = true
					break
				}
			}
		}
	}
	return takes
}

// passesTx reports whether the call whose arguments start at args hands the
// transaction tx on.
func passesTx(args, tx string) bool {
	depth := 1
	start := 0
	for i := 0; i < len(args) && depth > 0; i++ {
		switch args[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 || (depth == 1 && args[i] == ',') {
				if strings.TrimSpace(args[start:i]) == tx {
					return true
				}
			}
		case ',':
			if depth == 1 {
				if strings.TrimSpace(args[start:i]) == tx {
					return true
				}
				start = i + 1
			}
		}
	}
	return false
}

// nextCase is where the next case label at the starting depth of s begins, or
// -1.
func nextCase(s string) int {
	depth := 0
	for i, c := range s {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		case '\n':
			if depth == 0 && caseLabel.MatchString(s[i+1:]) {
				return i
			}
		}
	}
	return -1
}

// caseLabel is a switch or select case starting the next line.
var caseLabel = regexp.MustCompile(`^\s*(?:case\b|default:)`)

// beginFailed is the error check that immediately follows a Begin.
var beginFailed = regexp.MustCompile(`^[^\n]*\n\s*if err != nil \{`)

// lineComment is a `//` comment: one at the start of a line or after
// whitespace, so the `//` inside "https://" is left alone.
var lineComment = regexp.MustCompile(`(?m)(?:^|[ \t])//[^\n]*`)

// blockEnd is where the block enclosing the start of s closes, or -1.
func blockEnd(s string) int {
	depth := 0
	for i, c := range s {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return i
			}
		}
	}
	return -1
}

// releasedBefore reports whether one of the releases comes before use in a
// block that is still open there, so that it runs on the path reaching use.
func releasedBefore(window string, releases []int, use int) bool {
	for _, r := range releases {
		if r > use {
			continue
		}
		depth, closed := 0, false
		span := window[r:use]
		for i, c := range span {
			switch c {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					closed = true
				}
			case '\n':
				// Another case of the same switch is another path: a release
				// in one case does not run on the way into the next.
				if depth == 0 && caseLabel.MatchString(span[i+1:]) {
					closed = true
				}
			}
			if closed {
				break
			}
		}
		if !closed {
			return true
		}
	}
	return false
}
