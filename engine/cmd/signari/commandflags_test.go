package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// writeCommandFlags writes the table the dispatch implies to this path, for
// regenerating commandflags_table.go after a command or flag changes:
//
//	go test ./cmd/signari -run TestEachCommandParsesOnlyTheFlagsItReads -command-flags-out /tmp/table.go
var writeCommandFlags = flag.String("command-flags-out", "", "write the derived command flag table to this file")

// dispatchedFlags reads run()'s dispatch and answers which flags each command
// reads: every flag variable named inside the `case` of a `switch cmd` or the
// body of an `if cmd == "..."` that answers it, as a value, a pointer or the
// source of an alias. outside is the flags run() names in no command's branch.
func dispatchedFlags(t *testing.T) (commands map[string][]string, outside map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var runFn *ast.FuncDecl
	varFlag := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "run" {
				runFn = fd
			}
		}
	}
	if runFn == nil {
		t.Fatal("no run function: this test is reading the wrong thing")
	}
	// x := fs.String("name", ...) and the like, in run().
	defs := map[*ast.Ident]bool{}
	ast.Inspect(runFn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		call, ok2 := as.Rhs[0].(*ast.CallExpr)
		if !ok || !ok2 || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "fs" {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			v, _ := strconv.Unquote(lit.Value)
			varFlag[id.Name] = v
			defs[id] = true
		}
		return true
	})
	if len(varFlag) < 200 {
		t.Fatalf("only %d flag variables found; this test is reading the wrong thing", len(varFlag))
	}

	commands = map[string][]string{}
	outside = map[string]bool{}
	add := func(labels []string, flag string) {
		for _, l := range labels {
			if flag != "" && !slices.Contains(commands[l], flag) {
				commands[l] = append(commands[l], flag)
			} else if _, ok := commands[l]; !ok {
				commands[l] = []string{}
			}
		}
	}
	// labelsOf answers the commands a branch of the dispatch answers: a case's
	// string labels, or the literal an `if cmd == ` compares with.
	labelsOf := func(n ast.Node) []string {
		switch x := n.(type) {
		case *ast.CaseClause:
			var labels []string
			for _, e := range x.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, _ := strconv.Unquote(lit.Value)
					labels = append(labels, v)
				}
			}
			return labels
		case *ast.IfStmt:
			be, ok := x.Cond.(*ast.BinaryExpr)
			if !ok || be.Op != token.EQL {
				return nil
			}
			id, ok := be.X.(*ast.Ident)
			lit, ok2 := be.Y.(*ast.BasicLit)
			if !ok || !ok2 || id.Name != "cmd" {
				return nil
			}
			v, _ := strconv.Unquote(lit.Value)
			return []string{v}
		}
		return nil
	}
	// A CaseClause counts only under a `switch cmd`.
	cmdSwitch := map[*ast.BlockStmt]bool{}
	ast.Inspect(runFn.Body, func(n ast.Node) bool {
		if sw, ok := n.(*ast.SwitchStmt); ok {
			if id, ok := sw.Tag.(*ast.Ident); ok && id.Name == "cmd" {
				cmdSwitch[sw.Body] = true
			}
		}
		return true
	})
	var stack []ast.Node
	ast.Inspect(runFn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) > 0 {
			parent := stack[len(stack)-1]
			if cc, ok := n.(*ast.CaseClause); ok {
				if b, ok := parent.(*ast.BlockStmt); ok && cmdSwitch[b] {
					add(labelsOf(cc), "")
				}
			}
			if is, ok := n.(*ast.IfStmt); ok {
				add(labelsOf(is), "")
			}
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok || defs[id] || varFlag[id.Name] == "" {
			return true
		}
		flagName := varFlag[id.Name]
		// The innermost branch of the dispatch around this use.
		for i := len(stack) - 2; i >= 1; i-- {
			switch b := stack[i].(type) {
			case *ast.CaseClause:
				if blk, ok := stack[i-1].(*ast.BlockStmt); ok && cmdSwitch[blk] {
					add(labelsOf(b), flagName)
					return true
				}
			case *ast.BlockStmt:
				if is, ok := stack[i-1].(*ast.IfStmt); ok && is.Body == b {
					if labels := labelsOf(is); labels != nil {
						add(labels, flagName)
						return true
					}
				}
			}
		}
		outside[flagName] = true
		return true
	})
	// The commands answered before any flags are parsed, and the spellings of
	// -h that ask for help, are not commands that parse flags.
	for c := range commands {
		if slices.Contains(beforeFlags, c) || strings.HasPrefix(c, "-") {
			delete(commands, c)
		}
	}
	for _, l := range commands {
		sort.Strings(l)
	}
	return commands, outside
}

// captureStdout runs fn and answers what it printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			b.Write(buf[:n])
			if rerr != nil {
				done <- b.String()
				return
			}
		}
	}()
	ferr := fn()
	os.Stdout = saved
	_ = w.Close()
	return <-done, ferr
}

// A command refuses a flag it does not read, help shows its own flags and no
// others, and what went wrong is told apart by the exit code (6.15).
func TestACommandTakesOnlyItsOwnFlags(t *testing.T) {
	err := run([]string{"idp", "list", "-org", "x"})
	if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "-org") {
		t.Errorf("idp list -org answered %v (exit %d); it lists every provider and reads no -org", err, exitCode(err))
	}
	if err := run([]string{"version", "stray"}); exitCode(err) != 2 {
		t.Errorf("a word after the flags answered %v; parsing stops there, so it would be ignored", err)
	}
	if err := run([]string{"keys", "turn"}); exitCode(err) != 2 || !strings.Contains(fmt.Sprint(err), "rotate") {
		t.Errorf("an unknown verb answered %v; it should name the group's commands", err)
	}
	if err := run([]string{"keys"}); exitCode(err) != 2 {
		t.Errorf("a group with no verb answered %v", err)
	}
	if err := run([]string{"policy", "test"}); exitCode(err) != 2 {
		t.Errorf("a missing flag answered %v (exit %d)", err, exitCode(err))
	}
	if exitCode(errors.New("connecting: refused")) != 1 || exitCode(fmt.Errorf("planning: %w", errDrift)) != 3 {
		t.Error("a failure exits 1 and drift 3")
	}

	out, err := captureStdout(t, func() error { return run([]string{"help", "keys", "rotate"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"usage: signari keys rotate", "-alg string", "-now", "-dsn", "-timeout"} {
		if !strings.Contains(out, want) {
			t.Errorf("help for keys rotate lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"-org", "-client-id", "keys rotate\n    \t"} {
		if strings.Contains(out, not) {
			t.Errorf("help for keys rotate shows %q:\n%s", not, out)
		}
	}
	if out, err := captureStdout(t, func() error { return run([]string{"keys", "rotate", "-h"}) }); err != nil ||
		!strings.Contains(out, "-alg") {
		t.Errorf("keys rotate -h answered %v:\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return run([]string{"completion", "bash"}) })
	if err != nil || !strings.Contains(out, `"keys rotate") flags="-dsn -timeout -alg -now"`) ||
		!strings.Contains(out, "complete -F _signari signari") {
		t.Errorf("the bash completion answered %v:\n%.400s", err, out)
	}
}

// Every `signari …` written down for somebody to run, in the documentation's
// code and the repository's scripts, gives the command only flags it takes
// (6.15). With one set of every flag an example naming a flag the command
// ignores still ran and did less than it said; now it is refused.
func TestEveryWrittenInvocationUsesFlagsTheCommandTakes(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var files []string
	for _, pattern := range []string{"*.md", "docs/*.md", "scripts/*", "deploy/*", "deploy/*/*", "deploy/*/*/*",
		"tools/*/*.md"} {
		m, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			// The history of what was planned and built, which quotes flags as
			// they were proposed, rather than instructions to run.
			switch filepath.Base(f) {
			case "ROADMAP.md", "BUILD-LOG.md", "PROGRESS.md":
				continue
			}
			files = append(files, f)
		}
	}
	subshell := regexp.MustCompile(`\$\([^)]*\)`)
	if len(files) < 50 {
		t.Fatalf("only %d files found; this test is reading the wrong thing", len(files))
	}
	invocation := regexp.MustCompile(`\bsignari ([a-z][a-z0-9-]*)(?: ([a-z][a-z0-9-]*))?`)
	flagWord := regexp.MustCompile(`(?:^|\s)--?([a-z][a-z0-9-]*)`)
	span := regexp.MustCompile("`(signari [^`]+)`")
	var wrong []string
	checked := 0
	check := func(where, text string) {
		m := invocation.FindStringSubmatchIndex(text)
		if m == nil {
			return
		}
		first := text[m[2]:m[3]]
		cmd, rest := first, text[m[3]:]
		if m[4] >= 0 && twoWordCommands[first] {
			cmd, rest = first+" "+text[m[4]:m[5]], text[m[5]:]
		}
		flags, ok := commandFlags[cmd]
		if !ok {
			return
		}
		checked++
		// A `$(head -c 24 …)` in a value is another program's flags.
		rest = subshell.ReplaceAllString(rest, "")
		for _, f := range flagWord.FindAllStringSubmatch(rest, -1) {
			name := f[1]
			if name == "h" || name == "help" || slices.Contains(commonFlags, name) || slices.Contains(flags, name) {
				continue
			}
			wrong = append(wrong, fmt.Sprintf("%s: `signari %s` is given -%s, which it does not take", where, cmd, name))
		}
	}
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() > 2<<20 {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		markdown := strings.HasSuffix(path, ".md")
		lines := strings.Split(string(raw), "\n")
		fenced := !markdown
		for i := 0; i < len(lines); i++ {
			line := lines[i]
			if markdown && strings.HasPrefix(strings.TrimSpace(line), "```") {
				fenced = !fenced
				continue
			}
			where := fmt.Sprintf("%s:%d", rel, i+1)
			if !fenced {
				for _, s := range span.FindAllStringSubmatch(line, -1) {
					check(where, s[1])
				}
				continue
			}
			// A command continued over lines with a trailing backslash is one.
			for strings.HasSuffix(strings.TrimRight(line, " "), "\\") && i+1 < len(lines) {
				i++
				line = strings.TrimSuffix(strings.TrimRight(line, " "), "\\") + " " + lines[i]
			}
			// What follows a pipe, a separator or a comment is another command's,
			// once a subshell's own pipes are gone.
			line = subshell.ReplaceAllString(line, "")
			if j := strings.IndexAny(line, "|;#&"); j >= 0 {
				line = line[:j]
			}
			check(where, line)
		}
	}
	if checked < 100 {
		t.Fatalf("only %d invocations checked; this test is reading the wrong thing", checked)
	}
	sort.Strings(wrong)
	for _, w := range wrong {
		t.Error(w)
	}
}

// A listing prints its rows as a JSON array with -o json, for a script, and its
// text as before without it (6.15).
func TestListingsPrintJSON(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	var org string
	if err := conn.QueryRow(context.Background(), `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).
		Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	for _, args := range [][]string{{"group", "list"}, {"idp", "list"}, {"admin-token", "list"}, {"role", "list", "-org", org}} {
		out, err := captureStdout(t, func() error { return run(append(args, "-dsn", dsn, "-o", "json")) })
		if err != nil {
			t.Errorf("%v -o json: %v", args, err)
			continue
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Errorf("%v -o json is not a JSON array: %v\n%.300s", args, err, out)
		}
		if strings.Contains(out, "sgnadm_") {
			t.Errorf("%v -o json printed a token secret", args)
		}
	}
	text, err := captureStdout(t, func() error { return run([]string{"group", "list", "-dsn", dsn}) })
	if err != nil || !strings.HasPrefix(text, "NAME") {
		t.Errorf("group list without -o answered %v:\n%.200s", err, text)
	}
	if err := run([]string{"group", "list", "-dsn", dsn, "-o", "yaml"}); exitCode(err) != 2 {
		t.Errorf("-o yaml answered %v", err)
	}
	if err := run([]string{"group", "create", "-dsn", dsn, "-o", "json"}); exitCode(err) != 2 {
		t.Errorf("a command that prints no listing took -o: %v", err)
	}
}

// `signari plan` exits 3 when the deployment differs from the file, so a
// pipeline can tell drift from a failure (6.15), and 0 when it does not.
func TestPlanExitsThreeOnDrift(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	dir := t.TempDir()
	same, drifted := filepath.Join(dir, "same.yaml"), filepath.Join(dir, "drifted.yaml")
	if err := os.WriteFile(same, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(drifted, []byte("version: 1\ngroups:\n  - name: plan-drift-never-made\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var org string
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if err := conn.QueryRow(context.Background(), `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).
		Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	if _, err := captureStdout(t, func() error { return run([]string{"plan", "-dsn", dsn, "-org", org, "-f", same}) }); err != nil {
		t.Errorf("a plan with nothing to do answered %v (exit %d)", err, exitCode(err))
	}
	_, err = captureStdout(t, func() error { return run([]string{"plan", "-dsn", dsn, "-org", org, "-f", drifted}) })
	if exitCode(err) != 3 {
		t.Errorf("a plan with a group to create answered %v (exit %d), want 3", err, exitCode(err))
	}
}

// The flags each command parses are the ones its branch of the dispatch
// reads, plus those every command reads (6.15). Before, one FlagSet of every
// flag served every command, so `signari idp list -org x` accepted a flag the
// command ignores, and -h listed all of them.
func TestEachCommandParsesOnlyTheFlagsItReads(t *testing.T) {
	derived, outside := dispatchedFlags(t)
	if *writeCommandFlags != "" {
		var b strings.Builder
		b.WriteString("package main\n\n// commandFlags are the flags each command reads, as its branch of the dispatch in\n" +
			"// run() reads them. Derived from run() and checked against it by\n" +
			"// TestEachCommandParsesOnlyTheFlagsItReads, which writes this file anew with\n" +
			"// -command-flags-out.\nvar commandFlags = map[string][]string{\n")
		names := make([]string, 0, len(derived))
		for c := range derived {
			names = append(names, c)
		}
		sort.Strings(names)
		for _, c := range names {
			quoted := make([]string, len(derived[c]))
			for i, f := range derived[c] {
				quoted[i] = strconv.Quote(f)
			}
			fmt.Fprintf(&b, "\t%q: {%s},\n", c, strings.Join(quoted, ", "))
		}
		b.WriteString("}\n")
		src, err := format.Source([]byte(b.String()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(*writeCommandFlags, src, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for flag := range outside {
		if !slices.Contains(commonFlags, flag) && bookkeepingFlags[flag] == "" {
			t.Errorf("run() reads -%s outside every command's branch. Read it in the branches that use it, or "+
				"add it to commonFlags (every command parses it) or bookkeepingFlags (read for every command "+
				"without changing what one does), with the reason", flag)
		}
	}
	for flag := range bookkeepingFlags {
		if !outside[flag] {
			t.Errorf("bookkeepingFlags lists -%s, which run() no longer reads outside a branch", flag)
		}
	}
	for c, want := range derived {
		got, ok := commandFlags[c]
		switch {
		case !ok:
			t.Errorf("%q is dispatched and has no row in commandFlags; regenerate the table", c)
		case !slices.Equal(got, want):
			t.Errorf("commandFlags gives %q %v; its branch reads %v. Regenerate the table", c, got, want)
		}
	}
	for c := range commandFlags {
		if _, ok := derived[c]; !ok {
			t.Errorf("commandFlags has %q, which run() does not dispatch", c)
		}
	}
	if len(derived) < 200 {
		t.Fatalf("only %d commands derived; this test is reading the wrong thing", len(derived))
	}
}
