package docsync

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// PKCE stays required unless somebody asks for it not to be.
//
// `client create` grew a `-require-pkce` flag so a deployment seeking OIDC Basic
// OP certification can register a client for that profile, which predates the
// rule and sends no challenge. That flag is a loaded gun pointed at the default:
// flipping it to false, or flipping the column default it mirrors, would make
// every newly created client accept an authorization request with no PKCE
// challenge -- and nothing would fail, because the permissive behaviour is
// indistinguishable from the strict one until somebody attacks it.
//
// Two defaults have to agree, and they are written in different languages in
// different files:
//
//   - the Go flag, which decides what `client create` inserts
//   - the column default, which decides what every OTHER insert path gets
//
// Before the flag existed the INSERT omitted the column, so the column default
// was the only one that mattered. Now the CLI always supplies a value, and the
// two can drift apart silently. This asserts both, so they cannot.
func TestPKCEIsRequiredByDefaultInBothPlaces(t *testing.T) {
	root := repoRoot(t)

	// The Go flag. Read raw rather than through readSource: the default sits on
	// the fs.Bool line, and a reader that stripped comments could not tell a
	// commented-out declaration from a live one.
	main := readRaw(t, root+"/engine/cmd/signari/main.go")
	flagRE := regexp.MustCompile(`fs\.Bool\("require-pkce",\s*(true|false)`)
	m := flagRE.FindStringSubmatch(main)
	if m == nil {
		t.Fatal("the -require-pkce flag is gone from `client create`. If it was " +
			"renamed, update this test; if it was removed, check what now decides " +
			"whether a new client may skip PKCE")
	}
	if m[1] != "true" {
		t.Errorf("the -require-pkce flag defaults to %s. Every client created "+
			"without the flag would then accept an authorization request carrying "+
			"no PKCE challenge, which RFC 9700 and OAuth 2.1 both forbid", m[1])
	}

	// The column default, which governs every insert path that does not name the
	// column -- the admin API among them.
	schema := readRaw(t, root+"/engine/migrations/core/0002_core.sql")
	colRE := regexp.MustCompile(`require_pkce\s+boolean\s+NOT NULL DEFAULT (true|false)`)
	c := colRE.FindStringSubmatch(schema)
	if c == nil {
		t.Fatal("core.clients.require_pkce no longer declares a default in 0002. " +
			"A later migration may have changed it -- check that the new default is true")
	}
	if c[1] != "true" {
		t.Errorf("core.clients.require_pkce defaults to %s at the column level, so "+
			"any insert that does not name the column creates a client that may "+
			"skip PKCE", c[1])
	}

	// And the CLI must actually send the value, or the flag is decoration: a
	// `-require-pkce=false` that never reached the INSERT would report success
	// and change nothing, which is the worst of both.
	if !strings.Contains(main, "require_pkce") {
		t.Error("`client create` does not name require_pkce in its INSERT, so the " +
			"-require-pkce flag cannot be reaching the database")
	}
}

// Every other way a client is created, too.
//
// The test above covered the CLI and the column, and said the column default
// governs "every insert path that does not name the column -- the admin API
// among them". The admin API did name it, bound to `public`, and so did the
// importer. Every confidential client made through the API, the console,
// Terraform or an import accepted an authorization request with no challenge,
// and nothing here could see it.
//
// So every `INSERT INTO core.clients` in the engine is read. One that omits the
// column gets the default checked above. One that names it must give the
// literal `true`, or be listed here with the test that proves its default.
func TestEveryClientInsertRequiresPKCEByDefault(t *testing.T) {
	root := repoRoot(t)
	reviewed := map[string]string{
		"engine/cmd/signari/main.go": "the -require-pkce flag, checked by " +
			"TestPKCEIsRequiredByDefaultInBothPlaces",
		"engine/internal/adminapi/clients.go": "require_pkce defaults to true " +
			"unless the request opts out, TestAnAPICreatedClientRequiresPKCEUnlessItOptsOut",
	}

	insert := regexp.MustCompile(`(?s)INSERT INTO core\.clients\s*\(([^)]*)\)\s*VALUES\s*\(`)
	found := 0
	err := filepath.WalkDir(filepath.Join(root, "engine"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, path)
		for _, loc := range insert.FindAllStringSubmatchIndex(string(src), -1) {
			found++
			columns := splitTopLevel(string(src[loc[2]:loc[3]]))
			values := splitTopLevel(valuesGroup(string(src[loc[1]:])))
			at := -1
			for i, c := range columns {
				if c == "require_pkce" {
					at = i
				}
			}
			if at < 0 {
				continue // the column default, checked above
			}
			if at < len(values) && strings.EqualFold(values[at], "true") {
				continue
			}
			if _, ok := reviewed[rel]; ok {
				continue
			}
			value := "(unparsed)"
			if at < len(values) {
				value = values[at]
			}
			t.Errorf("%s inserts a client with require_pkce = %s. Give the literal true, "+
				"omit the column, or add the file to `reviewed` with the test proving the "+
				"value defaults to true: a client that may skip PKCE should be a decision "+
				"somebody made, not a binding nobody read", rel, value)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 4 {
		t.Fatalf("found %d client inserts; there were 5 when this was written, so the "+
			"pattern has stopped matching", found)
	}
}

// valuesGroup returns the text of a parenthesised group whose opening paren has
// already been consumed, up to its matching close.
func valuesGroup(s string) string {
	depth := 1
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// splitTopLevel splits on commas outside brackets and parentheses, so an
// ARRAY[...] literal or a NULLIF(...) call stays one value.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}
