package docsync

import (
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
