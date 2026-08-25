package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No competitive comparison may reach a file that gets published.
//
// Studying other implementations is how several real defects here were found and
// is not in question. What must not happen is the *result* of that study landing
// in a file we push: a rival named in a code comment, a "we are ahead of X" line
// in a page an end user reads, or a rival's CVE number cited as evidence that our
// design is better.
//
// This test exists because all three had already happened, and none was caught by
// review. Four shapes, each found in this tree:
//
//   - a rival named in a test's doc comment, alongside their advisory number
//   - a rival's internal class name cited as where a fix came from
//   - a feature page headed "Ahead of X, parity with Y"
//   - prose carefully avoiding the name -- "the most deployed competitor" --
//     while citing the advisory number in the same sentence
//
// The fourth shape is why the name check below is not sufficient alone. A CVE
// identifier belongs to exactly one vendor, so anonymising the prose around it
// anonymises nothing. The examples above are described rather than quoted for
// the same reason: this file is committed, and quoting them would reintroduce
// what it exists to remove.
//
// Where the comparison belongs is a local-only review document — the
// docs/protocol-review-*.md and docs/competitor-review-*.md families, which
// .git/info/exclude keeps out of every commit.
func TestNoCompetitorIsNamedInAPublishedFile(t *testing.T) {
	root := repoRoot(t)

	// Word-boundary matches, case-insensitive. "Ory" and "Hydra" are omitted
	// deliberately: too many false positives against ordinary English and against
	// library names, and neither has appeared in this repository.
	competitor := regexp.MustCompile(`(?i)\b(keycloak|authentik|zitadel|fusionauth|fosite|oathkeeper|workos|stytch|rauthy|kanidm|ssoready|boxyhq|auth0|okta)\b`)

	// A CVE identifier belongs to exactly one vendor, so citing one is naming
	// them. This list is the rivals' advisories we have studied; it is NOT a list
	// of all CVEs, because protocol-level ones -- Blast-RADIUS (CVE-2024-3596),
	// the SAML comment-truncation family (CVE-2017-11427), the Go LDAP parser
	// (CVE-2017-14623) -- affect everyone including us and are cited freely.
	//
	// Add to this list whenever a rival's advisory is read. The name check above
	// will not catch it: the first version of this test passed a tree in which
	// seven files cited identifiers from this list, because every one of them had
	// been carefully written WITHOUT the vendor's name. Naming the failure class
	// -- algorithm confusion, CWE-347 -- says everything the identifier said and
	// belongs to nobody.
	competitorCVE := regexp.MustCompile(
		`\bCVE-2026-(11800|1486|1609|25748|9793|15573|16443|16442|57580|25922)\b` +
			// Redirect-URI-as-pattern and the two halves of the PKCE biconditional.
			// Added 25 August 2026, when the comment-blind reader below was fixed and
			// a test file citing all four became visible to this guard for the first
			// time. The defect classes they name are tested in
			// engine/internal/oauth/vulnerabilityclasses_test.go, which describes each
			// class without attributing it.
			`|\bCVE-2024-(52289|21637|23647)\b` +
			`|\bCVE-2023-48228\b`)

	// A line naming a product purely as something we migrate FROM. Narrow on
	// purpose: it matches the migrate-from page names and the import verbs, and
	// nothing else, so it cannot be used to smuggle a comparison through.
	migrationLine := regexp.MustCompile(`migrate-from-|import (keycloak|authentik)\b`)

	// Prefixes of paths that are LOCAL-ONLY: never committed, so a competitor
	// named inside one is exactly where it should be. Keep in step with
	// .git/info/exclude.
	private := []string{
		"docs/protocol-review-",
		"docs/competitor-review-",
		"docs/comparison-matrix.md",
		"docs/security-review-competitors.md",
		"docs/security-review-defaults.md",
		"docs/benchmark",
		"docs/plan-",
		"docs/gap-plan-",
		"docs/roadmap",
		"docs/research/",
		"docs/BUILD-LOG.md",
		"docs/adr/",
		"BUILD-LOG.md",
		"TODO-FOR-YOU.md",
		"ROADMAP.md",
		"PROGRESS.md",
		"CLAUDE.md",
		"deploy/benchmark/",
		"specs/",
	}

	// Files where naming another product is the FEATURE, not a comparison.
	// Migrating somebody off a product requires reading its export format, and a
	// user looking for that page searches for the product by name.
	migration := []string{
		"docs/migrate-from-",
		"docs/cli.md", // the `import keycloak` / `import authentik` verbs
		"engine/internal/importer/",
		"engine/internal/passwords/foreign.go",
		"engine/internal/passwords/foreign_test.go",
		"engine/internal/passwords/passwords.go",      // the `$keycloak$` hash prefix
		"engine/internal/passwords/passwords_test.go", //
		"engine/cmd/signari/main.go",                  // the import commands and their help
		"engine/internal/pages/preview_test.go",       // sample federated-provider tiles
		// This file names them in order to forbid them.
		"engine/internal/docsync/competitornames_test.go",
	}

	skipDir := map[string]bool{
		".git": true, "node_modules": true, "vendor": true, "bin": true,
	}

	var found []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		if info.IsDir() {
			if skipDir[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(p) {
		case ".md", ".go", ".php", ".sql", ".yaml", ".yml", ".sh", ".tpl":
		default:
			return nil
		}
		if hasAnyPrefix(rel, private) || hasAnyPrefix(rel, migration) {
			return nil
		}
		// Read RAW, not through readSource.
		//
		// readSource strips comments, which is right for the scanners that look
		// for code -- a commented-out os.Getenv is not a setting the engine reads.
		// Here it was catastrophic: the FIRST failure shape this test was written
		// to catch is "a rival named in a code comment", and stripping comments
		// removed precisely that. The test passed a tree containing the exact
		// thing it exists to forbid, in a doc comment, in a committed file.
		//
		// It went unnoticed because the .md files carried no Go comments, so the
		// markdown half of the guard kept working and the test kept passing. A
		// guard that is only half blind still reports success.
		for i, line := range strings.Split(readRaw(t, p), "\n") {
			if migrationLine.MatchString(line) {
				// The name is there as a migration SOURCE -- a link to the
				// migrate-from page, or the import verb itself. Exempted per line
				// rather than per file, so a genuine comparison added to the same
				// page later is still caught.
				continue
			}
			if m := competitor.FindString(line); m != "" {
				found = append(found, rel+":"+itoa(i+1)+"  "+m+"  |  "+strings.TrimSpace(line))
				continue
			}
			if m := competitorCVE.FindString(line); m != "" {
				found = append(found, rel+":"+itoa(i+1)+"  "+m+" (a rival's advisory)  |  "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(found) > 0 {
		t.Errorf("a competitor is named in %d place(s) that would be published.\n\n"+
			"Move the comparison into a local-only review document\n"+
			"(docs/protocol-review-*.md or docs/competitor-review-*.md), and leave the\n"+
			"technical reasoning behind in the public file stated on its own terms --\n"+
			"a rule is not made weaker by dropping the name of whoever got it wrong.\n\n"+
			"If this is migration or import functionality, add the path to the\n"+
			"`migration` allow-list above and say why.\n\n%s",
			len(found), strings.Join(found, "\n"))
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// readRaw reads a file exactly as committed, comments included.
//
// Deliberately not readSource. See the note at the scan above: comments are
// where the names actually appear, because nobody puts a rival's name in a
// string literal -- they put it in the sentence explaining why the code is the
// way it is.
func readRaw(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The guard's own guard.
//
// TestNoCompetitorIsNamedInAPublishedFile passed for as long as it was blind,
// because a scan that finds nothing and a scan that looks at nothing report the
// same result. This asserts the scan can still see the two shapes that matter --
// a name in a `//` comment and a name in a `/* */` block -- so a future change to
// the reader cannot silently disarm it again.
//
// The names below are assembled at runtime rather than written out, so this file
// does not itself become the thing it forbids.
func TestTheCompetitorScanCanSeeIntoComments(t *testing.T) {
	rival := "key" + "cloak"

	for _, tc := range []struct {
		name string
		body string
	}{
		{"a line comment", "package x\n\n// " + rival + " does this differently.\n"},
		{"a doc comment", "// Package x is a thing.\n//\n//   - " + rival + " gets it wrong.\npackage x\n"},
		{"a block comment", "package x\n\n/*\n" + rival + " gets it wrong.\n*/\n"},
		{"a string literal", "package x\n\nconst s = \"" + rival + "\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "sample.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			raw := readRaw(t, path)
			if !strings.Contains(strings.ToLower(raw), rival) {
				t.Fatalf("the scan reads a file in a way that hides a name in %s. "+
					"The guard would report success over a tree that names a rival", tc.name)
			}
		})
	}

	// And the control: readSource, the reader that caused this, genuinely does
	// hide it. Without this the test above could pass against any reader at all
	// and prove nothing.
	dir := t.TempDir()
	path := filepath.Join(dir, "stripped.go")
	if err := os.WriteFile(path, []byte("package x\n\n// "+rival+" does this differently.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(readSource(t, path)), rival) {
		t.Skip("readSource no longer strips line comments; this control is obsolete")
	}
}
