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
// review:
//
//	httpapi/forwardauth_test.go   "authentik's a published advisory ... made their proxy"
//	httpapi/tokenadmin.go         "found by reading Keycloak's TokenRevocation..."
//	docs/par.md                   "### Ahead of authentik, parity with Keycloak"
//	docs/jwt-bearer.md            "The most deployed competitor made the other choice"
//
// The last one shows why matching on names alone is not enough on its own, and
// why the CVE rule below matters: "the most deployed competitor shipped
// a published advisory" identifies the vendor exactly as well as writing the name,
// because a CVE identifier belongs to one vendor. Anonymising the prose while
// keeping the number anonymises nothing.
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
	// Add to this list whenever a competitor advisory is read. The name check
	// above will not catch it: the first version of this test passed a tree in
	// which seven files cited these four identifiers, because every one had been
	// carefully written WITHOUT the vendor's name -- "the most deployed
	// implementation of this grant shipped a published advisory" names them precisely.
	competitorCVE := regexp.MustCompile(`\bCVE-2026-(11800|1486|1609|25748|9793|15573|16443|16442|57580|25922)\b`)

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
		for i, line := range strings.Split(readSource(t, p), "\n") {
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
