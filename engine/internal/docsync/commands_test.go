package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Keeping the documentation and the CLI in agreement.
//
// This project began with a bug of exactly this shape: discovery advertised
// endpoints that returned 404. The lesson written down at the time was that a
// thing enters the documentation once it works, and the way to keep a lesson is
// to make it fail a test rather than to remember it.
//
// The failure mode is not usually a deleted command. It is a page written
// alongside a design that changed, or a command renamed with the docs left
// behind -- and the operator finds out at the moment they most needed it to
// work, because a runbook is read during an incident.

// docCommand matches an invocation a page tells an operator to run.
//
// Anchored at the start of a line so prose mentioning a command in passing is
// not treated as an instruction, and tolerant of a shell prompt or `./` prefix.
var docCommand = regexp.MustCompile(
	`(?m)^\s*(?:\$\s*)?(?:sudo\s+)?(?:\./)?signari\s+([a-z][a-z0-9-]*(?:\s+[a-z][a-z0-9-]*)?)`)

func TestEveryDocumentedCommandExists(t *testing.T) {
	root := repoRoot(t)

	// What main.go dispatches.
	//
	// Both forms are read. Most commands are a `case` in the switch, but a few
	// are dispatched by an `if` before the database is required -- `proxy check`
	// is, deliberately, because it has to run from outside the network. A check
	// that knew only about the switch would report those as missing, which is a
	// false alarm that teaches whoever hits it to distrust this test.
	src := readSource(t, filepath.Join(root, "engine", "cmd", "signari", "main.go"))
	dispatched := map[string]bool{}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`case\s+"([a-z][a-z0-9 -]*)":`),
		regexp.MustCompile(`cmd\s*==\s*"([a-z][a-z0-9 -]*)"`),
	} {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			dispatched[m[1]] = true
		}
	}
	if len(dispatched) < 20 {
		t.Fatalf("only %d commands were found in main.go, which means this test is "+
			"reading it wrong rather than that the CLI shrank", len(dispatched))
	}

	// The groups whose first word is followed by a verb.
	//
	// Read separately from the switch because BOTH are required at runtime and
	// they fail differently. Dispatch joins the two words only when the first is
	// in this set; without the entry, `signari radius add` never becomes
	// "radius add", the switch on "radius" matches nothing, and the CLI prints
	// its usage text with no hint that dispatch is what is wrong. That is not
	// hypothetical -- it is what happened to `scim-source`, and the comment
	// above the map in main.go says so.
	groups := map[string]bool{}
	if i := strings.Index(src, "var twoWordCommands = map[string]bool{"); i >= 0 {
		block := src[i:]
		if j := strings.Index(block, "}"); j > 0 {
			for _, m := range regexp.MustCompile(`"([a-z][a-z0-9-]*)":\s*true`).
				FindAllStringSubmatch(block[:j], -1) {
				groups[m[1]] = true
			}
		}
	}
	if len(groups) < 10 {
		t.Fatalf("only %d command groups were parsed out of twoWordCommands, which "+
			"means this test is reading main.go wrong", len(groups))
	}

	// What the documentation tells people to run.
	documented := map[string][]string{}
	docs := filepath.Join(root, "docs")
	err := filepath.Walk(docs, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range docCommand.FindAllStringSubmatch(string(body), -1) {
			cmd := strings.TrimSpace(m[1])
			documented[cmd] = appendOnce(documented[cmd], rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(documented) < 20 {
		t.Fatalf("only %d commands were found across the documentation, which means "+
			"this test is reading it wrong", len(documented))
	}

	var missing []string
	for cmd, pages := range documented {
		sort.Strings(pages)
		where := "  (documented in " + strings.Join(pages, ", ") + ")"
		words := strings.Fields(cmd)

		if len(words) == 1 {
			// One word. It must be in the switch and must NOT be a group, since
			// a group with no verb prints the usage text.
			if groups[words[0]] {
				missing = append(missing, "signari "+cmd+" is a command GROUP and "+
					"needs a verb after it"+where)
			} else if !dispatched[cmd] {
				missing = append(missing, "signari "+cmd+where)
			}
			continue
		}

		// Two words. The pair may be dispatched directly, but only if the first
		// word is a group -- otherwise the two are never joined.
		switch {
		case !groups[words[0]]:
			// It may still be a one-word command followed by an argument that
			// happens to look like a verb, so only complain when the bare first
			// word is not a command either.
			if !dispatched[words[0]] {
				missing = append(missing, "signari "+cmd+": neither \""+words[0]+
					"\" nor the pair is dispatched, and \""+words[0]+
					"\" is not in twoWordCommands"+where)
			}
		case !dispatched[cmd]:
			missing = append(missing, "signari "+cmd+": \""+words[0]+
				"\" is a group but there is no case for the pair"+where)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("the documentation tells operators to run commands the CLI does "+
			"not dispatch:\n  %s\n\nEither implement them or correct the page. A "+
			"runbook is read during an incident, which is the worst moment to "+
			"discover it describes something that does not exist.",
			strings.Join(missing, "\n  "))
	}
}

// TestEveryCommandIsDocumented is the other direction.
//
// The existing check catches a page that outlived its command. This catches the
// commoner failure: a command shipped and never written down. Nobody finds
// those, because the person who added it knows it exists and everyone else
// cannot know to look.
//
// Verified by adding `events subscribe` and watching this fail before the page
// was written.
func TestEveryCommandIsDocumented(t *testing.T) {
	root := repoRoot(t)
	src := readSource(t, filepath.Join(root, "engine", "cmd", "signari", "main.go"))

	dispatched := map[string]bool{}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`case\s+"([a-z][a-z0-9 -]*)":`),
		regexp.MustCompile(`cmd\s*==\s*"([a-z][a-z0-9 -]*)"`),
	} {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			dispatched[m[1]] = true
		}
	}
	if len(dispatched) < 20 {
		t.Fatalf("only %d commands found in main.go; this test is reading it wrong",
			len(dispatched))
	}

	// Everything the docs mention anywhere -- including inside a fenced block,
	// which is where most invocations live. Looser than docCommand on purpose:
	// the question here is "is it written down at all", not "is it an
	// instruction", and being strict would demand a runbook for every command.
	mentioned := map[string]bool{}
	err := filepath.Walk(filepath.Join(root, "docs"),
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".md") {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			text := string(body)
			for cmd := range dispatched {
				if strings.Contains(text, "signari "+cmd) ||
					strings.Contains(text, "`"+cmd+"`") {
					mentioned[cmd] = true
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("walking docs: %v", err)
	}

	var missing []string
	for cmd := range dispatched {
		if !mentioned[cmd] {
			missing = append(missing, cmd)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d command(s) exist and appear in no documentation:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
