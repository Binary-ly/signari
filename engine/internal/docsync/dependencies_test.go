package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// docs/dependencies.md is the inventory OWASP ASVS V15.1.2 asks for, and the
// page that says why each dependency is here at all. It said thirteen direct
// dependencies while engine/go.mod named eighteen, three of them nowhere on the
// page and two at versions since replaced. So it is held to go.mod, both ways,
// at the pinned version, and its count to its table.
func TestEveryDirectDependencyIsListed(t *testing.T) {
	root := repoRoot(t)
	mod, err := os.ReadFile(filepath.Join(root, "engine", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	direct := map[string]string{}
	block := false
	for _, line := range strings.Split(string(mod), "\n") {
		line = strings.TrimSpace(line)
		spec, single := strings.CutPrefix(line, "require ")
		switch {
		case line == "require (":
			block = true
			continue
		case line == ")":
			block = false
			continue
		case block:
			spec = line
		case !single:
			continue
		}
		if f := strings.Fields(spec); len(f) >= 2 && !strings.Contains(spec, "// indirect") {
			direct[f[0]] = f[1]
		}
	}
	if len(direct) < 10 {
		t.Fatalf("read %d direct requirements from go.mod, which is not this module", len(direct))
	}

	doc, err := os.ReadFile(filepath.Join(root, "docs", "dependencies.md"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([^`]+)` \\| (v[^ |]+) \\|").FindAllStringSubmatch(string(doc), -1) {
		listed[m[1]] = m[2]
	}
	for module, version := range direct {
		switch got, ok := listed[module]; {
		case !ok:
			t.Errorf("go.mod requires %s directly and docs/dependencies.md does not say why", module)
		case got != version:
			t.Errorf("docs/dependencies.md lists %s at %s, and go.mod pins %s", module, got, version)
		}
	}
	for module := range listed {
		if _, ok := direct[module]; !ok {
			t.Errorf("docs/dependencies.md lists %s, which go.mod does not require directly", module)
		}
	}
	count := regexp.MustCompile(`\*\*(\d+) direct dependencies`).FindSubmatch(doc)
	if count == nil {
		t.Fatal("docs/dependencies.md no longer says how many direct dependencies there are")
	}
	if n, _ := strconv.Atoi(string(count[1])); n != len(direct) {
		t.Errorf("docs/dependencies.md counts %d direct dependencies, and go.mod has %d", n, len(direct))
	}
}
