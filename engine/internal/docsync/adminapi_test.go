package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docs/admin-api.md must list exactly the routes the admin API serves.
//
// # Why this is the same test as TestEveryCommandIsDocumented
//
// `docs/cli.md` once listed eight commands that had never existed, which is why
// the CLI has a derivation test and has not drifted since. The admin API had no
// equivalent, and it is the surface where drift costs the most: it is the only
// write path the console has, so somebody integrating against it has no code to
// read -- the document IS the interface.
//
// Both directions matter and they fail differently. A route the document omits
// is a capability nobody can find, which is how `DELETE /admin/clients` sat
// unwritten while support desks were told to use SQL. A route the document
// invents is worse: somebody builds against it, ships, and discovers at runtime
// that the endpoint answers 404.
//
// # Why the parsing is deliberately literal
//
// The route table is read from `mux.HandleFunc("METHOD /path"...)` calls and the
// document from its own tables, with no normalisation beyond trimming. A test
// that tried to match `{userID}` against `{id}` would be a test with an opinion
// about what counts as the same route, and the first time that opinion is wrong
// it hides exactly the drift it exists to catch.

var (
	// Both registration forms: `route(...)`, which also records the operation for
	// the OpenAPI document, and `mux.HandleFunc`, which still registers the
	// unauthenticated document endpoint. Matching only the first would make this
	// guard blind to exactly the route that has no scope.
	adminRoute = regexp.MustCompile(`(?:mux\.HandleFunc|route)\("((?:GET|POST|PUT|PATCH|DELETE) /admin/[^"]*)"`)
	// Routes appear in the document as `METHOD /admin/...` inside a table cell.
	docRoute = regexp.MustCompile("`((?:GET|POST|PUT|PATCH|DELETE) /admin/[^`]*)`")
)

func adminRoutes(t *testing.T, root string) map[string]bool {
	t.Helper()
	dir := filepath.Join(root, "engine", "internal", "adminapi")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range adminRoute.FindAllStringSubmatch(string(src), -1) {
			out[m[1]] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("no admin routes were found. The registration shape has " +
			"changed and this test is now passing vacuously, which is worse " +
			"than not existing.")
	}
	return out
}

func documentedAdminRoutes(t *testing.T, root string) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "docs", "admin-api.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range docRoute.FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = true
	}
	return out
}

func TestEveryAdminAPIRouteIsDocumented(t *testing.T) {
	root := repoRoot(t)
	routes := adminRoutes(t, root)
	documented := documentedAdminRoutes(t, root)

	var missing []string
	for r := range routes {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	sort.Strings(missing)
	for _, r := range missing {
		t.Errorf("%s is served and is not in docs/admin-api.md. The document is "+
			"the whole interface for anyone integrating against this API; a "+
			"route missing from it is a capability that exists and cannot be "+
			"found.", r)
	}
}

func TestEveryDocumentedAdminAPIRouteExists(t *testing.T) {
	root := repoRoot(t)
	routes := adminRoutes(t, root)
	documented := documentedAdminRoutes(t, root)

	var invented []string
	for r := range documented {
		if !routes[r] {
			invented = append(invented, r)
		}
	}
	sort.Strings(invented)
	for _, r := range invented {
		t.Errorf("docs/admin-api.md documents %s and nothing serves it. "+
			"Somebody will build against this and find out at runtime.", r)
	}
}
