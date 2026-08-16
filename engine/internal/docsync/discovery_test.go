package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Nothing enters discovery until it is routed.
//
// This is the bug this project started from. The discovery document advertised
// revocation_endpoint, introspection_endpoint and the client_credentials grant,
// and all three answered 404. A relying party has no way to find that out
// except by trying it in production, because discovery is precisely the
// mechanism it uses instead of asking.
//
// The rule written down at the time was: an endpoint enters discovery once it
// works. A rule that lives only in a document is a rule that lasts until the
// next person is in a hurry, so it lives here as well.
//
// This checks routing, not correctness. An endpoint that is registered and
// returns the wrong thing is a different problem, and one that handler tests
// are the right place for. What this catches is the specific asymmetry that
// caused the original bug: it is easy to add a line to the metadata builder and
// forget the line in the router, and nothing else notices.

// advertised finds the paths the metadata builder puts in the document.
//
// Two forms, because both are used: a named constant, and a literal for the
// endpoints that have no constant.
var (
	advertisedConst   = regexp.MustCompile(`Endpoint(?:s)?:\s*(?:\w+\()?at\((Path\w+)\)`)
	advertisedLiteral = regexp.MustCompile(`Endpoint(?:s)?:\s*(?:\w+\()?at\("([^"]+)"\)`)
	pathConstDecl     = regexp.MustCompile(`(Path\w+)\s*=\s*"([^"]+)"`)
	// Routes are registered in two forms and BOTH must be read. Most are
	// "METHOD "+oidc.PathX; a few are a quoted path. A check that knew only the
	// literal form would report every constant-registered endpoint as missing --
	// which is the first thing this test did, and a sweep that cries wolf is
	// worse than no sweep.
	routeLiteral = regexp.MustCompile(`mux\.Handle(?:Func)?\("(?:[A-Z]+\s+)?(/[^"]*)"`)
	routeConst   = regexp.MustCompile(`mux\.Handle(?:Func)?\("[A-Z]+ "\s*\+\s*\w+\.(Path\w+)`)
)

func TestEveryAdvertisedEndpointIsRouted(t *testing.T) {
	root := repoRoot(t)
	oidcDir := filepath.Join(root, "engine", "internal", "oidc")

	// The path constants.
	consts := map[string]string{}
	for _, f := range []string{"metadata.go", "oidc.go", "paths.go"} {
		src := readSourceIfPresent(t, filepath.Join(oidcDir, f))
		for _, m := range pathConstDecl.FindAllStringSubmatch(src, -1) {
			consts[m[1]] = m[2]
		}
	}
	if len(consts) < 5 {
		t.Fatalf("only %d path constants were found; this test is reading the oidc "+
			"package wrong rather than the package having shrunk", len(consts))
	}

	// What discovery advertises.
	meta := readSource(t, filepath.Join(oidcDir, "metadata.go"))
	advertised := map[string]string{} // path -> how it was written
	for _, m := range advertisedConst.FindAllStringSubmatch(meta, -1) {
		p, ok := consts[m[1]]
		if !ok {
			t.Errorf("metadata advertises %s, which is not a path constant this test "+
				"can resolve", m[1])
			continue
		}
		advertised[p] = m[1]
	}
	for _, m := range advertisedLiteral.FindAllStringSubmatch(meta, -1) {
		advertised[m[1]] = `"` + m[1] + `"`
	}
	if len(advertised) < 6 {
		t.Fatalf("only %d advertised endpoints were found in metadata.go; this test "+
			"is reading it wrong", len(advertised))
	}

	// What the router serves.
	routes := map[string]bool{}
	server := readSource(t, filepath.Join(root, "engine", "internal", "httpapi", "server.go"))
	for _, m := range routeLiteral.FindAllStringSubmatch(server, -1) {
		routes[m[1]] = true
	}
	for _, m := range routeConst.FindAllStringSubmatch(server, -1) {
		if p, ok := consts[m[1]]; ok {
			routes[p] = true
		} else {
			t.Errorf("a route is registered with %s, which this test cannot resolve "+
				"to a path", m[1])
		}
	}
	if len(routes) < 20 {
		t.Fatalf("only %d routes were found in server.go; this test is reading it "+
			"wrong", len(routes))
	}

	var unrouted []string
	for path, written := range advertised {
		if routes[path] {
			continue
		}
		unrouted = append(unrouted, path+"  (advertised as "+written+")")
	}
	if len(unrouted) > 0 {
		sort.Strings(unrouted)
		t.Errorf("discovery advertises endpoints the router does not serve, so a "+
			"relying party that trusts the document gets a 404:\n  %s\n\nAn endpoint "+
			"enters discovery once it works, not before.", strings.Join(unrouted, "\n  "))
	}
}

// readSourceIfPresent is readSource for a file that may not exist, because the
// path constants have moved between files before and will again.
func readSourceIfPresent(t *testing.T, path string) string {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return readSource(t, path)
}
