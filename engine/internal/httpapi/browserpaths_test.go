package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// browserPaths are the shapes a path on this origin takes where it is written down for
// a browser: a literal with a query on it, a redirect, and a link or a form on a page.
var browserPaths = []*regexp.Regexp{
	regexp.MustCompile(`"(/[a-z][a-zA-Z0-9_./-]*)\?`),
	regexp.MustCompile(`http\.Redirect\(\s*w,\s*r,\s*"(/[a-z][a-zA-Z0-9_./-]*)"`),
	regexp.MustCompile(`parkLogin\("(/[a-z][a-zA-Z0-9_./-]*)"`),
	regexp.MustCompile(`"Location",\s*"(/[a-z][a-zA-Z0-9_./-]*)"`),
	regexp.MustCompile(`(?:href|action|formaction)="(/[a-z][a-zA-Z0-9_./-]*)`),
}

// Every path this engine sends a browser to is one it serves. A sign-in through a
// provider ended at /authorize, which nothing has ever routed, for two weeks: the
// person had signed in upstream and arrived at a 404, and the test beside it had the
// wrong path written out too, so it agreed. Nothing here asked the router (0.85).
func TestEveryPathABrowserIsSentToIsRouted(t *testing.T) {
	f := newTokenFixture(t)
	mux := f.srv.mux()
	routed := func(path string) bool {
		// A literal ending in a slash has an identifier added to it where it is used.
		if strings.HasSuffix(path, "/") {
			path += "x"
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if _, pattern := mux.Handler(httptest.NewRequest(method, "https://id.test"+path, nil)); pattern != "" {
				return true
			}
		}
		return false
	}

	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	pages, err := filepath.Glob("../pages/files/*.html")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, file := range append(sources, pages...) {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, shape := range browserPaths {
			for _, m := range shape.FindAllSubmatch(raw, -1) {
				found[string(m[1])] = file
			}
		}
	}
	if len(found) < 30 {
		t.Fatalf("only %d paths found, so this looked at nothing", len(found))
	}
	var missing []string
	for path, file := range found {
		if !routed(path) {
			missing = append(missing, path+" ("+file+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("a browser is sent somewhere nothing serves: %s", m)
	}
}
