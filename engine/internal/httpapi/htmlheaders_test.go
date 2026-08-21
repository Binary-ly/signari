package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every HTML response this package sends must carry a Content-Security-Policy
// and `Cache-Control: no-store`.
//
// A source-scanning test rather than a per-handler one, because the defect it
// guards against is not a wrong header on a known page -- it is a NEW page
// written without one. Six existed:
//
//	handleConnectedApps        no policy, no cache header
//	writeAuthzError            no policy, no cache header
//	samlRefuse                 no policy, no cache header
//	federationError            no policy
//	renderLogoutConfirmation   no policy
//	renderAuthzFailure         no policy
//
// All six are error or notice pages. Nobody omitted the headers deliberately;
// they are the pages written while thinking about a failure, and the two ways of
// sending HTML in this package -- through `renderPage`, or by setting a
// Content-Type by hand -- differ in whether the headers come for free.
//
// A test that renders each page would have to know how to reach each page, which
// is why the gap survived: `samlRefuse` is reached only by a malformed SAML
// request, and nothing had ever sent one at that particular shape.
func TestEveryHTMLResponseCarriesAPolicyAndNoStore(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	type site struct {
		file, fn string
		line     int
	}
	var missing []site

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, l := range lines {
			if !strings.Contains(l, "text/html") || !strings.Contains(l, "Set(") {
				continue
			}
			// The enclosing function, from the preceding `func ` to the next one.
			start := i
			for start > 0 && !strings.HasPrefix(lines[start], "func ") {
				start--
			}
			end := i + 1
			for end < len(lines) && !strings.HasPrefix(lines[end], "func ") {
				end++
			}
			body := strings.Join(lines[start:end], "\n")

			hasPolicy := strings.Contains(body, "setCSP") ||
				strings.Contains(body, "htmlPageHeaders") ||
				strings.Contains(body, "Content-Security-Policy")
			hasNoStore := strings.Contains(body, "no-store") ||
				strings.Contains(body, "htmlPageHeaders")

			if !hasPolicy || !hasNoStore {
				name := strings.TrimSpace(lines[start])
				if len(name) > 60 {
					name = name[:60]
				}
				missing = append(missing, site{f, name, i + 1})
			}
		}
	}

	for _, m := range missing {
		t.Errorf("%s:%d sends HTML without a Content-Security-Policy or without "+
			"Cache-Control: no-store.\n\t%s\n\tUse htmlPageHeaders(w) unless the page "+
			"posts a form to another origin -- postSAMLResponse is the one that "+
			"does, and says so.", m.file, m.line, m.fn)
	}

	// The scan must actually find HTML responses, or a refactor that changed how
	// Content-Type is set would turn this into a test of nothing.
	var seen int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(f)
		seen += strings.Count(string(raw), `"text/html; charset=utf-8"`)
	}
	if seen < 5 {
		t.Fatalf("the scan found only %d HTML responses in this package, which is "+
			"too few to be right -- it is no longer looking at what it thinks", seen)
	}
}
