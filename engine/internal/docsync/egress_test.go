package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every outbound HTTP client is safedial's unless it is listed here with the
// reason it need not be.
//
// Seven were not. The upstream identity provider's token endpoint and keys,
// the jwt-bearer issuer's keys, an SSF source's keys, a SCIM target, the old
// provider behind delegated sign-in, the SMS gateway and Duo's API host are
// all stored or configured settings, and each was fetched through a plain
// client, so a value naming or resolving to 169.254.169.254 or the admin
// listener on loopback was dialled. The webhook and logout paths had the guard;
// the rest had been written before it existed and nothing asked.
//
// The direction of failure is a new client added without thinking about where
// its destination comes from, so the guard matches construction, not the
// destinations already known: a client literal, a transport literal, or the
// package-level defaults, in non-test code outside safedial itself.
var clientsOutsideSafedial = map[string]string{
	"engine/internal/captcha/captcha.go": "the three vendors' siteverify endpoints are constants; " +
		"nothing configurable reaches the URL",
	"engine/internal/passwords/breached.go": "the range API is a constant; the override is set " +
		"only by tests",
	"engine/internal/posture/chrome.go": "Google's Verified Access endpoint is a constant; the " +
		"override is set only by tests",
	// Not provision/google.go or directory/google.go. They were listed here as
	// "admin.googleapis.com is a constant", and the API host is -- but the token
	// request goes to the token_uri in the stored key file, which is data. Both
	// now use safedial.
	"engine/internal/provision/entra.go": "graph.microsoft.com and login.microsoftonline.com " +
		"are constants, the tenant only a path segment",
	"engine/internal/directory/entra.go": "graph.microsoft.com and login.microsoftonline.com " +
		"are constants, the tenant only a path segment",
	"engine/internal/outbox/tls.go": "safedial's transport; under SIGNARI_ALLOW_PRIVATE_DELIVERY " +
		"safedial's private-allowing one, which still refuses the metadata address",
	"engine/internal/outpost/outpost.go": "the outpost agent calling its own engine, run by the " +
		"operator on their network; not the engine making a request",
	"engine/internal/logouttest/logouttest.go": "a diagnostic run by hand against a URL the " +
		"operator types",
	"engine/internal/proxycheck/proxycheck.go": "a diagnostic run by hand against a URL the " +
		"operator types",
	"engine/cmd/signari/apiclient.go": "the operator's CLI calling the Admin API at the address they " +
		"type, usually on their own network, which safedial refuses by design; not the engine making a " +
		"request. It follows no redirect and sends its token in the clear only to loopback",
}

func TestEveryOutboundClientIsSafedialsOrListed(t *testing.T) {
	root := repoRoot(t)
	construct := regexp.MustCompile(
		`http\.(Client|Transport)\{|http\.Default(Client|Transport)\b|http\.(Get|Head|Post|PostForm)\(`)

	found := map[string][]string{}
	scanned := 0
	err := filepath.Walk(filepath.Join(root, "engine"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") ||
			strings.HasSuffix(p, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "engine/internal/safedial/") {
			return nil
		}
		scanned++
		for _, line := range strings.Split(readSource(t, p), "\n") {
			code := line
			if i := strings.Index(code, "//"); i >= 0 {
				code = code[:i] // a comment naming http.DefaultClient is not a use of it
			}
			if construct.MatchString(code) {
				found[rel] = append(found[rel], strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("only %d non-test Go files scanned; the walk is wrong", scanned)
	}

	var unlisted []string
	for file, lines := range found {
		if _, ok := clientsOutsideSafedial[file]; !ok {
			for _, l := range lines {
				unlisted = append(unlisted, file+": "+l)
			}
		}
	}
	sort.Strings(unlisted)
	for _, u := range unlisted {
		t.Errorf("an outbound client not built by safedial: %s\n\tuse safedial.Client, "+
			"ClientAllowing or ClientTrusting; or, if its destination cannot come from "+
			"configuration or a request, list the file in clientsOutsideSafedial with why", u)
	}

	// The list cannot outlive what it excuses: an entry whose file no longer
	// builds a client would excuse the next one added there without anyone
	// deciding it should.
	for file := range clientsOutsideSafedial {
		if len(found[file]) == 0 {
			t.Errorf("%s is excused from safedial but builds no client; remove the entry", file)
		}
	}
}
