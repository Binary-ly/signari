package docsync

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// No committed page cites a source file that this repository does not hold.
//
// # Why
//
// Reading other identity products' source is encouraged, and the record of
// having done it stays out of every committed file (CLAUDE.md, "Studying
// competitors"). TestNoCompetitorIsNamedInAPublishedFile enforces that by name.
// It cannot see the record once the name is gone, and the name is the first
// thing a careful writer removes. A published page carried this for three
// months, with no product named anywhere near it:
//
//	`Profile.java:177` carries `SSF("Shared Signals Framework", ...)`
//
// A file path and a line identify the product as exactly as its name does.
//
// # The direction the failure travels
//
// The citation comes from somebody else's tree into a page here. So the test
// does not need a list of rivals, or of their languages, which would miss the
// next one (several are written in Go, as Signari is). It asks the one thing
// that separates our files from theirs: does git track a file with that path
// here? `internal/saml/encrypt.go:107` and `authorize.go:324` are suffixes of
// tracked paths, and pass. `Profile.java:177` is a suffix of nothing, and fails.
// So does a citation of one of Signari's own files under a name it no longer
// has, which is worth failing for too.
//
// # What it reads, and what it leaves alone
//
// It reads every committed Markdown file, outside fenced code blocks: prose,
// tables, inline code and link targets, where a citation sits. A code block is
// what the reader types or writes, so a file named there is theirs (a build.sh
// they create). It leaves alone what is an address and not a path in a
// repository: a URL, a host-qualified path such as
// `challenges.example.com/api.js`, a route such as `/passkey.js`, and a path
// that starts at `$SRC` or `~`. A URL naming a rival is the name guard's to
// catch. It reads only files whose extension is a programming language's, since
// configuration a reader writes (`values.yaml`) is not a citation of anyone's
// source.
//
// It cannot see a class or method named without its file, such as
// `JsonWebToken.isActive()`. Those are found by reading, as that one was.
//
// The migrate-from pages are exempt, as they are from the name guard: a
// migration names the product it migrates from, and its tools.
func TestNoPublishedPageCitesSourceThisRepositoryDoesNotHold(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		// As TestEveryDocumentLinkResolvesForAReader: only git can say what a
		// reader gets, and a disk-based fallback would pass on the machine that
		// holds the local-only files.
		t.Skipf("cannot ask git what is tracked: %v", err)
	}
	var tracked []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			tracked = append(tracked, filepath.ToSlash(f))
		}
	}
	if len(tracked) == 0 {
		t.Skip("git reported no tracked files")
	}
	held := sourceSuffixes(tracked)

	used := map[[2]string]bool{}
	var found []string
	for _, page := range tracked {
		if !strings.HasSuffix(page, ".md") || hasAnyPrefix(page, sourceCitationExempt) {
			continue
		}
		for _, c := range sourceCitations(readRaw(t, filepath.Join(root, filepath.FromSlash(page)))) {
			if held[c.path] {
				continue
			}
			if key := [2]string{page, c.path}; sourceCitationAllowed[key] != "" {
				used[key] = true
				continue
			}
			found = append(found, page+":"+itoa(c.line)+": "+c.path)
		}
	}
	if len(found) > 0 {
		t.Errorf("%d source file(s) are cited on a committed page, and no file git tracks here has that path:\n  %s\n\n"+
			"A path such as Foo.java:177 names a file somebody can open, so a file this repository does not hold "+
			"is another project's source. Cited from an identity product, it is the record of a comparison, which "+
			"CLAUDE.md keeps out of every committed file: state the rule on its own terms, and move the comparison "+
			"to a local-only docs/competitor-review-*.md. If it is Signari's own file under an old name, cite the "+
			"new one. If it is a dependency's or a tool's file that the page has a reason to cite, add it to "+
			"sourceCitationAllowed with that reason.",
			len(found), strings.Join(found, "\n  "))
	}

	// An allowance whose citation has gone is a hole nothing uses, waiting for
	// the next citation of that path on that page.
	var stale []string
	for key := range sourceCitationAllowed {
		if !used[key] {
			stale = append(stale, key[0]+": "+key[1])
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d allowance(s) in sourceCitationAllowed are no longer used; delete them:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// sourceCitationExempt are the pages where naming another product's files is the
// feature, as in TestNoCompetitorIsNamedInAPublishedFile's migration list.
var sourceCitationExempt = []string{"docs/migrate-from-"}

// sourceCitationAllowed are the files of other projects that a page cites for a
// reason, by page and path. None is an identity product's. Each is allowed on
// that page only, so the same path cited anywhere else is still a finding.
var sourceCitationAllowed = map[[2]string]string{
	{"docs/connection-pooling.md", "conn.go"}: "pgx v5's, the PostgreSQL driver in engine/go.mod; " +
		"the page shows which query modes survive a pooler from its source",
	{"docs/security-review-asvs.md", "crypto/tls/defaults.go"}: "the Go standard library's; " +
		"the page quotes the TLS defaults the engine inherits",
	{"docs/security-scanning.md", "internal/impl/codec_gen.go"}: "protobuf-go's; " +
		"the page shows that the OTLP exporter encodes an int64 as protobuf's own encoder does",
	{"docs/fuzzing.md", "build.sh"}: "the OSS-Fuzz project file a reader writes, shown in full on the page",
	{"engine/internal/rac/static/PROVENANCE.md", "dist/esm/guacamole-common.js"}: "the file in the " +
		"guacamole-common-js package that this directory vendors",
	{"admin/resources/views/vendor/README.md", "filament/resources/views/components/layout/base.blade.php"}: filamentOriginal,
	{"admin/resources/views/vendor/README.md", "filament/resources/views/livewire/sidebar.blade.php"}:       filamentOriginal,
	{"admin/resources/views/vendor/README.md", "support/resources/views/assets.blade.php"}:                  filamentOriginal,
	{"deploy/conformance/README.md", "scripts/run-test-plan.py"}: "the OpenID Foundation conformance " +
		"suite's runner, which deploy/conformance drives",
	{"deploy/conformance/README.md", "BrowserControl.java"}: "the conformance suite's browser, whose " +
		"behaviour the page explains",
	{"deploy/conformance/README.md", "bootstrap.min.js"}: "the script on the conformance suite's own " +
		"results page, in an error the page explains",
}

// filamentOriginal is the reason for the console's overridden views: the README
// beside them names the file in the Filament package each one replaces.
const filamentOriginal = "Filament's original of a view the console overrides, in the package admin/composer.json requires"

// sourceExtensions are the extensions of programming languages' source files.
var sourceExtensions = map[string]bool{
	"c": true, "cc": true, "cjs": true, "clj": true, "cpp": true, "cs": true, "erl": true, "ex": true,
	"exs": true, "ftl": true, "go": true, "groovy": true, "h": true, "hpp": true, "java": true, "js": true,
	"jsp": true, "jsx": true, "kt": true, "kts": true, "lua": true, "mjs": true, "php": true, "pl": true,
	"py": true, "rb": true, "rs": true, "scala": true, "sh": true, "sql": true, "svelte": true,
	"swift": true, "ts": true, "tsx": true, "vue": true,
}

// sourceNamesNotFiles are products whose names end like a file.
var sourceNamesNotFiles = map[string]bool{"Next.js": true, "Node.js": true}

var (
	// A run of the characters a path can hold, with an optional :line or
	// :first-last after it.
	sourceCitationToken = regexp.MustCompile(`[A-Za-z0-9_./$@+\[\]~-]+(?::[0-9]+(?:[-–][0-9]+)?)?`)
	sourceCitationLine  = regexp.MustCompile(`:[0-9]+(?:[-–][0-9]+)?$`)
	sourceCitationFence = regexp.MustCompile("^[ \t]*(```|~~~)")
	sourceCitationHost  = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
)

type sourceCitation struct {
	line int
	path string
}

// sourceCitations is every source file a page names outside its code blocks,
// with the line it is on and the path as written, its line number and any
// leading ./ or ../ removed.
func sourceCitations(text string) []sourceCitation {
	var out []sourceCitation
	fence := false
	for i, line := range strings.Split(text, "\n") {
		if sourceCitationFence.MatchString(line) {
			fence = !fence
			continue
		}
		if fence {
			continue
		}
		for _, tok := range sourceCitationToken.FindAllString(line, -1) {
			p := sourceCitationLine.ReplaceAllString(tok, "")
			p = strings.TrimLeft(p, "[(")
			p = strings.TrimRight(p, ".,;)]")
			if p == "" || strings.ContainsAny(p[:1], "/$~") || sourceNamesNotFiles[p] {
				continue
			}
			if first, _, more := strings.Cut(p, "/"); more && sourceCitationHost.MatchString(first) {
				continue // an address: a host and a path on it
			}
			for strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") {
				_, p, _ = strings.Cut(p, "/")
			}
			name := p[strings.LastIndex(p, "/")+1:]
			dot := strings.LastIndex(name, ".")
			if dot <= 0 || !sourceExtensions[name[dot+1:]] {
				continue // a directory, a dotfile, or not a language's source
			}
			out = append(out, sourceCitation{i + 1, p})
		}
	}
	return out
}

// sourceSuffixes is every path a citation of a tracked file can take: the file's
// whole path, and each tail of it that starts at a directory boundary. So
// engine/internal/saml/encrypt.go may be cited as internal/saml/encrypt.go,
// saml/encrypt.go or encrypt.go, but not as crypt.go.
func sourceSuffixes(tracked []string) map[string]bool {
	held := map[string]bool{}
	for _, f := range tracked {
		parts := strings.Split(f, "/")
		for i := range parts {
			held[strings.Join(parts[i:], "/")] = true
		}
	}
	return held
}

// The guard's own guard. A scan that reads nothing and a tree that cites
// nothing report the same success, so this holds the reader to the shapes it
// must see and the ones it must leave alone.
func TestTheSourceCitationScanSeesAnotherProductsFile(t *testing.T) {
	page := strings.Join([]string{
		"# A page", // 1
		"",
		"Re-checked: `Profile.java:177` carries the flag.",                           // 3
		"See `internal/saml/encrypt.go:107`, and [the client](../sdk/go/client.go).", // 4
		"A bare kc_admin.py names it too, as does Rival.java.",                       // 5
		"```sh",
		"cat build.sh",
		"```",
		"Next.js runs at https://example.com/app.js and loads challenges.example.com/api.js.", // 9
		"The browser fetches `/passkey.js`; the build runs `$SRC/build.sh`; `kc/ssf/` is a folder.",
		"Write `values.yaml`, then `.env`.",
	}, "\n")
	got := sourceCitations(page)
	want := []sourceCitation{
		{3, "Profile.java"},
		{4, "internal/saml/encrypt.go"},
		{4, "sdk/go/client.go"},
		{5, "kc_admin.py"},
		{5, "Rival.java"},
	}
	if len(got) != len(want) {
		t.Fatalf("the scan found %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("citation %d: got %v, want %v", i, got[i], want[i])
		}
	}

	held := sourceSuffixes([]string{"engine/internal/saml/encrypt.go", "sdk/go/client.go"})
	for path, want := range map[string]bool{
		"internal/saml/encrypt.go": true,
		"encrypt.go":               true,
		"crypt.go":                 false,
		"Profile.java":             false,
		"sdk/go/client.go":         true,
	} {
		if held[path] != want {
			t.Errorf("%s held: got %v, want %v", path, held[path], want)
		}
	}
}
