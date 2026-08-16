package docsync

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Keeping docs/fips.md true.
//
// The FIPS page names the packages that cannot run under GODEBUG=fips140=only
// and says why for each. That list is exactly the kind of thing that is correct
// on the day it is written and quietly wrong three months later: somebody adds
// an MD5 checksum to a new package, everything passes, and the page now
// understates what breaks.
//
// So the page is checked against the code in both directions. A package that
// imports a non-approved primitive must be named. A package that is named must
// still import one, because a stale entry is a claim that a feature is broken
// when it is not, and that costs somebody an afternoon.
//
// This does not run the suite under FIPS -- that is a build mode, not something
// a test can enter from inside. It checks the thing that drifts.

// nonApproved are primitives outside the FIPS 140-3 module.
//
// Two different situations, deliberately in one list. crypto/md5 and crypto/sha1
// are REFUSED under fips140=only. The x/crypto entries are not refused, because
// the module has no opinion about code outside it -- they are simply not
// covered, which for a compliance boundary is the same problem wearing a
// different hat. Both belong on a page about what a FIPS deployment gets.
var nonApproved = []string{
	"crypto/md5",
	"crypto/sha1",
	"crypto/rc4",
	"crypto/des",
	"golang.org/x/crypto/argon2",
	"golang.org/x/crypto/bcrypt",
	"golang.org/x/crypto/scrypt",
	"golang.org/x/crypto/pbkdf2",
	"golang.org/x/crypto/blowfish",
	"golang.org/x/crypto/md4",
	"golang.org/x/crypto/ripemd160",
}

func TestFIPSNotesEveryNonApprovedImport(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "fips.md"))
	if err != nil {
		t.Fatalf("reading the FIPS page: %v", err)
	}
	doc := string(page)

	uses := map[string][]string{} // package path -> primitives it imports
	root := filepath.Join("..", "..")
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Test files are excluded on purpose: a test that pins a foreign hash
		// format needs the algorithm that format uses, and it says nothing about
		// what a running deployment does.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body := readSource(t, path)
		pkg := packagePathOf(path)
		for _, prim := range nonApproved {
			if strings.Contains(body, `"`+prim+`"`) {
				uses[pkg] = appendOnce(uses[pkg], prim)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var undocumented []string
	for pkg, prims := range uses {
		if !strings.Contains(doc, pkg) {
			sort.Strings(prims)
			undocumented = append(undocumented,
				pkg+" (imports "+strings.Join(prims, ", ")+")")
		}
	}
	if len(undocumented) > 0 {
		sort.Strings(undocumented)
		t.Errorf("these packages use crypto outside the FIPS module and docs/fips.md "+
			"does not mention them, so the page understates what a FIPS deployment "+
			"loses:\n  %s", strings.Join(undocumented, "\n  "))
	}

	// And the other direction: a named package that no longer uses one.
	for _, pkg := range namedPackages(doc) {
		if _, ok := uses[pkg]; !ok {
			t.Errorf("docs/fips.md names %s, but it no longer imports anything "+
				"outside the FIPS module -- the page claims a feature is broken "+
				"when it is not", pkg)
		}
	}
}

// packagePathOf turns a walked file path into the import path the page uses.
func packagePathOf(path string) string {
	dir := filepath.ToSlash(filepath.Dir(path))
	if i := strings.Index(dir, "internal/"); i >= 0 {
		return dir[i:]
	}
	return dir
}

// namedPackages finds `internal/...` paths mentioned in the page.
func namedPackages(doc string) []string {
	var out []string
	for _, field := range strings.FieldsFunc(doc, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '`' || r == ',' || r == '\t'
	}) {
		field = strings.Trim(field, ".;:()")
		if strings.HasPrefix(field, "internal/") && !strings.Contains(field, "*") {
			out = append(out, field)
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func appendOnce(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

func dedupe(in []string) []string {
	var out []string
	for i, v := range in {
		if i == 0 || in[i-1] != v {
			out = append(out, v)
		}
	}
	return out
}
