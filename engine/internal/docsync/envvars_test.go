// Package docsync holds checks that documentation and code still agree.
//
// Not a sweep run by hand and remembered, but a test: the three drifts this
// project has already had -- configuration described and never read, a
// capability advertised and not implemented, a column stored and never
// consulted -- all shared one shape. Somebody changed the code and the prose
// stayed where it was.
package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var envRE = regexp.MustCompile(`SIGNARI_[A-Z0-9_]+`)

var (
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`(?m)^\s*//.*$`)
)

// readSource returns a file with comments removed.
//
// A setting named in a comment is not a setting the engine reads. Two files in
// this project discuss SIGNARI_RADIUS_CLIENTS at length precisely because it
// never existed -- and the first version of this test scanned its own comment
// saying so and reported it as an undocumented control.
func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := blockComment.ReplaceAllString(string(b), "")
	return lineComment.ReplaceAllString(s, "")
}

// TestEveryEnvVarIsDocumented fails when the engine reads a setting that
// docs/configuration.md does not mention.
//
// The gap this closes was real and quiet: SIGNARI_SMTP_USERNAME,
// SIGNARI_SMTP_PASSWORD, SIGNARI_SMTP_PORT and SIGNARI_MAIL_FROM_NAME were read
// by the code and documented nowhere, so an authenticated relay -- the normal
// way anybody sends mail -- could not be configured from the documentation.
// SIGNARI_DEVICE_COMPLIANT_HEADER was missing too, while the policy condition
// it feeds was documented, so a rule could be written that nothing could
// satisfy.
func TestEveryEnvVarIsDocumented(t *testing.T) {
	root := repoRoot(t)

	inCode := map[string]string{} // name -> first file that reads it
	err := filepath.Walk(filepath.Join(root, "engine"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		for _, name := range envRE.FindAllString(readSource(t, p), -1) {
			if _, seen := inCode[name]; !seen {
				rel, _ := filepath.Rel(root, p)
				inCode[name] = rel
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inCode) < 20 {
		t.Fatalf("found only %d settings in the source; the walk is wrong and this "+
			"test would pass by finding nothing", len(inCode))
	}

	ref, err := os.ReadFile(filepath.Join(root, "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("docs/configuration.md is missing: %v", err)
	}
	documented := map[string]bool{}
	for _, name := range envRE.FindAllString(string(ref), -1) {
		documented[name] = true
	}

	var missing []string
	for name, file := range inCode {
		if !documented[name] {
			missing = append(missing, name+"  (read in "+file+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d setting(s) are read by the engine and absent from "+
			"docs/configuration.md:\n  %s\n\nA control nobody knows exists is a "+
			"control nobody uses, and the ones this caught were how you configure "+
			"an authenticated mail relay.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestNoDocumentedSettingIsUnread is the other direction: prose promising a
// control the code does not read.
//
// Only docs/configuration.md is checked. Other pages legitimately discuss
// settings that do NOT exist -- two of them describe an earlier version of this
// project documenting SIGNARI_RADIUS_CLIENTS, which never existed, as a warning
// about exactly this class of drift.
func TestNoDocumentedSettingIsUnread(t *testing.T) {
	root := repoRoot(t)

	ref, err := os.ReadFile(filepath.Join(root, "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}

	inCode := map[string]bool{}
	_ = filepath.Walk(filepath.Join(root, "engine"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		for _, name := range envRE.FindAllString(readSource(t, p), -1) {
			inCode[name] = true
		}
		return nil
	})

	var phantom []string
	for _, name := range envRE.FindAllString(string(ref), -1) {
		if !inCode[name] {
			phantom = append(phantom, name)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Fatalf("docs/configuration.md documents %d setting(s) nothing reads:\n  %s\n\n"+
			"An operator who sets one believes they have a control they do not.",
			len(phantom), strings.Join(uniq(phantom), "\n  "))
	}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// repoRoot walks up until it finds the docs directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "docs")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root from the test's directory")
	return ""
}
