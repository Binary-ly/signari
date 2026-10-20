package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"signari.dev/engine/internal/migrate"
)

// scripts/build-release.sh refuses to tag a build whose `version` does not
// report the pin it was given, read with awk as the second field of the
// `pinned` line. The line has to say the pin when there is one and anything
// else when there is not, and keep that shape.
func TestVersionReportsThePinTheReleaseScriptChecks(t *testing.T) {
	pinOf := func() string {
		t.Helper()
		var out bytes.Buffer
		if err := printVersion(&out); err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(out.String(), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "pinned" {
				return f[1]
			}
		}
		t.Fatalf("no pinned line in:\n%s", out.String())
		return ""
	}
	saved := migrate.ExpectedFingerprint
	t.Cleanup(func() { migrate.ExpectedFingerprint = saved })

	migrate.ExpectedFingerprint = ""
	if got := pinOf(); got != "none" {
		t.Errorf("an unpinned binary reports pin %q", got)
	}
	fp := strings.Repeat("ab", 32)
	migrate.ExpectedFingerprint = fp
	if got := pinOf(); got != fp {
		t.Errorf("a binary pinned to %s reports %q", fp, got)
	}

	var out bytes.Buffer
	if err := printVersion(&out); err != nil {
		t.Fatal(err)
	}
	all, err := migrate.Load()
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("schema   %d\n", all[len(all)-1].Version); !strings.Contains(out.String(), want) {
		t.Errorf("version does not name the schema this binary expects (%q):\n%s", want, out.String())
	}
}
