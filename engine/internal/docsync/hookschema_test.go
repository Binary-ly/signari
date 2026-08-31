package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The schema must accept every extension hook the code knows about.
//
// # The failure this catches
//
// `core.providers` was created with `CHECK (hook IN ('authorize'))`, correctly:
// `authorize` was the only hook. Later, `internal/provider` gained
// `HookTokenIssue`, migration 0117 added `providers.allowed_claims` to bound
// what a token hook may contribute, and the token path gained a call to
// `ConsultTokenProvider`. The CHECK was never widened.
//
// Every piece was present and the capability was unreachable. Registering the
// hook was refused by the database, so no row existed, so the column governing
// it applied to nothing, so the call on the token path found no provider and
// returned. No error anywhere — the hook simply never fired, which reads exactly
// like "no operator has configured one".
//
// Three existing guards were green throughout, and it is worth saying why each
// missed it:
//
//   - `provider.Hook.Called()` asks whether a decision point CONSULTS the hook.
//     It does. That was never the problem.
//   - `TestEveryConfigurableCapabilityIsReachable` asks whether the function has
//     a caller. It has one, on the request path.
//   - `TestEveryColumnAddedForBehaviourCanBeWritten` asks whether the column has
//     a writer. It does, once `signari provider claims` existed — and the write
//     still cannot land, because no row can exist to write to.
//
// Each guard was correct and none could see a constraint. This one reads the
// constraint.

// hookConst matches `HookSomething Hook = "value"` in the provider package.
var hookConst = regexp.MustCompile(`Hook\w*\s+Hook\s*=\s*"([a-z_]+)"`)

// hookCheck matches the accepted set in a CHECK on the providers.hook column,
// in either spelling PostgreSQL and this repo use.
var hookCheck = regexp.MustCompile(`(?is)CONSTRAINT\s+providers_hook_check\s+CHECK\s*\(\s*hook\s+IN\s*\(([^)]*)\)`)

// hookInline matches the constraint as written inline in a CREATE TABLE.
var hookInline = regexp.MustCompile(`(?is)hook\s+text\s+NOT NULL\s+CHECK\s*\(\s*hook\s+IN\s*\(([^)]*)\)`)

func quotedValues(s string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

func TestEverySupportedHookIsAcceptedBySchema(t *testing.T) {
	root := repoRoot(t)

	// What the code declares.
	src, err := os.ReadFile(filepath.Join(root, "engine", "internal", "provider", "provider.go"))
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	for _, m := range hookConst.FindAllStringSubmatch(string(src), -1) {
		declared = append(declared, m[1])
	}
	if len(declared) == 0 {
		t.Fatal("no Hook constants found in internal/provider/provider.go; this test " +
			"has stopped reading what it thinks it reads, which is worse than not " +
			"having it")
	}
	sort.Strings(declared)

	// What the schema accepts, after every migration has run. Migrations are
	// applied in order and the constraint may be replaced, so the LAST definition
	// is the live one — reading the first would report the state the database was
	// in several versions ago.
	dir := filepath.Join(root, "engine", "migrations", "core")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // zero-padded, so lexical order is migration order

	var accepted []string
	var from string
	for _, n := range names {
		body, rerr := os.ReadFile(filepath.Join(dir, n))
		if rerr != nil {
			t.Fatal(rerr)
		}
		text := string(body)
		if m := hookInline.FindStringSubmatch(text); m != nil {
			accepted, from = quotedValues(m[1]), n
		}
		if m := hookCheck.FindStringSubmatch(text); m != nil {
			accepted, from = quotedValues(m[1]), n
		}
	}
	if accepted == nil {
		t.Fatal("no providers_hook_check constraint found in the migrations; if the " +
			"constraint was dropped rather than widened, a typo in -hook is now stored " +
			"and consulted by nothing, which is the same silence from the other side")
	}

	for _, h := range declared {
		if !slicesContains(accepted, h) {
			t.Errorf("internal/provider declares the hook %q and the schema refuses it "+
				"(%s accepts only %s).\n\n"+
				"Registering it fails, so no row exists, so nothing consults it and "+
				"nothing errors — the hook reads as unconfigured rather than "+
				"unreachable. Widen the CHECK in a new migration.",
				h, from, strings.Join(accepted, ", "))
		}
	}
	for _, a := range accepted {
		if !slicesContains(declared, a) {
			t.Errorf("the schema accepts the hook %q (%s) and internal/provider "+
				"declares no such Hook.\n\n"+
				"An operator can register it, `provider list` will show it, and no "+
				"decision point will ever call it.", a, from)
		}
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
