package main

import (
	"crypto/fips140"
	"fmt"
	"io"
	"runtime/debug"

	"signari.dev/engine/internal/migrate"
)

// version is the release this binary was built as. scripts/build-release.sh
// sets it with -X main.version; any other build leaves it empty.
var version string

// printVersion says what this binary is: which release, from which commit,
// with which toolchain and cryptographic module, for which schema, and
// whether it is pinned to that schema's fingerprint. One `key value` per
// line, so a release script can read a value with awk, and nothing that
// needs a database, so it answers on a machine that has none.
func printVersion(w io.Writer) error {
	release := version
	if release == "" {
		release = "unreleased (not built by scripts/build-release.sh)"
	}
	commit, toolchain, module := "unknown", "unknown", "none"
	if bi, ok := debug.ReadBuildInfo(); ok {
		toolchain = bi.GoVersion
		modified := false
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				commit = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			case "GOFIPS140":
				module = s.Value
			}
		}
		if modified {
			commit += " (with uncommitted changes)"
		}
	}
	fips := "disabled"
	if fips140.Enabled() {
		fips = "enabled"
	}
	all, err := migrate.Load()
	if err != nil {
		return err
	}
	pinned := migrate.ExpectedFingerprint
	if pinned == "" {
		pinned = "none (the schema is compared only with its ledger; see docs/schema-pinning.md)"
	}
	for _, l := range [][2]string{
		{"version", release},
		{"commit", commit},
		{"go", toolchain},
		{"fips140", fips + ", module " + module},
		{"schema", fmt.Sprint(all[len(all)-1].Version)},
		{"pinned", pinned},
	} {
		if _, err := fmt.Fprintf(w, "%-8s %s\n", l[0], l[1]); err != nil {
			return err
		}
	}
	return nil
}
