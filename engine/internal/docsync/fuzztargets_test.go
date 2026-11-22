package docsync

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	fuzzFunc     = regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]+)\(f \*testing\.F\)`)
	fuzzBuildCmd = regexp.MustCompile(`(?m)^compile_native_go_fuzzer signari\.dev/engine/(\S+) (Fuzz[A-Za-z0-9_]+) \S+$`)
)

// wireParsers are the packages whose code reads what a stranger sends before anything
// about the sender is known, each with what it reads. Each keeps a fuzz target: a panic
// in any of them is an unauthenticated crash of a listener.
var wireParsers = map[string]string{
	"internal/authzen":    "an access evaluation's JSON from a policy enforcement point",
	"internal/clientip":   "X-Forwarded-For and Forwarded, which any client sets",
	"internal/dpop":       "a DPoP proof header, read before the client is known",
	"internal/jsonstrict": "every JSON body, first",
	"internal/ldapd":      "an LDAP search filter, from anybody who reaches the port",
	"internal/oauth":      "an authorization request's parameters and a PKCE verifier",
	"internal/oid4vp":     "a wallet's answer: an mdoc DeviceResponse, a Digital Credentials API answer",
	"internal/oidfed":     "an entity statement fetched from another entity or posted by a client",
	"internal/proxyproto": "a PROXY v2 header, the first bytes on the listener",
	"internal/radius":     "a RADIUS datagram and the EAP inside it",
	"internal/rar":        "authorization_details",
	"internal/saml":       "an AuthnRequest or a response's XML",
	"internal/scim":       "a SCIM list filter and PATCH path",
	"internal/sdjwt":      "a wallet's disclosures",
	"internal/tokens":     "a bearer token presented to a resource",
	"internal/uma":        "a resource registration, permission request, scope and claim token",
}

// Every fuzz target in the engine is built for OSS-Fuzz by engine/fuzz/oss-fuzz-build.sh,
// and every line there names a target that exists: a target missing from the script is
// never run continuously, and a line naming a removed one breaks the build. Every
// package that reads a stranger's input keeps a target. Derived both ways from the
// source, so a new target or a renamed one cannot be forgotten.
func TestEveryFuzzTargetIsBuiltForOSSFuzz(t *testing.T) {
	engine := filepath.Join(repoRoot(t), "engine")
	inSource := map[string]bool{}
	byPackage := map[string]int{}
	err := filepath.WalkDir(engine, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pkg, _ := filepath.Rel(engine, filepath.Dir(path))
		for _, m := range fuzzFunc.FindAllStringSubmatch(string(raw), -1) {
			inSource[pkg+" "+m[1]] = true
			byPackage[pkg]++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(engine, "fuzz", "oss-fuzz-build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	inScript := map[string]bool{}
	for _, m := range fuzzBuildCmd.FindAllStringSubmatch(string(script), -1) {
		inScript[m[1]+" "+m[2]] = true
	}
	var missing, stale []string
	for k := range inSource {
		if !inScript[k] {
			missing = append(missing, k)
		}
	}
	for k := range inScript {
		if !inSource[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	for _, k := range missing {
		t.Errorf("fuzz target %s is not built by engine/fuzz/oss-fuzz-build.sh, so nothing runs it continuously", k)
	}
	for _, k := range stale {
		t.Errorf("engine/fuzz/oss-fuzz-build.sh builds %s, which does not exist", k)
	}
	for pkg, what := range wireParsers {
		if byPackage[pkg] == 0 {
			t.Errorf("%s reads %s and has no fuzz target", pkg, what)
		}
	}
	if len(inSource) < 20 {
		t.Fatalf("only %d fuzz targets found, so the pattern has stopped matching them", len(inSource))
	}
}
