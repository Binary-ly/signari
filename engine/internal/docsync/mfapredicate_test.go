package docsync

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Whether a session is multi-factor is decided in one place.
//
// # The failure this guards against
//
// There were four answers. The AuthZEN PDP counted `user` or `pin` alone as
// multi-factor; the access policy and the SAML authentication context counted
// any single possession factor; the session list called every password session
// "more than one factor" because it tested acr != "0". So a passkey used
// without user verification -- one factor -- satisfied an MFA requirement in
// three places and failed it in the fourth, and a relying party, a service
// provider and a policy file each got a different story about the same login.
//
// oauth.IsMultiFactor (over oauth.ACRFromAMR) is the one predicate. This fails
// when any other file classifies authentication methods into "multi-factor"
// for itself: a switch case over amr values, or a hand-written comparison of
// ACRFromAMR's result.
func TestThereIsOneMultiFactorPredicate(t *testing.T) {
	engine := filepath.Join(repoRoot(t), "engine")

	// A `case` that names authentication methods is a classifier: one naming an
	// oauth.AMR constant, or two or more of the method names as literals (a
	// single literal such as `case "sms":` is as likely a channel as a method).
	caseLine := regexp.MustCompile(`^\s*case\s`)
	amrConst := regexp.MustCompile(`oauth\.AMR(OTP|HardwareKey|SMS|MFA|PIN|UserPresence)\b`)
	amrLiteral := regexp.MustCompile(`"(otp|hwk|swk|sms|mfa|pin|user|face|fpt)"`)
	caseOverAMR := func(code string) bool {
		if !caseLine.MatchString(code) {
			return false
		}
		return amrConst.MatchString(code) || len(amrLiteral.FindAllString(code, -1)) >= 2
	}
	// IsMultiFactor exists so nobody writes this comparison again.
	handRolled := regexp.MustCompile(`ACRFromAMR\([^)]*\)\s*==`)

	var found []string
	scanned := 0
	err := filepath.WalkDir(engine, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(engine, path)
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") ||
			rel == "internal/oauth/acr.go" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if caseOverAMR(code) || handRolled.MatchString(code) {
				found = append(found, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d Go files; the walk is not finding the engine", scanned)
	}
	for _, f := range found {
		t.Errorf("%s\n\tclassifies authentication methods for itself. Use oauth.IsMultiFactor, "+
			"so every MFA decision agrees.", f)
	}
}
