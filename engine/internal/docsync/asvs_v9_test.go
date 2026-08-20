package docsync

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ASVS 5.0.0 V9.1.2, as a standing check rather than a one-time review.
//
//	"Verify that only algorithms on an allowlist can be used to create and verify
//	self-contained tokens, for a given context. The allowlist must include the
//	permitted algorithms, ideally only either symmetric or asymmetric algorithms,
//	and must not include the 'None' algorithm. If both symmetric and asymmetric
//	must be supported, additional controls will be needed to prevent key
//	confusion."
//
// This engine parses signed tokens in eight places — access tokens, ID tokens,
// DPoP proofs, SSF events, federation trust chains, upstream OIDC, Apple client
// secrets, private_key_jwt, ABCA attestations. Each passes its own allowlist to
// jose.ParseSigned, which is the right shape: the library makes the list
// mandatory, so it cannot be forgotten.
//
// What it cannot do is stop a future edit adding jose.HS256 "so the test client
// works" in one of the eight. A reviewer checking that file sees a plausible
// list; nobody sees all eight at once. This test does.
//
// Asymmetric-only, deliberately, and that is stronger than the requirement. With
// no symmetric algorithm anywhere, the key-confusion attack the second half of
// V9.1.2 asks for controls against cannot be constructed: there is no context in
// which a public key could be presented as an HMAC secret, because no verifier
// will accept an HMAC at all.
func TestNoTokenVerifierAcceptsNoneOrHMAC(t *testing.T) {
	root := repoRoot(t)

	// jose.None and the HMAC family. `none` is the classic algorithm-confusion
	// bypass; HS* in a codebase that otherwise uses asymmetric keys is how a
	// public key becomes a verification secret.
	banned := regexp.MustCompile(`jose\.(None|HS256|HS384|HS512)\b`)
	parseCall := regexp.MustCompile(`(jose|jwt)\.ParseSigned\(`)

	var offenders []string
	var sites int
	err := filepath.Walk(filepath.Join(root, "engine"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		if strings.HasSuffix(p, "_test.go") {
			// A test may legitimately construct a `none` token to prove it is
			// refused — which several do.
			return nil
		}
		src := readSource(t, p)
		if parseCall.MatchString(src) {
			sites++
		}
		for i, line := range strings.Split(src, "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if banned.MatchString(code) {
				rel, _ := filepath.Rel(root, p)
				offenders = append(offenders,
					fmt.Sprintf("%s:%d: %s", rel, i+1, strings.TrimSpace(line)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The walk must actually find the verifiers, or this passes by finding
	// nothing — the failure mode that made a mutation harness report eight
	// uncovered guards earlier in this project's history.
	if sites < 5 {
		t.Fatalf("only %d ParseSigned sites found; the walk is wrong and this test "+
			"would pass vacuously", sites)
	}
	if len(offenders) > 0 {
		t.Errorf("%d token verifier(s) admit 'none' or an HMAC algorithm:\n  %s\n\n"+
			"ASVS V9.1.2 forbids 'none' outright. This engine is asymmetric-only "+
			"everywhere, which is what makes the key-confusion controls V9.1.2 "+
			"asks for unnecessary — adding one symmetric algorithm removes that "+
			"property from the whole codebase, not just from this file.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
