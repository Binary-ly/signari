package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No JWT this engine verifies may ever be verified with a symmetric algorithm.
//
// # Why this is a whole-tree test rather than a package one
//
// Every JWT this server verifies is signed by somebody we do NOT share a secret
// with: a client's private_key_jwt, a DPoP proof, an SSF transmitter's SET, an
// upstream provider's id_token, an RFC 7523 assertion, a federation entity
// statement. For all of them the verification key is a PUBLIC key.
//
// If a symmetric algorithm is ever accepted alongside those, the "secret" becomes
// the public key — which is public. Anyone can then forge a token. That is
// algorithm confusion (CWE-347), and it is not hypothetical: it has shipped in
// production identity software as recently as 2026, in a jwt-bearer grant, where
// it let anyone holding client credentials impersonate any federated user linked
// to the affected provider.
//
// Eleven separate call sites in this engine parse a JWS. Each passes its own
// algorithm list. A per-package test would check the list it knows about and say
// nothing about the twelfth site somebody adds next year — and the twelfth site
// is the one that will be wrong, because by then this reasoning is folklore.
//
// So the property is asserted across the source: `jose.HS*` must not appear in
// non-test code at all.
var symmetricAlg = regexp.MustCompile(`jose\.HS(256|384|512)\b`)

func TestNoSymmetricAlgorithmIsAcceptedAnywhere(t *testing.T) {
	root := repoRoot(t)
	engine := filepath.Join(root, "engine")

	var offenders []string
	err := filepath.Walk(engine, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Vendored code is somebody else's library making its own choices.
			if name := info.Name(); name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(body), "\n") {
			if symmetricAlg.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders,
					rel+":"+itoa(i+1)+"  "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("a symmetric signature algorithm appears in non-test code. Every JWT "+
			"this engine verifies is signed with a key we do not hold, so accepting "+
			"HMAC means accepting a signature anyone can forge with the public key:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
