package internal_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A parameter assigned to the blank identifier looks exactly like a check.
//
// This review has now found three instances of the same shape in this codebase:
//
//	dpop.proofClaims.Nonce   parsed from the proof, read by nothing
//	oauth.subjectClientID    threaded into ValidateExchange, `_ = subjectClientID`
//	oauth.ExchangeRequest    actor_token / actor_token_type, parsed, read by nothing
//	httpapi samlslo.go       `_ = userID` on a value used two lines below, which
//	                         told a reader it was deliberately unused when the
//	                         audit event depends on it
//
// It ran over one package when it was written and found a fourth instance the
// moment it was pointed at the rest of the tree.
//
// Each was a protocol parameter the code appeared to handle and did not. The
// compiler is happy with all three; a reader cannot tell them from working code
// without following every use; and in two of the three the specification put a
// MUST on doing something with the value.
//
// `_ = someParameter` is the version of this the compiler forces you to write
// down, so it is the version that can be caught. Discarding a value is
// occasionally right -- but it should be rare enough to argue for each time,
// which is what this test makes you do.
func TestNoParameterIsDiscardedSilently(t *testing.T) {
	// `_ = x` where x is a bare identifier. Not `_, err :=` (a genuine
	// multi-return discard) and not `_ = fmt.Sprintf(...)` (a call).
	discard := regexp.MustCompile(`^\s*_ = [a-z][A-Za-z0-9]*\s*$`)

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(filepath.Clean(path))
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(src), "\n") {
			if discard.MatchString(line) {
				t.Errorf("%s:%d discards a value:\n\t%s\n"+
					"If the protocol defines this parameter, either act on it or "+
					"refuse the request that carries it -- accepting and ignoring "+
					"it tells the caller something was applied when it was not. "+
					"If it genuinely has no meaning here, remove it rather than "+
					"leaving something shaped like a check.",
					path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
