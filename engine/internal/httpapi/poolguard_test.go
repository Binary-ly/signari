package httpapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Guard 0.08e: no function takes a second pool connection while it holds a
// transaction.
//
// A second connection taken while holding one is a deadlock under load: with as
// many concurrent requests as the pool has connections, each holds one and
// waits for another that only someone else's completion frees. It happened at
// token minting (the groups claim), in desktop login, and wherever a refusal
// was recorded with auditDetached before the transaction was released. It
// hung the suite for eight minutes once.
//
// A function handed a `pgx.Tx`, or one that opens one with `s.db.Begin`, may
// use s.db or auditDetached only where an explicit tx.Commit or tx.Rollback
// comes first on the same path, meaning earlier in a block still open at the
// use. That is brace counting, not control flow, and it sees direct uses only.
// A helper that takes a connection of its own is not seen, so pass the
// transaction to helpers rather than relying on this.
func TestNothingTakesASecondConnectionWhileHoldingATransaction(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?m)^func (?:\(s \*Server\) )?(\w+)\(([^)]*)\)`)
	begin := regexp.MustCompile(`tx, \w+ :?= s\.db\.Begin\(`)
	pool := regexp.MustCompile(`\bs\.db\b|\bs\.auditDetached\(`)
	release := regexp.MustCompile(`(?m)^[^\n]*\btx\.(?:Commit|Rollback)\(`)
	checked := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		// Comments blanked to spaces of the same length, so a comment that
		// explains why s.db is not used is not read as a use, and positions
		// and line numbers stay where they are.
		src := lineComment.ReplaceAllStringFunc(string(b), func(c string) string {
			return strings.Repeat(" ", len(c))
		})
		locs := fn.FindAllStringSubmatchIndex(src, -1)
		for i, loc := range locs {
			end := len(src)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			name, params := src[loc[2]:loc[3]], src[loc[4]:loc[5]]

			var starts []int
			if strings.Contains(params, "pgx.Tx") {
				starts = append(starts, loc[1])
			}
			for _, m := range begin.FindAllStringIndex(src[loc[1]:end], -1) {
				starts = append(starts, loc[1]+m[1])
			}
			for _, start := range starts {
				checked++
				// To the end of the block the transaction lives in: past that
				// it is out of scope, released by its deferred rollback.
				window := src[start:end]
				if close := blockEnd(window); close >= 0 {
					window = window[:close]
				}
				var releases []int
				for _, m := range release.FindAllStringIndex(window, -1) {
					if !strings.Contains(window[m[0]:m[1]], "defer") {
						releases = append(releases, m[1])
					}
				}
				for _, use := range pool.FindAllStringIndex(window, -1) {
					if releasedBefore(window, releases, use[0]) {
						continue
					}
					line := strings.Count(src[:start+use[0]], "\n") + 1
					t.Errorf("%s:%d: %s takes a second connection while holding a transaction; "+
						"pass the transaction, or commit or roll it back first", e.Name(), line, name)
				}
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d transaction-holding functions were found, so the pattern has "+
			"stopped matching", checked)
	}
}

// lineComment is a `//` comment: one at the start of a line or after
// whitespace, so the `//` inside "https://" is left alone.
var lineComment = regexp.MustCompile(`(?m)(?:^|[ \t])//[^\n]*`)

// blockEnd is where the block enclosing the start of s closes, or -1.
func blockEnd(s string) int {
	depth := 0
	for i, c := range s {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return i
			}
		}
	}
	return -1
}

// releasedBefore reports whether one of the releases comes before use in a
// block that is still open there, so that it runs on the path reaching use.
func releasedBefore(window string, releases []int, use int) bool {
	for _, r := range releases {
		if r > use {
			continue
		}
		depth, closed := 0, false
		for _, c := range window[r:use] {
			switch c {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					closed = true
				}
			}
			if closed {
				break
			}
		}
		if !closed {
			return true
		}
	}
	return false
}
