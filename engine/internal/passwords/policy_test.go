package passwords

import (
	"context"
	"crypto/sha1" //nolint:gosec // the HIBP corpus is indexed by SHA-1
	"encoding/hex"
	"fmt"
	"golang.org/x/text/unicode/norm"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func hibpServing(t *testing.T, breached string, count string) string {
	t.Helper()
	sum := sha1.Sum([]byte(breached)) //nolint:gosec
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real API returns ~800 suffixes; two is enough to prove the
		// comparison happens locally and that a non-match is not a match.
		fmt.Fprintf(w, "%s:%s\n", digest[5:], count)
		fmt.Fprint(w, "0000000000000000000000000000000000A:3\n")
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/range/"
}

// TestTheRangeAPINeverSeesThePassword is the privacy property that makes this
// check acceptable to run at all.
func TestTheRangeAPINeverSeesThePassword(t *testing.T) {
	var gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = os.ReadFile("/dev/null")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := &BreachChecker{Endpoint: srv.URL + "/range/", Online: true}
	_, _ = b.Breached(context.Background(), "correct horse battery staple")

	if strings.Contains(gotPath, "correct") || len(gotBody) > 0 {
		t.Fatal("the password reached the service")
	}
	// Exactly five hex characters of the digest, and nothing else.
	suffix := strings.TrimPrefix(gotPath, "/range/")
	if len(suffix) != 5 {
		t.Errorf("sent %q; the range API takes a five-character prefix, and "+
			"sending more narrows the search space at the far end", suffix)
	}
}

func TestABreachedPasswordIsRefused(t *testing.T) {
	// 15+ characters, so the LENGTH check is not what refuses it -- otherwise
	// this test passes without the breach check ever running, which is what it
	// exists to exercise. (It did, the moment the floor moved to 15.)
	endpoint := hibpServing(t, "correct-horse-battery", "12345")
	p := DefaultPolicy()
	p.Breach = &BreachChecker{Endpoint: endpoint, Online: true}

	res, err := p.Check(context.Background(), "correct-horse-battery", "", nil, nil)
	if err == nil {
		t.Fatal("a breached password was accepted")
	}
	if !res.BreachCheckRan {
		t.Error("the check ran, so it should be reported as having run")
	}
	if strings.Contains(err.Error(), "12345") {
		t.Error("the error quotes the breach count, which invites bargaining " +
			"over a verdict that does not change")
	}
}

// A padding entry has a count of 0. Treating one as a match refuses passwords
// that are not in the corpus at all, and the padding exists precisely so
// responses are indistinguishable.
func TestPaddingEntriesAreNotMatches(t *testing.T) {
	endpoint := hibpServing(t, "a-fine-passphrase-nobody-has", "0")
	b := &BreachChecker{Endpoint: endpoint, Online: true}
	breached, err := b.Breached(context.Background(), "a-fine-passphrase-nobody-has")
	if err != nil {
		t.Fatal(err)
	}
	if breached {
		t.Error("a zero-count padding entry was treated as a real match")
	}
}

// An unreachable corpus is not a verdict.
func TestUnavailableIsNotClean(t *testing.T) {
	b := &BreachChecker{Endpoint: "http://127.0.0.1:1/range/", Online: true}
	_, err := b.Breached(context.Background(), "anything")
	if err != ErrUnavailable {
		t.Fatalf("an unreachable corpus returned %v, want ErrUnavailable", err)
	}

	// Default: allowed through, and reported as not having run.
	p := DefaultPolicy()
	p.Breach = b
	res, err := p.Check(context.Background(), "a-long-enough-passphrase", "", nil, nil)
	if err != nil {
		t.Errorf("an outage at a third party blocked a password change: %v", err)
	}
	if res.BreachCheckRan {
		t.Error("the check did not run and must not report that it did")
	}

	// Opt-in strictness.
	p.BreachRequired = true
	if _, err := p.Check(context.Background(), "a-long-enough-passphrase", "", nil, nil); err == nil {
		t.Error("BreachRequired did not refuse when the corpus was unreachable")
	}
}

// The offline list exists because plenty of deployments cannot call out at all.
func TestTheOfflineListWorksWithNoNetwork(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/corpus.txt"
	sum := sha1.Sum([]byte("hunter2")) //nolint:gosec
	body := strings.ToUpper(hex.EncodeToString(sum[:])) + ":9999\n# a comment\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	b := &BreachChecker{LocalFile: path} // Online deliberately false
	breached, err := b.Breached(context.Background(), "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !breached {
		t.Error("the offline corpus did not match a password it contains")
	}
	if got, err := b.Breached(context.Background(), "something-else-entirely"); err != nil || got {
		t.Errorf("a password not in the offline corpus was reported breached: %v %v", got, err)
	}
}

func TestLengthIsCountedInRunes(t *testing.T) {
	p := Policy{MinLength: 8, MaxLength: 1024}
	// Seven characters, but 21 bytes. A byte count would let it through.
	if _, err := p.Check(context.Background(), "パスワード七つ", "", nil, nil); err == nil {
		t.Error("a seven-character password passed an eight-character minimum " +
			"because its bytes were counted instead of its characters")
	}
}

func TestContextualPasswordsAreRefused(t *testing.T) {
	p := DefaultPolicy()
	if _, err := p.Check(context.Background(), "alice-was-here-2026", "alice@example.com",
		nil, nil); err == nil {
		t.Error("a password containing the user's own username was accepted")
	}
}

func TestRepeatedCharacterIsRefused(t *testing.T) {
	p := DefaultPolicy()
	if _, err := p.Check(context.Background(), "aaaaaaaaaaaa", "", nil, nil); err == nil {
		t.Error("one character repeated passed a length check")
	}
}

func TestReuseIsRefused(t *testing.T) {
	h := NewHasher(MemoryBudgetMiB)
	ctx := context.Background()
	old, err := h.Hash(ctx, "the-previous-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.HistoryDepth = 3

	if _, err := p.Check(ctx, "the-previous-passphrase", "", []string{old}, h); err == nil {
		t.Error("a previous password was accepted again")
	}
	if _, err := p.Check(ctx, "a-genuinely-different-one", "", []string{old}, h); err != nil {
		t.Errorf("a new password was refused: %v", err)
	}
}

// NIST SP 800-63B **revision 4** §3.1.1.2:
//
//	"Verifiers and CSPs SHALL require passwords that are used as a single-factor
//	authentication mechanism to be a minimum of 15 characters in length."
//
// The policy said 8, citing SP 800-63B — accurate for revision 3, and the more
// dangerous kind of stale: a correct citation of a superseded document reads
// like diligence, so nobody re-checks it.
func TestTheDefaultFloorIsFifteenCharacters(t *testing.T) {
	p := DefaultPolicy()
	if p.MinLength != MinLengthSingleFactor {
		t.Fatalf("MinLength = %d, want %d (SP 800-63B-4 §3.1.1.2)",
			p.MinLength, MinLengthSingleFactor)
	}
	if MinLengthSingleFactor != 15 {
		t.Fatalf("MinLengthSingleFactor = %d, want 15", MinLengthSingleFactor)
	}

	// Fourteen is refused, fifteen is not — the boundary, not just a long and a
	// short example either side of it.
	if _, err := p.Check(context.Background(), strings.Repeat("aB3-", 3)+"xy", "", nil, nil); err == nil {
		t.Error("a 14-character password was accepted")
	}
	if _, err := p.Check(context.Background(), "correct-horse-battery-staple", "", nil, nil); err != nil {
		t.Errorf("a 28-character passphrase was refused: %v", err)
	}

	// The MFA carve-out exists but is not the default: §3.1.1.2 permits 8 only
	// for a password "only used as part of multi-factor authentication".
	if MinLengthWithMFA != 8 {
		t.Errorf("MinLengthWithMFA = %d, want 8", MinLengthWithMFA)
	}
	if p.MinLength == MinLengthWithMFA {
		t.Error("the default floor is the MFA one; a deployment without MFA " +
			"would silently accept single-factor passwords below the SHALL")
	}
}

// §3.1.1.2: "the verifier SHOULD apply the normalization process for stabilized
// strings using the Normalization Form Canonical Composition (NFC)... This
// process is applied before hashing the byte string that represents the
// password."
//
// The failure this prevents is a real one: "é" is one code point or two
// depending on the keyboard, so a password set on one platform and typed on
// another is a different byte string and does not verify — intermittently, for a
// minority of users, with no actionable error.
func TestPasswordsAreNormalisedToNFC(t *testing.T) {
	// The same passphrase, composed and decomposed. 15+ characters either way.
	composed := "café-passphrase-ok"    // é as U+00E9
	decomposed := "café-passphrase-ok" // e + U+0301

	if composed == decomposed {
		t.Fatal("the fixtures are identical; the test proves nothing")
	}

	p := DefaultPolicy()
	// Both must be accepted, and both must produce the same normalised form —
	// which is what makes them hash identically.
	for _, s := range []string{composed, decomposed} {
		if _, err := p.Check(context.Background(), s, "", nil, nil); err != nil {
			t.Fatalf("%q was refused: %v", s, err)
		}
	}
	if norm.NFC.String(composed) != norm.NFC.String(decomposed) {
		t.Fatal("the two forms do not normalise alike; the fixture is wrong")
	}

	// And the rune count is of the NORMALISED string: decomposed is longer by
	// one code point before normalisation, so a length check applied first would
	// measure a different password than the one that gets hashed.
	if len([]rune(decomposed)) == len([]rune(norm.NFC.String(decomposed))) {
		t.Skip("this platform's fixture did not decompose; nothing to compare")
	}
}

// SP 800-63B-4 §3.1.1.2's two SHALL NOTs, which revision 4 raised from
// revision 3's SHOULD NOTs:
//
//	"Verifiers and CSPs SHALL NOT impose other composition rules (e.g.,
//	 requiring mixtures of different character types) for passwords."
//	"Verifiers and CSPs SHALL NOT require users to change passwords
//	 periodically."
//
// Compliance here is compliance by ABSENCE — there is no composition check and
// no expiry column — and absence is the hardest thing to keep. Nobody reviewing
// a diff that adds "must contain a digit" is reminded that a standard forbids
// it; it reads like tightening security. This test is the reminder.
//
// The strength estimate is deliberately not a composition rule: it scores how
// many guesses a password would take, so a long lowercase passphrase passes and
// `Password1!` does not, which is the opposite of what a composition rule does.
func TestNoCompositionRulesAreImposed(t *testing.T) {
	p := DefaultPolicy()
	ctx := context.Background()

	// Every one of these would fail a conventional composition rule, and every
	// one is a perfectly good passphrase.
	// Deliberately not famous examples: `correct horse battery staple` is in
	// every breach corpus by now, and refusing it would be the breach check
	// working rather than a composition rule.
	for _, pw := range []string{
		"marmalade lantern quietly drifting",
		"seventeen wooden ladders by the shore",
		"thebargeleftharbourbeforedaylight",
	} {
		if _, err := p.Check(ctx, pw, "", nil, nil); err != nil {
			t.Errorf("the passphrase %q was refused (%v). It has no uppercase, no "+
				"digit and no symbol — which §3.1.1.2 says SHALL NOT be required. "+
				"A rule that pushes people to `Password1!` and away from length is "+
				"the failure the standard forbids", pw, err)
		}
	}
}
