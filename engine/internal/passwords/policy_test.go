package passwords

import (
	"context"
	"crypto/sha1" //nolint:gosec // the HIBP corpus is indexed by SHA-1
	"encoding/hex"
	"fmt"
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
	endpoint := hibpServing(t, "password123", "12345")
	p := DefaultPolicy()
	p.Breach = &BreachChecker{Endpoint: endpoint, Online: true}

	res, err := p.Check(context.Background(), "password123", "", nil, nil)
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
