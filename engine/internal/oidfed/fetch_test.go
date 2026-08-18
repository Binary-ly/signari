package oidfed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// serveStatement stands in for a federation entity's HTTP surface.
func serveStatement(t *testing.T, handler func(r *http.Request) (string, int)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, code := handler(r)
		w.Header().Set("Content-Type", MediaType)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A superior handing back somebody else's configuration reroutes the whole
// chain: we would go on to read ITS authority_hints and walk ITS superiors.
func TestAConfigurationMustBeAboutTheEntityWeAsked(t *testing.T) {
	other := newEntity(t, "https://elsewhere.example", "k1")
	st := other.sign(t, other.id, other.jwks(t), time.Now().Add(time.Hour))

	srv := serveStatement(t, func(*http.Request) (string, int) { return st.Raw, 200 })
	f := &Fetcher{HTTP: srv.Client(), AllowLoopbackForTesting: true}

	// Ask for the server's own address, receive a document about elsewhere.
	_, err := f.EntityConfigurationOf(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("a configuration for a different entity was accepted; the chain " +
			"would then be walked from somebody else's authority_hints")
	}
}

// §8.1: we ask about a specific subordinate. A statement about a different one
// is how a chain gets rerouted to an entity nobody enquired about.
func TestASubordinateStatementMustBeAboutTheSubjectWeAsked(t *testing.T) {
	sup := newEntity(t, "https://sup.example", "s1")
	other := newEntity(t, "https://elsewhere.example", "o1")
	st := sup.sign(t, other.id, other.jwks(t), time.Now().Add(time.Hour))

	var gotSub string
	srv := serveStatement(t, func(r *http.Request) (string, int) {
		gotSub = r.URL.Query().Get("sub")
		return st.Raw, 200
	})
	f := &Fetcher{HTTP: srv.Client(), AllowLoopbackForTesting: true}

	_, err := f.SubordinateStatement(context.Background(),
		srv.URL+"/fetch", "https://leaf.example")
	if err == nil {
		t.Fatal("a statement about a different subject was accepted")
	}
	if gotSub != "https://leaf.example" {
		t.Errorf("the sub parameter sent was %q", gotSub)
	}
}

// The fetch endpoint must be https, and the sub parameter must be a valid Entity
// Identifier — both are attacker-influenced, arriving from a fetched document.
func TestTheFetchEndpointAndSubjectAreValidated(t *testing.T) {
	f := &Fetcher{HTTP: http.DefaultClient}
	ctx := context.Background()

	if _, err := f.SubordinateStatement(ctx, "http://sup.example/fetch",
		"https://leaf.example"); err == nil {
		t.Error("a plaintext federation fetch endpoint was accepted")
	}
	if _, err := f.SubordinateStatement(ctx, "https://sup.example/fetch",
		"http://leaf.example"); err == nil {
		t.Error("a plaintext subject Entity Identifier was accepted")
	}
}

// A body limit applied after buffering is not a limit.
func TestAnOversizedStatementIsRefused(t *testing.T) {
	huge := strings.Repeat("a", MaxStatementBytes+100)
	srv := serveStatement(t, func(*http.Request) (string, int) { return huge, 200 })
	f := &Fetcher{HTTP: srv.Client(), AllowLoopbackForTesting: true}

	_, err := f.EntityConfigurationOf(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("an oversized statement was accepted")
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// §3.1.2 forbids the empty array. Reading it as "no superiors" would silently
// accept a document saying something the specification does not permit.
func TestAnEmptyAuthorityHintsArrayIsRefused(t *testing.T) {
	e := newEntity(t, "https://leaf.example", "k1")

	// Hand-built so the empty array actually reaches the parser.
	claims := map[string]any{
		"iss": e.id, "sub": e.id,
		"iat":             time.Now().Add(-time.Minute).Unix(),
		"exp":             time.Now().Add(time.Hour).Unix(),
		"jwks":            json.RawMessage(e.jwks(t)),
		"authority_hints": []string{},
	}
	raw := signClaims(t, e, claims)
	st, err := ParseStatement(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorityHintsOf(st, false); err == nil {
		t.Fatal("an empty authority_hints array was read as `no superiors`")
	}

	// A populated one is read back intact.
	claims["authority_hints"] = []string{"https://anchor.example"}
	st2, err := ParseStatement(signClaims(t, e, claims))
	if err != nil {
		t.Fatal(err)
	}
	hints, err := AuthorityHintsOf(st2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 || hints[0] != "https://anchor.example" {
		t.Errorf("hints = %v", hints)
	}

	// And a plaintext hint is refused, because a hint is an Entity Identifier.
	claims["authority_hints"] = []string{"http://anchor.example"}
	st3, _ := ParseStatement(signClaims(t, e, claims))
	if _, err := AuthorityHintsOf(st3, false); err == nil {
		t.Error("a plaintext authority hint was accepted")
	}
}

// ParseStatement must not be mistaken for verification.
func TestParseStatementVerifiesNothing(t *testing.T) {
	e := newEntity(t, "https://leaf.example", "k1")
	st := e.sign(t, e.id, e.jwks(t), time.Now().Add(time.Hour))

	// Corrupt the signature. Parsing still succeeds, by design — verification is
	// ValidateChain's job, against keys not known until the chain is assembled.
	bad := st.Raw[:len(st.Raw)-4] + "AAAA"
	if _, err := ParseStatement(bad); err != nil {
		t.Fatalf("parsing a statement with a bad signature failed: %v\n"+
			"ParseStatement is deliberately not a verifier; if it starts "+
			"rejecting here, callers may start trusting its output", err)
	}
	// But that statement must not validate.
	if err := verifyWith(mustParse(t, bad), e.jwks(t)); err == nil {
		t.Fatal("a corrupted signature verified")
	}
}

func mustParse(t *testing.T, raw string) Statement {
	t.Helper()
	st, err := ParseStatement(raw)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The SSRF guards must be on by default.
//
// Every URL a chain resolver visits after the first comes out of a document the
// previous entity controls, so `authority_hints` is a list of addresses an
// attacker writes. A Fetcher constructed with no options must refuse loopback
// and link-local, or the resolver is a proxy into our own network.
func TestTheDefaultFetcherRefusesPrivateAddresses(t *testing.T) {
	f := &Fetcher{} // no options: the shape a caller gets by default
	ctx := context.Background()

	for _, target := range []string{
		"https://127.0.0.1",
		"https://169.254.169.254", // cloud instance metadata
		"https://10.0.0.1",
		"https://[::1]",
	} {
		if _, err := f.EntityConfigurationOf(ctx, target); err == nil {
			t.Errorf("the default fetcher accepted %s", target)
		}
	}
}

// And the escape hatch must be the only way to reach them, so that reading the
// code makes the exposure obvious at the call site.
func TestTheLoopbackEscapeIsNamedForWhatItDoes(t *testing.T) {
	src := readSourceFile(t, "fetch.go")
	if !strings.Contains(src, "AllowLoopbackForTesting") {
		t.Fatal("the escape hatch has been renamed; if it is now something " +
			"shorter, it can be set in a config file by somebody solving a " +
			"different problem")
	}
	// Comment lines skipped: fetch.go names the tempting alternatives in prose,
	// to explain why it did not use them. A check that cannot tell an
	// explanation from a declaration forces the explanation to be deleted --
	// which is the second time this review has written that same test wrong.
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, tempting := range []string{"Insecure ", "SkipVerify", "DisableSSRF"} {
			if strings.Contains(line, tempting) {
				t.Errorf("fetch.go declares %q:\n\t%s", tempting, strings.TrimSpace(line))
			}
		}
	}
}

func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
