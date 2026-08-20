package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
)

// Cross-language verification against `jose`, run rather than assumed.
//
// interop/verify.mjs has existed for a while and is the right idea — `jose` is
// OpenID-certified, written by the author of node-oidc-provider, and shares no
// code, no language and no author with go-jose. What it needed was a live issuer,
// which meant a deployment, which meant it was run by hand and then not again.
//
// This runs it in the suite. The listener is opened first so the issuer can be
// the address it will actually be served on — discovery's first check is that
// the document's `issuer` equals the URL it was fetched from, and a fixture
// issuer of "https://token-test.example" fails that immediately.
//
// Skipped loudly when node or the module is missing. An interop test that passes
// because the second implementation is absent is worse than no test.
func TestJoseCrossLanguageVerification(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; this is the independent check and is being skipped")
	}
	root := repoRootFromHere(t)
	script := filepath.Join(root, "interop", "verify.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("interop/verify.mjs not found at %s", script)
	}
	if _, err := os.Stat(filepath.Join(root, "interop", "node_modules", "jose")); err != nil {
		t.Skip("interop/node_modules/jose not installed; run npm install in interop/")
	}

	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// The listener first, so the issuer can name the address it is served on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()

	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(oidc.Config{Issuer: issuer, Keys: set, AllowInsecureIssuer: true},
		pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Routes(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })

	// Tokens shaped exactly as the flows emit them.
	now := time.Now()
	signer := tokens.NewSigner(active)
	idToken, err := signer.SignJSON(tokens.IDTokenClaims{
		Issuer: issuer, Subject: "user-interop", Audience: "client-interop",
		Expiry: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(),
		AuthTime: now.Unix(), SessionID: "sid-interop",
		AuthorizedParty: "client-interop",
	}, tokens.TypIDToken)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := signer.SignJSON(tokens.AccessTokenClaims{
		Issuer: issuer, Subject: "user-interop", Audience: []string{"client-interop"},
		Expiry: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(),
		JTI: "jti-interop", ClientID: "client-interop", Scope: "openid",
	}, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "node", script, issuer, idToken, accessToken)
	cmd.Dir = filepath.Join(root, "interop")
	out, err := cmd.CombinedOutput()
	t.Logf("jose verification against %s:\n%s", issuer, out)

	var ee *exec.ExitError
	if errors.As(err, &ee) {
		t.Errorf("verify.mjs exited %d — an independent implementation disagrees "+
			"with ours about our own tokens or discovery document", ee.ExitCode())
	} else if err != nil {
		t.Fatalf("running verify.mjs: %v", err)
	}
	if strings.Contains(string(out), "FAIL") {
		t.Errorf("verify.mjs reported failures")
	}
}

func repoRootFromHere(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "interop")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("could not locate the repository root from the test directory")
	return ""
}
