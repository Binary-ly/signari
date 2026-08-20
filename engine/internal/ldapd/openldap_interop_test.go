package ldapd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Interop against the OpenLDAP client tools, not against our own encoder.
//
// Every other test in this package builds a request with the same BER code that
// parses it. That proves the two halves agree and proves nothing about whether a
// real client can talk to this server — a self-consistent misreading of the
// protocol passes every one of them.
//
// `ldapsearch` and `ldapwhoami` ship with OpenLDAP and are what actual
// deployments use. Running them against this server is external validation of
// the kind point 5 asks for, and unlike a hosted conformance suite it needs no
// public deployment.
//
// Skipped when the tools are absent, and NOT silently: an interop test that
// quietly passes because the client is missing is worse than no test.
func TestOpenLDAPClientInterop(t *testing.T) {
	if _, err := exec.LookPath("ldapwhoami"); err != nil {
		t.Skip("ldapwhoami not installed; install OpenLDAP client tools to run " +
			"the third-party interop checks")
	}

	addr := startInteropServer(t)
	uri := "ldap://" + addr

	run := func(t *testing.T, args ...string) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running %v: %v", args, err)
		}
		return string(out), code
	}

	const (
		aliceDN = "uid=alice,dc=example,dc=test"
		alicePW = "correct-horse-battery-staple"
	)

	t.Run("a correct simple bind succeeds", func(t *testing.T) {
		out, code := run(t, "ldapwhoami", "-x", "-H", uri, "-D", aliceDN, "-w", alicePW)
		if code != 0 {
			t.Fatalf("ldapwhoami exited %d: %s", code, out)
		}
		// RFC 4513: the authorization identity of a simple bind is the bound DN.
		if !strings.Contains(out, "alice") {
			t.Errorf("ldapwhoami did not report the bound identity: %q", out)
		}
	})

	t.Run("a wrong password is refused", func(t *testing.T) {
		out, code := run(t, "ldapwhoami", "-x", "-H", uri, "-D", aliceDN, "-w", "wrong")
		if code == 0 {
			t.Fatalf("ldapwhoami accepted a wrong password: %s", out)
		}
		if !strings.Contains(out, "Invalid credentials") {
			t.Errorf("expected the client to report invalid credentials, got: %q", out)
		}
	})

	// RFC 4513 §5.1.2, checked by a real client rather than by our own encoder.
	//
	// `ldapwhoami -x -D <dn>` with no -w sends a bind with a DN and an empty
	// password — the unauthenticated bind. A client that reads our
	// unwillingToPerform(53) correctly says so; one that got invalidCredentials
	// would say something else entirely, which is the difference this test can
	// see and a unit test on our own bytes cannot.
	t.Run("an unauthenticated bind is refused as unwillingToPerform", func(t *testing.T) {
		out, code := run(t, "ldapwhoami", "-x", "-H", uri, "-D", aliceDN, "-w", "")
		if code == 0 {
			t.Fatalf("a bind with an empty password succeeded: %s", out)
		}
		if !strings.Contains(out, "Server is unwilling to perform") {
			t.Errorf("the client did not report unwillingToPerform, so our result "+
				"code is not being read the way RFC 4513 §5.1.2 intends: %q", out)
		}
	})

	t.Run("a bound search returns entries a real client can parse", func(t *testing.T) {
		out, code := run(t, "ldapsearch", "-x", "-LLL", "-H", uri,
			"-D", aliceDN, "-w", alicePW,
			"-b", "dc=example,dc=test", "(uid=alice)")
		if code != 0 {
			t.Fatalf("ldapsearch exited %d: %s", code, out)
		}
		// If the client could not parse our response it would print a decoding
		// error rather than an entry.
		for _, want := range []string{"dn: uid=alice", "alice@example.test"} {
			if !strings.Contains(out, want) {
				t.Errorf("the search result does not contain %q:\n%s", want, out)
			}
		}
		// memberOf is what applications gate on, and a directory that cannot
		// publish it gives everybody the same access.
		if !strings.Contains(out, "engineering") {
			t.Errorf("group membership was not published:\n%s", out)
		}
		// No password material, ever.
		low := strings.ToLower(out)
		if strings.Contains(low, "userpassword") {
			t.Errorf("a password attribute was returned to a client:\n%s", out)
		}
	})

	t.Run("anonymous search is refused", func(t *testing.T) {
		out, code := run(t, "ldapsearch", "-x", "-LLL", "-H", uri,
			"-b", "dc=example,dc=test", "(uid=alice)")
		if code == 0 && strings.Contains(out, "dn: uid=alice") {
			t.Errorf("an unauthenticated client read the directory:\n%s", out)
		}
	})
}

func startInteropServer(t *testing.T) string {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := New(Config{BaseDN: "dc=example,dc=test", UserAttr: "uid"}, interopAuth{}, log)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return ln.Addr().String()
}

type interopAuth struct{}

var errInteropDenied = errors.New("invalid credentials")

func (interopAuth) Authenticate(_ context.Context, u, p string) (*Identity, error) {
	if u == "alice" && p == "correct-horse-battery-staple" {
		return interopAlice(), nil
	}
	return nil, errInteropDenied
}

func (interopAuth) Lookup(_ context.Context, u string) (*Identity, error) {
	if u == "alice" {
		return interopAlice(), nil
	}
	return nil, errInteropDenied
}

func (interopAuth) List(_ context.Context, _ int) ([]*Identity, error) {
	return []*Identity{interopAlice()}, nil
}

func interopAlice() *Identity {
	return &Identity{
		Username: "alice", Email: "alice@example.test",
		DisplayName: "Alice Example", Active: true,
		Groups: []string{"engineering", "oncall"},
	}
}
