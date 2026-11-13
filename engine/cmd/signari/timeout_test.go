package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// An entry naming a command that is not dispatched -- a typo, or a command
// since renamed -- leaves the real command under the configuration deadline,
// and nothing else would notice.
func TestEveryUnboundedCommandIsDispatched(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	dispatched := map[string]bool{}
	for _, m := range regexp.MustCompile(`case\s+"([a-z][a-z0-9 -]*)"`).FindAllStringSubmatch(string(src), -1) {
		dispatched[m[1]] = true
	}
	if len(dispatched) < 100 {
		t.Fatalf("only %d case labels read from main.go; reading it wrong", len(dispatched))
	}
	for cmd, why := range unboundedCommands {
		if !dispatched[cmd] {
			t.Errorf("unboundedCommands names %q, which main.go does not dispatch", cmd)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("unboundedCommands[%q] gives no reason", cmd)
		}
	}
}

func TestTheTimeoutIsWhatWasAskedForOrTheCommandsOwn(t *testing.T) {
	for _, c := range []struct {
		cmd      string
		given    time.Duration
		wasGiven bool
		want     time.Duration
	}{
		{"client set-par", 0, false, defaultCommandTimeout},
		{"export audit", 0, false, 0},
		{"migrate up", 0, false, 0},
		{"proxy check", 0, false, 5 * time.Minute},
		// Waits for somebody to sign in for as long as the authorization lasts.
		{"scim authorize", 0, false, 11 * time.Minute},
		{"export audit", 30 * time.Second, true, 30 * time.Second},
		{"client set-par", 0, true, 0},
	} {
		if got := commandTimeout(c.cmd, c.given, c.wasGiven); got != c.want {
			t.Errorf("commandTimeout(%q, %s, %v) = %s, want %s", c.cmd, c.given, c.wasGiven, got, c.want)
		}
	}
}

// growTheTrail writes to the audit trail until it holds about size bytes, so a
// test of a long export does not depend on what other runs left there. Through
// audit.Write, as any test's records must be.
func growTheTrail(t *testing.T, dsn string, size int) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var held int
	if err := conn.QueryRow(ctx, `SELECT coalesce(sum(length(detail::text)), 0)::int FROM core.audit_events`).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if held >= size {
		return
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	padding := strings.Repeat("x", 4096)
	for ; held < size; held += len(padding) {
		if err := audit.Write(ctx, tx, audit.Event{Type: "admin.cli_command",
			Detail: map[string]any{"padding": padding}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// An audit export runs for as long as the trail takes to verify and write.
// The deadline is shortened to 300 ms and the export written into a pipe
// whose reader waits a second and a half before draining it, standing in for
// a trail too large to export in a minute. Every command used to share the
// one deadline, and an export of a large trail was cancelled partway through.
func TestAnAuditExportOutlivesTheConfigurationDeadline(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	saved := defaultCommandTimeout
	defaultCommandTimeout = 300 * time.Millisecond
	t.Cleanup(func() { defaultCommandTimeout = saved })
	growTheTrail(t, dsn, 2<<20)

	export := func(extra ...string) (int64, error) {
		t.Helper()
		pipe := filepath.Join(t.TempDir(), "export.csv")
		if err := syscall.Mkfifo(pipe, 0o600); err != nil {
			t.Fatal(err)
		}
		read := make(chan int64, 1)
		go func() {
			f, err := os.Open(pipe)
			if err != nil {
				read <- -1
				return
			}
			defer func() { _ = f.Close() }()
			time.Sleep(1500 * time.Millisecond)
			n, _ := io.Copy(io.Discard, f)
			read <- n
		}()
		err := run(append([]string{"export", "audit", "-dsn", dsn, "-out", pipe}, extra...))
		// A deadline that passes before the export opens its output leaves the
		// reader waiting in open(2) for a writer that will never come, and this
		// test waiting on the reader until the suite's own timeout. So be that
		// writer, for as long as the reader has not answered.
		for {
			select {
			case n := <-read:
				return n, err
			case <-time.After(50 * time.Millisecond):
				if w, oerr := os.OpenFile(pipe, os.O_WRONLY|syscall.O_NONBLOCK, 0); oerr == nil {
					_ = w.Close()
				}
			}
		}
	}

	n, err := export()
	if errors.Is(err, context.DeadlineExceeded) || (err != nil && strings.Contains(err.Error(), "deadline")) {
		t.Fatalf("the export was cancelled by a deadline after writing %d bytes: %v", n, err)
	}
	if err != nil && !strings.Contains(err.Error(), "did not verify") {
		// A chain that does not verify is this database's business; anything
		// else stopped the export.
		t.Fatalf("the export failed after writing %d bytes: %v", n, err)
	}
	if n < 1<<20 {
		t.Fatalf("only %d bytes were exported; the test needs a trail larger than the pipe to mean anything", n)
	}

	// And -timeout still bounds it when it is given. Whatever the export was
	// doing when the deadline passed reports it, in its own words: a query
	// cancelled, or the connection closed under it.
	if _, err := export("-timeout", "300ms"); err == nil {
		t.Fatal("an export given -timeout 300ms and held for 1.5s was not cancelled")
	}
}
