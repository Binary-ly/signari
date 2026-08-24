package auditsink

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
)

// A webhook whose URL resolves into the private network is refused, the same SSRF
// guard every outbound path here applies -- the destination is operator-set but
// still a URL.
func TestWebhookSinkRefusesPrivateAddresses(t *testing.T) {
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:9000/ingest",
		"http://10.0.0.5/siem",
	} {
		if _, err := NewWebhookSink(u, ""); err == nil {
			t.Errorf("NewWebhookSink(%q) was allowed; a link-local or private "+
				"destination must be refused", u)
		}
	}
}

// The syslog line is octet-counted RFC 5424 with the event as a JSON payload.
func TestSyslogLineIsOctetCountedRFC5424(t *testing.T) {
	r := audit.StreamRecord{ID: 7, EventType: "password.changed", RetentionClass: "security"}
	line := syslogLine("host1", r)
	// "<len> <PRI>1 <time> host1 signari - password.changed - {json}"
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		t.Fatalf("no octet count prefix: %q", line)
	}
	if !strings.Contains(line, "<110>1 ") { // facility 13*8 + severity 6 = 110
		t.Errorf("wrong priority/version header: %q", line)
	}
	if !strings.Contains(line, "signari") || !strings.Contains(line, "password.changed") {
		t.Errorf("line missing app-name or event type: %q", line)
	}
	if !strings.Contains(line, `"event_type":"password.changed"`) {
		t.Errorf("JSON payload missing: %q", line)
	}
}

type fakeSink struct {
	mu   sync.Mutex
	got  []audit.StreamRecord
	fail bool
}

func (f *fakeSink) Describe() string { return "fake" }
func (f *fakeSink) Emit(_ context.Context, rs []audit.StreamRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return io.ErrUnexpectedEOF
	}
	f.got = append(f.got, rs...)
	return nil
}

// The pump forwards new events and advances the cursor only on success; a failing
// sink leaves the cursor where it was, so the batch is retried rather than lost.
func TestPumpForwardsAndAdvancesOnlyOnSuccess(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// A fresh event to forward, written through audit.Write so the hash chain
	// stays intact. The row is NOT deleted afterwards: core.audit_events is a
	// hash-linked chain, and both inserting a row without a hash and deleting a
	// row in the middle break it (that is precisely what the audit package's own
	// tamper tests detect). A valid extra entry is harmless; a broken chain is not.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "test.stream", Retention: "security",
		Detail: map[string]any{"k": "v"},
	}); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM core.audit_events WHERE event_type = 'test.stream' ORDER BY id DESC LIMIT 1`).
		Scan(&id); err != nil {
		t.Fatal(err)
	}
	// Cursor just below our row so exactly it is pending.
	if _, err := pool.Exec(ctx,
		`UPDATE core.audit_stream_state SET last_id = $1 WHERE only_row`, id-1); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A failing sink must not advance the cursor.
	failing := &fakeSink{fail: true}
	if _, err := NewPump(pool, failing, log).once(ctx); err == nil {
		t.Error("a failing sink returned no error from the pump")
	}
	var after int64
	_ = pool.QueryRow(ctx, `SELECT last_id FROM core.audit_stream_state WHERE only_row`).Scan(&after)
	if after != id-1 {
		t.Errorf("cursor moved to %d despite a failed emit; the batch would be lost", after)
	}

	// A working sink forwards the row and advances past it.
	ok := &fakeSink{}
	sent, err := NewPump(pool, ok, log).once(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sent == 0 {
		t.Fatal("nothing was forwarded")
	}
	found := false
	for _, r := range ok.got {
		if r.ID == id {
			found = true
			if r.EventType != "test.stream" || r.Detail["k"] != "v" {
				t.Errorf("record forwarded with wrong contents: %+v", r)
			}
		}
	}
	if !found {
		t.Error("the new event was not forwarded")
	}
	_ = pool.QueryRow(ctx, `SELECT last_id FROM core.audit_stream_state WHERE only_row`).Scan(&after)
	if after < id {
		t.Errorf("cursor at %d after a successful emit, want >= %d", after, id)
	}
}
