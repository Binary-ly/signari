package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No test may forge a link in the audit chain, or delete one.
//
// # The mistake this guards, which was made here
//
// `core.audit_events` is a hash chain: each row's `entry_hash` covers its
// predecessor's. Two things follow, and a test fixture broke both on 31 August
// 2026:
//
//   - An INSERT with hand-made `prev_hash`/`entry_hash` values is not a link.
//     It is a row that looks like one and hashes to nothing the chain agrees
//     with.
//   - A DELETE breaks the link that pointed at the deleted row. Permanently, and
//     for every row after it.
//
// The fixture did both — inserted rows with `sha256(...)` literals and cleaned
// up with `DELETE ... WHERE event_type = $1` — and orphaned 6,635 rows' worth of
// chain in the shared test database. The audit package's own tamper-detection
// tests caught it immediately, which is the mechanism working; what was missing
// was anything stopping the fixture being written that way in the first place.
//
// The correct shape is `audit.Write` inside a transaction, and no cleanup: an
// append-only trail is append-only for tests too. A fixture that needs an
// older row writes it with `Event.OccurredAt`: since hash version 2 (3.19)
// occurred_at is in the hash, so moving it afterwards breaks the chain too.
//
// An UPDATE of any chain column is therefore a broken link as well.
var movedLink = regexp.MustCompile(`(?is)UPDATE\s+core\.audit_events\s+SET`)

var (
	// An INSERT naming the chain columns. The columns are the tell: a fixture
	// that writes them is claiming to produce a link.
	forgedLink = regexp.MustCompile(`(?is)INSERT\s+INTO\s+core\.audit_events[^;]*?(prev_hash|entry_hash)`)
	// Any DELETE against the table.
	brokenLink = regexp.MustCompile(`(?is)DELETE\s+FROM\s+core\.audit_events`)
)

func TestNoTestForgesOrDeletesAnAuditChainLink(t *testing.T) {
	root := repoRoot(t)
	engine := filepath.Join(root, "engine")

	err := filepath.Walk(engine, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		// The audit package's own tests build and break chains ON PURPOSE --
		// that is what TestTamperedRowIsDetected and TestDeletedRowIsDetected
		// are. They run against SIGNARI_DESTRUCTIVE_TEST_DSN for exactly this
		// reason, and exempting them by path is honest rather than a loophole.
		if strings.Contains(path, filepath.Join("internal", "audit")) {
			return nil
		}

		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		body := string(src)
		rel, _ := filepath.Rel(root, path)

		if m := forgedLink.FindString(body); m != "" {
			t.Errorf("%s writes prev_hash or entry_hash into core.audit_events.\n\n"+
				"Those are chain links, and a hand-made value is not one. Use "+
				"audit.Write inside a transaction, which computes the link from "+
				"the row before it.\n\nFound near: %s",
				rel, firstLine(m))
		}
		if brokenLink.MatchString(body) {
			t.Errorf("%s deletes from core.audit_events.\n\n"+
				"Deleting a row breaks the link that pointed at it, and every "+
				"row after it, permanently. An append-only trail is append-only "+
				"for tests too -- write real events and leave them. If a fixture "+
				"needs an older row, write it with audit.Event.OccurredAt.", rel)
		}
		// A test that alters a row on a database of its own is not a fixture
		// breaking the shared chain; it names its own database to say so.
		if movedLink.MatchString(body) && !strings.Contains(body, "CREATE DATABASE") {
			t.Errorf("%s updates core.audit_events in the shared database.\n\n"+
				"Every column but id is in the chain hash, occurred_at included "+
				"since hash version 2, so an UPDATE breaks the chain from that row "+
				"on. Write the row as it should be with audit.Write, giving "+
				"Event.OccurredAt for an older one.", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
