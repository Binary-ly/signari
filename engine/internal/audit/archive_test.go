package audit

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/migrate"
)

// scratchChain is a migrated database of the test's own, since archiving
// removes rows and these tests break chains on purpose.
func scratchChain(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("signari_archivetest_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, tier := range []migrate.Tier{migrate.TierBootstrap, migrate.TierCore} {
		if _, err := migrate.Up(ctx, conn, tier, 0, migrate.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

func writeAt(t *testing.T, conn *pgx.Conn, at time.Time, version int, n int) {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := write(ctx, tx, Event{Type: "test.archive", OccurredAt: at,
		Detail: map[string]any{"n": n}}, version); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// archive writes and commits one archive, returning it and its file.
func archive(t *testing.T, conn *pgx.Conn, before time.Time) (*Archive, []byte) {
	t.Helper()
	ctx := context.Background()
	snap, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	var file bytes.Buffer
	a, err := WriteArchive(ctx, snap, &file, before)
	_ = snap.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitArchive(ctx, tx, a, "test operator"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return a, file.Bytes()
}

func judge(t *testing.T, conn *pgx.Conn) *ChainState {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s, err := JudgeChain(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// An archive verifies with nothing but its file, the trail left verifies from
// it, and a later archive chains to it (3.18). The trail only grew, and the
// one way to shrink it broke the chain for good.
func TestAnArchiveVerifiesAloneAndTheRestFromIt(t *testing.T) {
	conn := scratchChain(t)
	old := time.Date(2026, 1, 2, 3, 4, 5, 678901000, time.UTC)
	writeAt(t, conn, old, 1, 0) // a row as an older release wrote it
	for i := 1; i < 6; i++ {
		writeAt(t, conn, old.Add(time.Duration(i)*time.Hour), 2, i)
	}
	for i := 6; i < 9; i++ {
		writeAt(t, conn, time.Time{}, 2, i)
	}

	a, file := archive(t, conn, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if a.Entries != 6 || len(a.FirstPrev) != 0 {
		t.Fatalf("archived %d entries from prev %x, want the first 6 from the start", a.Entries, a.FirstPrev)
	}
	v, err := VerifyArchiveFile(bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	if v.BrokenAt != 0 || v.Entries != 6 || v.SHA256 != a.SHA256 || !bytes.Equal(v.LastHash, a.LastHash) {
		t.Fatalf("the file on its own: %+v, archive %+v", v, a)
	}
	var left int
	if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if s := judge(t, conn); !s.Verified || s.Checkpoint != nil || left != 4 || s.Checked != 4 {
		t.Fatalf("after the archive: %+v with %d rows left, want 4 verified from the archive", s, left)
	}

	// A second archive takes the first one's record with it, and its file
	// starts where the first ended and names it.
	writeAt(t, conn, time.Time{}, 2, 9)
	b, file2 := archive(t, conn, time.Now().Add(time.Hour))
	v2, err := VerifyArchiveFile(bytes.NewReader(file2))
	if err != nil {
		t.Fatal(err)
	}
	if v2.BrokenAt != 0 || !bytes.Equal(v2.FirstPrev, a.LastHash) || v2.PreviousArchiveSum != a.SHA256 {
		t.Errorf("the second file: broken %d, first prev %x (want %x), names %q (want %q)",
			v2.BrokenAt, v2.FirstPrev, a.LastHash, v2.PreviousArchiveSum, a.SHA256)
	}
	if s := judge(t, conn); !s.Verified || s.Checked != 1 || b.Entries != 5 {
		t.Errorf("after the second archive of %d: %+v, want its record alone, verified", b.Entries, s)
	}
}

// A row removed after an archive is caught like any other, and so is an
// edited archive file.
func TestADeletionAfterAnArchiveIsCaught(t *testing.T) {
	conn := scratchChain(t)
	old := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	for i := range 4 {
		writeAt(t, conn, old.Add(time.Duration(i)*time.Hour), 2, i)
	}
	for i := 4; i < 7; i++ {
		writeAt(t, conn, time.Time{}, 2, i)
	}
	_, file := archive(t, conn, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	edited := bytes.Replace(file, []byte(`{""n"": 2}`), []byte(`{""n"": 9}`), 1)
	if bytes.Equal(edited, file) {
		t.Fatalf("the fixture has no entry to edit:\n%s", file)
	}
	if v, err := VerifyArchiveFile(bytes.NewReader(edited)); err != nil || v.BrokenAt == 0 {
		t.Errorf("an edited archive file verified: %+v %v", v, err)
	}

	ctx := context.Background()
	var first int64
	if err := conn.QueryRow(ctx, `SELECT min(id) FROM core.audit_events`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM core.audit_events WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	if s := judge(t, conn); s.Verified {
		t.Errorf("the first entry after an archive was deleted and the chain verified: %+v", s)
	}
}

// An archive is refused on a broken chain, and is not committed when the
// chain no longer starts where it ends.
func TestAnArchiveRefusesWhatItCannotVouchFor(t *testing.T) {
	conn := scratchChain(t)
	ctx := context.Background()
	old := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	for i := range 3 {
		writeAt(t, conn, old.Add(time.Duration(i)*time.Hour), 2, i)
	}
	writeAt(t, conn, time.Time{}, 2, 3)

	snap, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	a, err := WriteArchive(ctx, snap, &bytes.Buffer{}, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	_ = snap.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	moved := *a
	moved.LastHash = []byte("not the last hash")
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitArchive(ctx, tx, &moved, "test operator"); err == nil || !strings.Contains(err.Error(), "no longer links") {
		t.Errorf("an archive the chain moved past: %v", err)
	}
	_ = tx.Rollback(ctx)

	if _, err := conn.Exec(ctx, `UPDATE core.audit_events SET detail = '{"n": 9}'
		WHERE id = (SELECT min(id) FROM core.audit_events)`); err != nil {
		t.Fatal(err)
	}
	snap, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snap.Rollback(ctx) }()
	if _, err := WriteArchive(ctx, snap, &bytes.Buffer{}, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)); err == nil ||
		!strings.Contains(err.Error(), "broken") {
		t.Errorf("an archive of a broken chain: %v", err)
	}
}
