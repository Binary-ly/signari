package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// An export verifies the chain and then reads the rows. Under READ COMMITTED
// those were two snapshots, so a row appended between them went out under a
// verification that had never read it. The export now refuses a transaction
// that cannot hold one snapshot, and under one, a row committed after the
// snapshot is in neither the verification nor the file.
func TestAnExportVerifiesAndReadsOneSnapshot(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()

	rc, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ExportCSV(ctx, rc, io.Discard, ExportOptions{})
	_ = rc.Rollback(ctx)
	if err == nil || !strings.Contains(err.Error(), "one snapshot") {
		t.Fatalf("an export in a READ COMMITTED transaction was not refused: %v", err)
	}

	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rr.Rollback(ctx) }()
	var before int
	if err := rr.QueryRow(ctx, `SELECT count(*) FROM core.audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	writer, err := pgx.Connect(ctx, os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(context.Background()) })
	marker := fmt.Sprintf("export-snapshot-probe-%d", time.Now().UnixNano())
	wtx, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(ctx, wtx, Event{Type: marker}); err != nil {
		t.Fatal(err)
	}
	if err := wtx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	res, err := ExportCSV(ctx, rr, &out, ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != before {
		t.Errorf("the export wrote %d rows from a snapshot that held %d", res.Rows, before)
	}
	if strings.Contains(out.String(), marker) {
		t.Error("a row committed after the export's snapshot is in the file")
	}
}
