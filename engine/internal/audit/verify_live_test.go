package audit

import (
	"context"
	"testing"
)

// Verifies the chain the RUNNING SERVER wrote, not one the test built.
//
// The unit tests above construct their own entries, so they would still pass if
// the server wrote rows a different way -- which is exactly the bug that hid
// here once already (Go's JSON bytes versus what jsonb stores). This one reads
// whatever is actually in the table.
//
// It judges the chain as an export does: the whole of it, or, when that fails,
// everything from the latest declared checkpoint provided the break is before
// it. A break after the checkpoint fails, and is the one reported. A
// historical break with no checkpoint fails too, so declaring one stays a
// deliberate, recorded act (`signari audit checkpoint`).
func TestLiveChainVerifies(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	broken, checked, err := Verify(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Skip("no audit rows in this database yet")
	}
	if broken == 0 {
		t.Logf("verified %d rows written by the server", checked)
		return
	}
	cp, err := LatestCheckpoint(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if cp == nil || broken >= cp.EntryID {
		t.Fatalf("the live chain is broken at id %d after checking %d rows, and no "+
			"checkpoint declared after it", broken, checked)
	}
	from, fromChecked, err := VerifyFrom(ctx, tx, cp.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if from != 0 {
		t.Fatalf("the live chain is broken at id %d, after the checkpoint at %d", from, cp.EntryID)
	}
	t.Logf("verified %d rows from the checkpoint at %d (%q); the break at %d is before it",
		fromChecked, cp.EntryID, cp.Reason, broken)
}
