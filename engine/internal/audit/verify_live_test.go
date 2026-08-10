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
	if broken != 0 {
		t.Fatalf("the live chain is broken at id %d after checking %d rows", broken, checked)
	}
	t.Logf("verified %d rows written by the server", checked)
}
