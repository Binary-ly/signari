package migrate

import (
	"context"
	"strings"
	"testing"
)

// A PostgreSQL older than the release runs on is refused by verify and by
// migrate before anything is applied (3.28). Nothing declared a range: an
// older server failed part way through the migrations. The floor is raised
// above this server's major to make it the old one.
func TestAnUnsupportedPostgreSQLIsRefused(t *testing.T) {
	conn, ctx := fpConn(t)
	major, err := ServerMajor(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if major < MinServerMajor {
		t.Fatalf("the test database is PostgreSQL %d, below the floor %d", major, MinServerMajor)
	}
	saved := MinServerMajor
	t.Cleanup(func() { MinServerMajor = saved })
	MinServerMajor = major + 1

	if err := Verify(ctx, conn); err == nil || !strings.Contains(err.Error(), "older than") {
		t.Errorf("verify on a server below the floor said %v", err)
	}
	applied, err := Up(context.Background(), conn, TierCore, 0, Options{})
	if err == nil || !strings.Contains(err.Error(), "older than") || len(applied) != 0 {
		t.Errorf("migrate on a server below the floor applied %d and said %v", len(applied), err)
	}
}
