package provision

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type execRecorder struct {
	DB
	sent []string
}

func (e *execRecorder) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	e.sent = append(e.sent, sql)
	return pgconn.CommandTag{}, nil
}

// A sync that has written many links counts them, or the next one, with nothing to do,
// walks all of them per person. One that wrote a few leaves the table to autovacuum,
// as an ANALYZE on every small sync would be work for nothing.
func TestABigSyncCountsTheLinksItWrote(t *testing.T) {
	for _, c := range []struct {
		created int
		counts  bool
	}{{0, false}, {countAfter - 1, false}, {countAfter, true}, {100000, true}} {
		db := &execRecorder{}
		countLinks(context.Background(), db, c.created)
		if counted := len(db.sent) == 1 && db.sent[0] == `ANALYZE core.scim_links`; counted != c.counts {
			t.Errorf("after %d new links it sent %q, want counted=%v", c.created, db.sent, c.counts)
		}
	}
}
