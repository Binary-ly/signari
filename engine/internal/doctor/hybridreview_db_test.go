package doctor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A hybrid-flow exemption past its review date is reported. `client
// set-hybrid` demands the date and the schema says it is "Reported, not
// enforced", and nothing reported it (found by guard 0.08b).
func TestAnOverdueHybridExemptionIsReported(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	n := time.Now().UnixNano()
	overdue, current := fmt.Sprintf("hybrid-overdue-%d", n), fmt.Sprintf("hybrid-current-%d", n)
	for _, c := range []struct{ id, due string }{
		{overdue, "2020-01-01"}, {current, "2999-01-01"},
	} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          client_secret_hash, allow_hybrid, hybrid_review_by)
			SELECT $1, id, 'T', 'confidential', 'x', true, $2::date
			  FROM core.organizations LIMIT 1`, c.id, c.due); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{}
	if err := checkClients(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	var said []string
	for _, f := range r.Findings {
		said = append(said, f.Summary)
	}
	all := strings.Join(said, "\n")
	if !strings.Contains(all, overdue) || !strings.Contains(all, "2020-01-01") {
		t.Errorf("the overdue exemption was not reported:\n%s", all)
	}
	if strings.Contains(all, current) {
		t.Errorf("an exemption not yet due was reported:\n%s", all)
	}
}
