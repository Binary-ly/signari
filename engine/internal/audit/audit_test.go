package audit

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(context.Background(), "SET ROLE signari_maintenance"); err != nil {
		t.Fatalf("assuming signari_maintenance: %v", err)
	}
	return conn
}

// Every test runs inside a transaction that is never committed, so the real
// chain in the database is left exactly as it was.
func inRollback(t *testing.T, fn func(tx pgx.Tx)) {
	t.Helper()
	conn := connect(t)
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fn(tx)
}

func TestChainVerifies(t *testing.T) {
	inRollback(t, func(tx pgx.Tx) {
		ctx := context.Background()
		for _, ev := range []Event{
			{Type: EventLoginFailed, Detail: map[string]any{"reason": "bad_password"}},
			{Type: EventLoginSucceeded, Detail: map[string]any{"amr": []string{"pwd"}}},
			{Type: EventCodeIssued, ClientID: "webapp"},
		} {
			if err := Write(ctx, tx, ev); err != nil {
				t.Fatalf("write %s: %v", ev.Type, err)
			}
		}

		broken, checked, err := Verify(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if checked < 3 {
			t.Fatalf("verified only %d entries", checked)
		}
		if broken != 0 {
			t.Fatalf("chain reported broken at id %d on untouched data", broken)
		}
	})
}

// The property the chain exists for. Editing a row in place is exactly what an
// attacker with database access does to remove evidence of their own sign-in,
// and it must not go unnoticed.
func TestTamperedRowIsDetected(t *testing.T) {
	inRollback(t, func(tx pgx.Tx) {
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			if err := Write(ctx, tx, Event{Type: EventLoginSucceeded}); err != nil {
				t.Fatal(err)
			}
		}

		var victim int64
		if err := tx.QueryRow(ctx,
			`SELECT id FROM core.audit_events ORDER BY id DESC LIMIT 1 OFFSET 1`).Scan(&victim); err != nil {
			t.Fatal(err)
		}
		// Rewrite the event type, leaving every hash untouched -- the subtle
		// version of tampering, where the row still looks structurally fine.
		if _, err := tx.Exec(ctx,
			`UPDATE core.audit_events SET event_type = 'login.failed' WHERE id = $1`, victim); err != nil {
			t.Fatal(err)
		}

		broken, _, err := Verify(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if broken != victim {
			t.Fatalf("tampered row %d was not detected (Verify reported %d)", victim, broken)
		}
	})
}

// Deleting a row to hide an event must also be detectable. It shows up at the
// SUCCESSOR, whose prev_hash no longer matches the new predecessor's entry_hash.
func TestDeletedRowIsDetected(t *testing.T) {
	inRollback(t, func(tx pgx.Tx) {
		ctx := context.Background()
		for i := 0; i < 4; i++ {
			if err := Write(ctx, tx, Event{Type: EventLoginSucceeded}); err != nil {
				t.Fatal(err)
			}
		}

		var victim, successor int64
		if err := tx.QueryRow(ctx,
			`SELECT id FROM core.audit_events ORDER BY id DESC LIMIT 1 OFFSET 2`).Scan(&victim); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT min(id) FROM core.audit_events WHERE id > $1`, victim).Scan(&successor); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM core.audit_events WHERE id = $1`, victim); err != nil {
			t.Fatal(err)
		}

		broken, _, err := Verify(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if broken != successor {
			t.Fatalf("deletion of %d should surface at its successor %d, got %d",
				victim, successor, broken)
		}
	})
}

// An unclassified event must not default to the most erasable class, or a
// security event quietly becomes deletable on request.
func TestRetentionDefaultsToSecurity(t *testing.T) {
	inRollback(t, func(tx pgx.Tx) {
		ctx := context.Background()
		if err := Write(ctx, tx, Event{Type: EventLoginSucceeded}); err != nil {
			t.Fatal(err)
		}
		var class string
		if err := tx.QueryRow(ctx,
			`SELECT retention_class FROM core.audit_events ORDER BY id DESC LIMIT 1`).Scan(&class); err != nil {
			t.Fatal(err)
		}
		if class != RetentionSecurity {
			t.Errorf("retention_class = %q, want %q", class, RetentionSecurity)
		}
	})
}

func TestTypeIsRequired(t *testing.T) {
	inRollback(t, func(tx pgx.Tx) {
		if err := Write(context.Background(), tx, Event{}); err == nil {
			t.Fatal("an event with no type was accepted")
		}
	})
}
