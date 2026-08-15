package audit

import (
	"context"
	"crypto/sha256"
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

// TestExistingChainSurvivesTheAttributionField.
//
// When AdminTokenID was added it was hashed unconditionally, which changed the
// digest of every entry that did not have one -- so the whole pre-existing chain
// read as tampered. An append-only table cannot be rehashed, so that would have
// been unrecoverable in production, and indistinguishable from a real attack.
//
// The rule this pins: an event with no attribution must hash exactly as it did
// before the field existed.
func TestExistingChainSurvivesTheAttributionField(t *testing.T) {
	e := Event{
		Type: "test.event", OrgID: "org", SubjectID: "subj", ActorID: "actor",
		ClientID: "client", CorrelationID: "corr", Retention: RetentionSecurity,
	}

	// The formula as it stood before the field was added, written out here so
	// this test does not depend on the code it is checking.
	legacy := sha256.New()
	legacy.Write([]byte(nil))
	for _, f := range []string{e.Type, e.OrgID, e.SubjectID, e.ActorID, e.ClientID,
		e.CorrelationID, e.Retention} {
		legacy.Write([]byte(f))
		legacy.Write([]byte{0})
	}
	legacy.Write([]byte("{}"))

	if got := chainHash(nil, e, "{}"); !equalBytes(got, legacy.Sum(nil)) {
		t.Fatal("an unattributed event no longer hashes the way it did before " +
			"AdminTokenID existed; every historic row would now read as tampered")
	}
}

// TestAttributionIsCoveredByTheChain. The other half: attribution that the hash
// does not cover could be rewritten without breaking the chain, leaving a record
// that looks intact while naming the wrong credential.
func TestAttributionIsCoveredByTheChain(t *testing.T) {
	base := Event{Type: "admin.thing", Retention: RetentionSecurity}
	withToken := base
	withToken.AdminTokenID = "11111111-1111-1111-1111-111111111111"
	other := base
	other.AdminTokenID = "22222222-2222-2222-2222-222222222222"

	if equalBytes(chainHash(nil, base, "{}"), chainHash(nil, withToken, "{}")) {
		t.Error("adding attribution did not change the hash")
	}
	if equalBytes(chainHash(nil, withToken, "{}"), chainHash(nil, other, "{}")) {
		t.Error("two different tokens produce the same hash; attribution could be " +
			"swapped without detection")
	}
}

// TestRevokingATokenDoesNotRewriteHistory.
//
// core.audit_events once had ON DELETE SET NULL on admin_token_id and org_id,
// and both columns are inside the chain hash. Deleting a token therefore
// rewrote every audit row it had caused, and the chain then reported those rows
// as tampered -- for an entirely ordinary administrative action.
//
// A smoke alarm that goes off when somebody makes toast gets taken down. That is
// the real damage: the false positives cost the true ones their meaning.
//
// This test asserts the referential actions are gone. It is a schema assertion
// rather than a behavioural one because the failure was a schema decision, and
// the natural fix -- someone re-adding a foreign key "for tidiness" -- would be
// silent without it.
func TestRevokingATokenDoesNotRewriteHistory(t *testing.T) {
	conn := connect(t)
	ctx := t.Context()

	rows, err := conn.Query(ctx, `
		SELECT conname, confdeltype
		FROM pg_constraint
		WHERE conrelid = 'core.audit_events'::regclass AND contype = 'f'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var delType string
		if err := rows.Scan(&name, &delType); err != nil {
			t.Fatal(err)
		}
		// 'a' is NO ACTION, which never mutates. Anything else can reach into a
		// written row and change it.
		if delType != "a" && delType != "r" {
			t.Errorf("core.audit_events has foreign key %q with ON DELETE type %q; "+
				"a referential action that alters a hashed column rewrites history "+
				"and breaks the chain", name, delType)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
