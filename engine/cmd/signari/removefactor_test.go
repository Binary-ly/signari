package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// `user remove-factor` removes a method, as the Admin API does, and queues the
// holder's notice with it (4.14). A kind that is not one, or a passkey not
// named when the person might hold several, is refused before anything moves.
func TestRemoveFactorRemovesAndTellsTheHolder(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var org string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://rmfactor-' || gen_random_uuid() || '.test', 'Remove factor test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'r' || substr(gen_random_uuid()::text, 1, 8), 'RF' FROM i RETURNING id::text`).
		Scan(&org); err != nil {
		t.Fatal(err)
	}
	email := fmt.Sprintf("rmfactor-%d@example.test", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email)
	})
	pw := make([]byte, 24)
	_, _ = rand.Read(pw)
	if err := run([]string{"user", "create", "-dsn", dsn, "-org", org, "-email", email,
		"-password", base64.RawURLEncoding.EncodeToString(pw)}); err != nil {
		t.Fatal(err)
	}
	var userID string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GenerateRecoveryCodes(ctx, tx, userID, org, 10); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	base := []string{"user", "remove-factor", "-dsn", dsn, "-org", org, "-email", email}
	for _, bad := range [][]string{{"-factor", "password"}, {"-factor", "webauthn"}, {}} {
		if err := run(append(append([]string{}, base...), bad...)); err == nil {
			t.Errorf("remove-factor %v was accepted", bad)
		}
	}
	if err := run(append(base, "-factor", "recovery")); err != nil {
		t.Fatalf("remove-factor recovery: %v", err)
	}
	var codes, notices int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM core.recovery_codes WHERE user_id = $1::uuid),
		(SELECT count(*) FROM core.outbox WHERE topic = 'account_notice' AND payload->>'user_id' = $1::text
		    AND payload->>'factor' = 'recovery')`, userID).Scan(&codes, &notices); err != nil {
		t.Fatal(err)
	}
	if codes != 0 || notices != 1 {
		t.Errorf("after removal: %d recovery codes, %d notices queued", codes, notices)
	}
	if err := run(append(base, "-factor", "recovery")); err == nil {
		t.Error("removing what is no longer there succeeded")
	}
}
