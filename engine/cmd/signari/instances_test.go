package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The key commands act on the instance SIGNARI_ISSUER names, as serve does.
// They took the oldest instance whatever was named, so with two `keys rotate`
// rotated another issuer's keys (0.33).
func TestTheKeyCommandsActOnTheNamedInstance(t *testing.T) {
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
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(ctx, "ROLLBACK") }()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNARI_ROOT_KEY", base64.StdEncoding.EncodeToString(raw))
	t.Setenv("SIGNARI_ROOT_KEY_FILE", "")

	var older, newer, newerIssuer string
	for _, dst := range []*string{&older, &newer} {
		if err := conn.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://keys-' || gen_random_uuid() || '.test', 'T') RETURNING id::text`).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.QueryRow(ctx, `SELECT issuer FROM core.instances WHERE id::text = $1`, newer).Scan(&newerIssuer); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNARI_ISSUER", newerIssuer)
	got, _, _, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got != newer {
		t.Errorf("the key commands act on %s, not the instance SIGNARI_ISSUER names (%s)", got, newer)
	}
}

// SIGNARI_ADDITIONAL_ISSUERS names the instances served beside the primary
// (6.12): each must exist and be named once, and the primary is not named
// again. Inside a transaction that is rolled back, so the instances it makes
// are seen by nothing else.
func TestTheAdditionalIssuersAreNamedInstancesEachOnce(t *testing.T) {
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
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(ctx, "ROLLBACK") }()

	issuer := func() (string, string) {
		var id, iss string
		if err := conn.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://ai-' || gen_random_uuid() || '.test', 'T') RETURNING id::text, issuer`).Scan(&id, &iss); err != nil {
			t.Fatal(err)
		}
		return id, iss
	}
	_, primary := issuer()
	idB, b := issuer()
	idC, c := issuer()

	got, err := additionalInstances(ctx, conn, " "+b+" ,"+c+",", primary)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].id != idB || got[1].id != idC || got[0].issuer != b {
		t.Errorf("the named instances read as %+v", got)
	}
	if got, err := additionalInstances(ctx, conn, "", primary); err != nil || len(got) != 0 {
		t.Errorf("none named answered %v, %v", got, err)
	}
	for why, raw := range map[string]string{
		"twice":             b + "," + b,
		"the primary":       primary,
		"an unknown issuer": "https://nobody-" + idB + ".test",
	} {
		if _, err := additionalInstances(ctx, conn, raw, primary); err == nil {
			t.Errorf("an issuer named %s was accepted", why)
		} else if !strings.Contains(err.Error(), "SIGNARI_ADDITIONAL_ISSUERS") {
			t.Errorf("naming %s was refused without saying which setting: %v", why, err)
		}
	}
}
