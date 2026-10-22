package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// An admin token from the CLI expires in ninety days unless asked otherwise,
// and never only when -expires-in 0 says so (6.04).
func TestAnAdminTokenFromTheCLIExpiresUnlessToldNotTo(t *testing.T) {
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

	expiry := func(name string, in time.Duration, given bool) *time.Time {
		t.Helper()
		t.Cleanup(func() {
			_, _ = db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE name = $1`, name)
		})
		if err := adminTokenCreate(ctx, db, name, "", "config:read", in, given, "", ""); err != nil {
			t.Fatal(err)
		}
		var at *time.Time
		if err := db.QueryRow(ctx, `SELECT expires_at FROM core.admin_tokens WHERE name = $1`, name).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	stamp := time.Now().UnixNano()
	if at := expiry(fmt.Sprintf("cli-default-%d", stamp), 0, false); at == nil ||
		at.Sub(time.Now()) < 89*24*time.Hour || at.Sub(time.Now()) > 91*24*time.Hour {
		t.Errorf("with no -expires-in the token expires %v, want in ninety days", at)
	}
	if at := expiry(fmt.Sprintf("cli-never-%d", stamp), 0, true); at != nil {
		t.Errorf("-expires-in 0 gave an expiry, %v", at)
	}
	if at := expiry(fmt.Sprintf("cli-day-%d", stamp), 24*time.Hour, true); at == nil || at.Sub(time.Now()) > 25*time.Hour {
		t.Errorf("-expires-in 24h gave %v", at)
	}
}
