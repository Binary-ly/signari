// Package storetest is what a test needs to leave the shared database as it
// found it. Tests import it; the engine does not.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is a pool or a connection.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// holders are the tables that refuse to lose an organisation (ON DELETE RESTRICT)
// and what they refuse in turn, most dependent first. Everything else goes with it.
var holders = []string{
	"authorization_codes", "refresh_token_families", "sessions",
	"recovery_code_failures", "recovery_requests", "recovery_codes",
	"totp_enrolments", "totp_credentials", "webauthn_credentials",
	"password_credentials", "clients", "users",
}

// Forget removes organisations when the test ends, with what holds them, and each
// one's instance if that leaves it none. The audit trail stays, as it does when a
// real organisation is deleted.
//
// A test that makes an organisation and leaves it costs every later run: a sign-in
// page counts the organisations, and the shared database once held 278,628 of them,
// at 727 MB, when a test that wanted any one of them got whichever came first.
func Forget(t testing.TB, db Execer, orgIDs ...string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, org := range orgIDs {
			if err := remove(ctx, db, org); err != nil {
				t.Errorf("organisation %s was left behind: %v", org, err)
			}
		}
	})
}

func remove(ctx context.Context, db Execer, org string) error {
	for _, table := range holders {
		if _, err := db.Exec(ctx, `DELETE FROM core.`+table+` WHERE org_id = $1::uuid`, org); err != nil {
			return err
		}
	}
	_, err := db.Exec(ctx, `
		WITH gone AS (DELETE FROM core.organizations WHERE id = $1::uuid RETURNING instance_id)
		DELETE FROM core.instances i USING gone
		 WHERE i.id = gone.instance_id
		   AND NOT EXISTS (SELECT 1 FROM core.organizations o WHERE o.instance_id = i.id AND o.id <> $1::uuid)`, org)
	return err
}
