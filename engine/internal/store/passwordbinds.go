package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// The two answers core.organizations.password_only_binds may hold (0128).
const (
	PasswordBindsAllow         = "allow"
	PasswordBindsRefuseWhenMFA = "refuse_when_mfa"
)

// RefusesPasswordOnlyBinds reports whether an organisation refuses a bind that
// proves only a password -- LDAP, RADIUS PAP, an outpost -- for somebody its
// sign-in flow would ask for a second factor.
//
// An organisation that cannot be found refuses. The caller has just found a
// user in it, so this is a race with a deletion, and the answer that cannot
// sign anybody in wrongly is the one to give.
func RefusesPasswordOnlyBinds(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (bool, error) {
	var policy string
	err := db.QueryRow(ctx,
		`SELECT password_only_binds FROM core.organizations WHERE id = $1::uuid`, orgID).Scan(&policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading the organisation's password-only bind rule: %w", err)
	}
	return policy != PasswordBindsAllow, nil
}
