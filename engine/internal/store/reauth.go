package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The bounds core.organizations.reauth_window_s holds (0167). Under a minute
// asks somebody to sign in again between reading a page and pressing its
// button; over a day is a session's whole life on most deployments, which is
// no window at all.
const (
	MinReauthWindow     = time.Minute
	MaxReauthWindow     = 24 * time.Hour
	DefaultReauthWindow = 10 * time.Minute
)

// ErrReauthWindow is a window outside the bounds.
var ErrReauthWindow = fmt.Errorf("the re-authentication window must be whole seconds from %s to %s",
	MinReauthWindow, MaxReauthWindow)

// ErrOrganizationNotFound is an organisation id that names none.
var ErrOrganizationNotFound = errors.New("no such organisation")

// SetReauthWindow sets how recently a session must have been authenticated to
// change the account, and returns the window it replaced.
func SetReauthWindow(ctx context.Context, tx pgx.Tx, orgID string, d time.Duration) (time.Duration, error) {
	if d < MinReauthWindow || d > MaxReauthWindow || d%time.Second != 0 {
		return 0, ErrReauthWindow
	}
	var previous int
	err := tx.QueryRow(ctx, `
		SELECT reauth_window_s FROM core.organizations WHERE id = $1::uuid FOR UPDATE`, orgID).
		Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrOrganizationNotFound
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET reauth_window_s = $2 WHERE id = $1::uuid`,
		orgID, int(d.Seconds())); err != nil {
		return 0, err
	}
	return time.Duration(previous) * time.Second, nil
}
