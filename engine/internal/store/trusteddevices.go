package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Remembered devices (migration 0168): a device a person chose, after a second
// factor, not to be asked for one on again for the organisation's number of
// days. Read on every sign-in and never cached (ADR-007), so forgetting one
// holds from the next sign-in.

// MaxRememberDeviceDays bounds the organisation's setting, as the schema does.
const MaxRememberDeviceDays = 90

// ErrRememberDeviceDays is a setting outside 0 to MaxRememberDeviceDays.
var ErrRememberDeviceDays = fmt.Errorf("a device can be remembered for 0 (never) to %d days",
	MaxRememberDeviceDays)

// RememberDeviceDaysForUser is the setting of the organisation userID is in.
func RememberDeviceDaysForUser(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (int, error) {
	var days int
	err := q.QueryRow(ctx, `
		SELECT o.remember_device_days FROM core.users u
		  JOIN core.organizations o ON o.id = u.org_id
		 WHERE u.id = $1::uuid`, userID).Scan(&days)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return days, err
}

// SetRememberDeviceDays sets an organisation's setting and returns the one it
// replaced. 0 turns it off, and every remembered device stops counting with
// it, whatever its own expiry.
func SetRememberDeviceDays(ctx context.Context, tx pgx.Tx, orgID string, days int) (int, error) {
	if days < 0 || days > MaxRememberDeviceDays {
		return 0, ErrRememberDeviceDays
	}
	var previous int
	err := tx.QueryRow(ctx, `SELECT remember_device_days FROM core.organizations
		WHERE id = $1::uuid FOR UPDATE`, orgID).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrOrganizationNotFound
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET remember_device_days = $2
		WHERE id = $1::uuid`, orgID, days); err != nil {
		return 0, err
	}
	return previous, nil
}

// RememberDevice records a device for userID, for the organisation's number of
// days, and reports false when the organisation offers none.
func RememberDevice(ctx context.Context, tx pgx.Tx, orgID, userID string, tokenHash []byte,
	userAgent string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.trusted_devices (org_id, user_id, token_hash, user_agent, expires_at)
		SELECT o.id, $2::uuid, $3, $4, now() + make_interval(days => o.remember_device_days)
		  FROM core.organizations o
		 WHERE o.id = $1::uuid AND o.remember_device_days > 0`,
		orgID, userID, tokenHash, userAgent)
	if err != nil {
		return false, fmt.Errorf("remembering a device: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeviceRemembered reports whether tokenHash is a device userID remembered and
// that still counts: not forgotten, not expired, and the organisation still
// offering it. A use is recorded.
func DeviceRemembered(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, userID string, tokenHash []byte) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		UPDATE core.trusted_devices d SET last_used_at = now()
		  FROM core.organizations o
		 WHERE d.token_hash = $3 AND d.user_id = $2::uuid AND d.org_id = $1::uuid
		   AND o.id = d.org_id AND o.remember_device_days > 0
		   AND d.revoked_at IS NULL AND d.expires_at > now()
		RETURNING true`, orgID, userID, tokenHash).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}

// RememberedDevice is one row of the account page's list.
type RememberedDevice struct {
	ID, UserAgent        string
	CreatedAt, ExpiresAt time.Time
	LastUsedAt           *time.Time
}

// RememberedDevices lists the devices userID has remembered that still count.
func RememberedDevices(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, userID string) ([]RememberedDevice, error) {
	rows, err := q.Query(ctx, `
		SELECT d.id::text, d.user_agent, d.created_at, d.expires_at, d.last_used_at
		  FROM core.trusted_devices d
		  JOIN core.organizations o ON o.id = d.org_id AND o.remember_device_days > 0
		 WHERE d.user_id = $1::uuid AND d.revoked_at IS NULL AND d.expires_at > now()
		 ORDER BY d.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RememberedDevice
	for rows.Next() {
		var d RememberedDevice
		if err := rows.Scan(&d.ID, &d.UserAgent, &d.CreatedAt, &d.ExpiresAt, &d.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ForgetDevices forgets one of userID's devices, or all of them when id is
// empty, and says how many.
func ForgetDevices(ctx context.Context, tx pgx.Tx, userID, id string) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE core.trusted_devices SET revoked_at = now()
		 WHERE user_id = $1::uuid AND revoked_at IS NULL
		   AND ($2 = '' OR id::text = $2)`, userID, id)
	if err != nil {
		return 0, fmt.Errorf("forgetting devices: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
