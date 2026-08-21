package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Device authorization grant storage, RFC 8628.

var (
	// ErrDeviceCodeUnknown covers "no such code" and "expired" together. The two
	// are deliberately indistinguishable at the polling endpoint: telling a
	// caller their code was once real narrows a guess.
	ErrDeviceCodeUnknown = errors.New("device code not recognised")
	// ErrDeviceCodePending is the normal answer while the person has not acted.
	ErrDeviceCodePending = errors.New("authorization_pending")
	// ErrDeviceCodeDenied means they said no.
	ErrDeviceCodeDenied = errors.New("access_denied")
	// ErrDeviceCodeSlowDown means the device polled faster than its interval.
	ErrDeviceCodeSlowDown = errors.New("slow_down")
	// ErrDeviceCodeSessionGone is an approval whose session ended before the
	// client polled. Distinct from expiry and from denial: the person did
	// approve, and something afterwards took that authority away.
	ErrDeviceCodeSessionGone = errors.New("the session behind this approval has ended")
)

// DeviceAuthorization is a pending or completed device grant.
type DeviceAuthorization struct {
	ID        string
	OrgID     string
	ClientID  string
	Scope     string
	Resource  []string
	Status    string
	UserID    string
	SID       string
	Interval  int
	ExpiresAt time.Time
}

// CreateDeviceAuthorization records a new request and returns its id.
func CreateDeviceAuthorization(ctx context.Context, db *pgxpool.Pool, orgID, clientID,
	scope string, resource []string, deviceHash, userHash []byte, interval int,
	lifetime time.Duration) (string, error) {

	// See CreateBackchannelAuthentication: a nil slice is SQL NULL, which the
	// NOT NULL on `resource` rejects rather than defaulting. A caller with no
	// resource indicators is the ordinary case and must not have to know that.
	if resource == nil {
		resource = []string{}
	}

	var id string
	err := db.QueryRow(ctx, `
		INSERT INTO core.device_authorizations
			(org_id, client_id, scope, resource, device_code_hash, user_code_hash,
			 interval_s, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, now() + $8::interval)
		RETURNING id::text`,
		orgID, clientID, scope, resource, deviceHash, userHash, interval,
		fmt.Sprintf("%d seconds", int(lifetime.Seconds()))).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("recording a device authorization: %w", err)
	}
	return id, nil
}

// LookupUserCode finds a pending request by the code a person typed.
//
// Expiry is part of the WHERE clause rather than a check afterwards, so an
// expired record is simply not found and cannot be approved by a slow browser.
func LookupUserCode(ctx context.Context, db *pgxpool.Pool, userHash []byte) (*DeviceAuthorization, error) {
	d := &DeviceAuthorization{}
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, client_id, scope, resource, status, interval_s, expires_at
		FROM core.device_authorizations
		WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > now()`,
		userHash).Scan(&d.ID, &d.OrgID, &d.ClientID, &d.Scope, &d.Resource, &d.Status,
		&d.Interval, &d.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceCodeUnknown
		}
		return nil, err
	}
	return d, nil
}

// ApproveDeviceAuthorization records that a person allowed the device.
func ApproveDeviceAuthorization(ctx context.Context, db *pgxpool.Pool, id, userID, sid string) error {
	tag, err := db.Exec(ctx, `
		UPDATE core.device_authorizations
		SET status = 'approved', user_id = $2::uuid, sid = $3
		WHERE id = $1::uuid AND status = 'pending' AND expires_at > now()`,
		id, userID, sid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Already decided, or expired between the screen rendering and the click.
		return ErrDeviceCodeUnknown
	}
	return nil
}

// DenyDeviceAuthorization records a refusal.
func DenyDeviceAuthorization(ctx context.Context, db *pgxpool.Pool, id string) error {
	_, err := db.Exec(ctx, `
		UPDATE core.device_authorizations SET status = 'denied'
		WHERE id = $1::uuid AND status = 'pending'`, id)
	return err
}

// ErrDeviceCodeWrongClient means the code was issued to a different client.
var ErrDeviceCodeWrongClient = errors.New("device code belongs to another client")

// PollDeviceCode is what the device calls, repeatedly.
//
// Returns the authorization only when it is approved and unredeemed, and marks
// it redeemed in the same statement so a replayed device_code gets nothing.
//
// clientID is checked INSIDE this transaction, before anything is consumed. It
// was originally checked by the caller afterwards, which meant a party holding a
// leaked device code could present any client id, have the approval marked
// redeemed, and only then be rejected -- burning a legitimate approval and
// leaving the real device stuck on expired_token forever. The check has to
// happen before the state changes, not after.
//
// flow selects which specification's rows are eligible: "device" for RFC 8628,
// "ciba" for CIBA Core 1.0. Both store their secret in device_code_hash, so
// WITHOUT this filter a device_code would be redeemable through the CIBA grant
// and an auth_req_id through the device grant. Nothing terrible follows from
// that -- the client, user and scope are the same either way -- but it is grant
// confusion, and the fix is one WHERE clause rather than an argument about
// whether it matters.
func PollDeviceCode(ctx context.Context, db *pgxpool.Pool, deviceHash []byte,
	clientID, flow string) (*DeviceAuthorization, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	d := &DeviceAuthorization{}
	var lastPolled *time.Time
	var redeemed *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id::text, org_id::text, client_id, scope, resource, status,
		       COALESCE(user_id::text,''), COALESCE(sid,''), interval_s,
		       expires_at, last_polled_at, redeemed_at
		FROM core.device_authorizations
		WHERE device_code_hash = $1 AND flow = $2
		FOR UPDATE`, deviceHash, flow).
		Scan(&d.ID, &d.OrgID, &d.ClientID, &d.Scope, &d.Resource, &d.Status,
			&d.UserID, &d.SID, &d.Interval, &d.ExpiresAt, &lastPolled, &redeemed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceCodeUnknown
		}
		return nil, err
	}

	// Whose code this is, before any state moves.
	if d.ClientID != clientID {
		return nil, ErrDeviceCodeWrongClient
	}

	// Expiry next: an expired approval is not an approval.
	if time.Now().After(d.ExpiresAt) {
		return nil, ErrDeviceCodeUnknown
	}
	if redeemed != nil {
		// Single use. A second poll with the same device code is either a broken
		// client or a stolen one, and neither should receive tokens twice.
		return nil, ErrDeviceCodeUnknown
	}

	// Polling discipline. Checked BEFORE the status so a device that hammers the
	// endpoint is slowed whether or not the person has approved yet -- otherwise
	// the rule would only apply to the boring case.
	if lastPolled != nil && time.Since(*lastPolled) < time.Duration(d.Interval)*time.Second {
		// RFC 8628 §3.5: each slow_down adds 5 seconds to the client's interval.
		// Persisted so the requirement is real rather than a suggestion the
		// client is free to ignore.
		if _, err := tx.Exec(ctx, `
			UPDATE core.device_authorizations
			SET last_polled_at = now(), interval_s = interval_s + 5
			WHERE id = $1::uuid`, d.ID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrDeviceCodeSlowDown
	}

	if _, err := tx.Exec(ctx,
		`UPDATE core.device_authorizations SET last_polled_at = now() WHERE id = $1::uuid`,
		d.ID); err != nil {
		return nil, err
	}

	switch d.Status {
	case "pending":
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrDeviceCodePending
	case "denied":
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrDeviceCodeDenied
	}

	var live bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM core.sessions
			WHERE sid = $1 AND revoked_at IS NULL AND not_after > now())`,
		d.SID).Scan(&live); err != nil {
		return nil, err
	}
	if !live {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrDeviceCodeSessionGone
	}

	// Approved. Mark redeemed in the same transaction that hands it over.
	if _, err := tx.Exec(ctx,
		`UPDATE core.device_authorizations SET redeemed_at = now() WHERE id = $1::uuid`,
		d.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// PurgeExpiredDeviceCodes removes dead records. Called by the janitor.
//
// Takes a transaction rather than the pool so it joins the janitor's single
// advisory-locked pass, like every other sweep.
func PurgeExpiredDeviceCodes(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM core.device_authorizations
		WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
