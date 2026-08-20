package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Storage for CIBA backchannel authentication requests.
//
// A CIBA request lives in core.device_authorizations with flow = 'ciba'. The
// argument for that is in migration 0088 and worth repeating in one line: CIBA
// §11 and RFC 8628 §3.5 specify the same polling discipline in the same words,
// so PollDeviceCode is the CIBA polling implementation too, and there is no
// second copy of it to drift.
//
// What lives here is the part that differs: creating a request that already
// knows its subject, and finding the requests waiting for a given person.

// ErrCIBASubjectUnknown means no account matched the hint.
//
// §13 gives this its own error code, unknown_user_id, which the endpoint returns
// -- so the hint that identifies nobody is distinguishable from the hint that is
// malformed.
var ErrCIBASubjectUnknown = errors.New("no user matched the hint")

// CIBAPending is a backchannel request awaiting someone's decision.
type CIBAPending struct {
	ID             string
	ClientID       string
	ClientName     string
	Scope          string
	BindingMessage string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// ResolveCIBASubject finds the account a login_hint names.
//
// Matches the same two columns the sign-in form does, and for the same reason:
// a deployment that lets people sign in by username must let a client name them
// by username, or the hint that works at the login box fails here.
//
// Only ACTIVE users. A deactivated account must not be reachable by a
// backchannel prompt -- that would be a way to push an approval request at
// somebody whose access was removed, and if they still hold the device they
// could approve it.
func ResolveCIBASubject(ctx context.Context, db *pgxpool.Pool, orgID, hint string) (string, error) {
	var userID string
	err := db.QueryRow(ctx, `
		SELECT id::text FROM core.users
		WHERE org_id = $1::uuid AND status = 'active'
		  AND (lower(email) = lower($2) OR lower(username) = lower($2))`,
		orgID, hint).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrCIBASubjectUnknown
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

// CreateBackchannelAuthentication records a CIBA request awaiting approval.
//
// userID is set NOW, while the request is still pending, which is the structural
// difference from a device authorization: the client said who it wants, we
// resolved them, and only that person's approval can complete it. The
// ciba_names_its_subject constraint in migration 0088 makes that a property of
// the schema rather than of this function.
func CreateBackchannelAuthentication(ctx context.Context, db *pgxpool.Pool,
	orgID, clientID, userID, scope, bindingMessage string, acr []string,
	authReqHash []byte, interval int, lifetime time.Duration) (string, error) {

	// A nil slice marshals to SQL NULL, not to an empty array, so the column's
	// DEFAULT '{}' never applies and the NOT NULL fires. Normalised here rather
	// than at the caller: every caller would otherwise have to know this, and
	// the one that forgot would fail only when it had no acr_values to pass --
	// which is the common case.
	if acr == nil {
		acr = []string{}
	}

	var id string
	err := db.QueryRow(ctx, `
		INSERT INTO core.device_authorizations
			(org_id, client_id, user_id, scope, device_code_hash, user_code_hash,
			 flow, binding_message, requested_acr, interval_s, expires_at)
		VALUES ($1::uuid, $2, $3::uuid, $4, $5, NULL,
		        'ciba', NULLIF($6,''), $7, $8, now() + $9::interval)
		RETURNING id::text`,
		orgID, clientID, userID, scope, authReqHash, bindingMessage, acr, interval,
		fmt.Sprintf("%d seconds", int(lifetime.Seconds()))).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("recording a backchannel authentication: %w", err)
	}
	return id, nil
}

// PendingBackchannelFor lists the requests waiting on one person.
//
// Scoped to the user AND to pending AND to unexpired, in the query. Anything
// looser would be a screen on which somebody can approve a request that is not
// theirs, and the filter is the only thing standing between those two states.
func PendingBackchannelFor(ctx context.Context, db *pgxpool.Pool, userID string) ([]CIBAPending, error) {
	rows, err := db.Query(ctx, `
		SELECT d.id::text, d.client_id, COALESCE(c.display_name, d.client_id),
		       d.scope, COALESCE(d.binding_message, ''), d.expires_at, d.created_at
		FROM core.device_authorizations d
		LEFT JOIN core.clients c ON c.client_id = d.client_id
		WHERE d.flow = 'ciba' AND d.user_id = $1::uuid
		  AND d.status = 'pending' AND d.expires_at > now()
		ORDER BY d.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CIBAPending
	for rows.Next() {
		var p CIBAPending
		if err := rows.Scan(&p.ID, &p.ClientID, &p.ClientName, &p.Scope,
			&p.BindingMessage, &p.ExpiresAt, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DecideBackchannel records one person's answer to one request.
//
// The user id is part of the WHERE clause, not checked by the caller
// beforehand. That is the whole safety property of this function: a request
// belonging to somebody else does not match, so it cannot be approved by the
// wrong person even if the id reached them -- and the same statement checks
// pending and unexpired, so a decision cannot be revised or arrive late.
func DecideBackchannel(ctx context.Context, db *pgxpool.Pool, id, userID, sid string,
	approve bool) error {

	status := "denied"
	if approve {
		status = "approved"
	}
	tag, err := db.Exec(ctx, `
		UPDATE core.device_authorizations
		SET status = $4, sid = $3
		WHERE id = $1::uuid AND user_id = $2::uuid AND flow = 'ciba'
		  AND status = 'pending' AND expires_at > now()`,
		id, userID, sid, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Not theirs, already decided, or expired while the page was open.
		return ErrDeviceCodeUnknown
	}
	return nil
}
