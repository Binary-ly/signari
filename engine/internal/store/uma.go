package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/uma"
)

// UMA permission tickets.
//
// §3.3.1: "Permission tickets MUST be single-use... The authorization server
// MUST invalidate a permission ticket when the client presents the permission
// ticket to either the token endpoint or the claims interaction endpoint, or
// when the permission ticket expires, whichever occurs first."
//
// Both halves are enforced in one statement, for the same reason authorization
// codes are: a read followed by an update is a window in which two concurrent
// redemptions both see an unredeemed ticket.

// ErrTicketUnknown means the ticket is unknown, expired, or already spent.
//
// One error for all three deliberately. §3.3.6 maps every one of them to
// invalid_grant -- "the provided permission ticket was not found at the
// authorization server, or the provided permission ticket has expired" -- so a
// finer taxonomy here would be distinguishing cases the protocol answers
// identically, while telling a caller whether a ticket it does not hold ever
// existed.
var ErrTicketUnknown = errors.New("permission ticket is not valid")

// Ticket is a redeemed permission ticket.
type Ticket struct {
	ID             string
	OrgID          string
	ResourceServer string
	Permissions    []uma.Permission
}

// CreatePermissionTicket records a ticket for a resource server's request.
func CreatePermissionTicket(ctx context.Context, db *pgxpool.Pool, orgID, resourceServer string,
	ticketHash []byte, permissions []uma.Permission, lifetime time.Duration) (string, error) {

	blob, err := json.Marshal(permissions)
	if err != nil {
		return "", err
	}
	var id string
	if err := db.QueryRow(ctx, `
		INSERT INTO core.uma_permission_tickets
			(org_id, resource_server, ticket_hash, permissions, expires_at)
		VALUES ($1::uuid, $2, $3, $4, now() + $5::interval)
		RETURNING id::text`,
		orgID, resourceServer, ticketHash, blob,
		fmt.Sprintf("%d seconds", int(lifetime.Seconds()))).Scan(&id); err != nil {
		return "", fmt.Errorf("recording a permission ticket: %w", err)
	}
	return id, nil
}

// RedeemPermissionTicket claims a ticket, once.
//
// The UPDATE is the read: `WHERE ... redeemed_at IS NULL AND expires_at > now()
// RETURNING` means the row is spent by the same statement that discovers it, so
// a second presentation finds nothing. Checking first and updating afterwards
// would let two requests through, which is precisely the session-fixation
// susceptibility §3.3.1 names.
func RedeemPermissionTicket(ctx context.Context, db *pgxpool.Pool, ticketHash []byte) (*Ticket, error) {
	var t Ticket
	var blob []byte
	err := db.QueryRow(ctx, `
		UPDATE core.uma_permission_tickets
		SET redeemed_at = now()
		WHERE ticket_hash = $1 AND redeemed_at IS NULL AND expires_at > now()
		RETURNING id::text, org_id::text, resource_server, permissions`,
		ticketHash).Scan(&t.ID, &t.OrgID, &t.ResourceServer, &blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTicketUnknown
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(blob, &t.Permissions); err != nil {
		return nil, fmt.Errorf("the stored permissions are not readable: %w", err)
	}
	return &t, nil
}

// PurgeExpiredPermissionTickets is the janitor's share.
//
// A redeemed ticket is kept until it would have expired anyway rather than
// deleted on redemption: within that window a replay can be recognised as a
// replay. After it, the row says nothing an expired ticket would not.
func PurgeExpiredPermissionTickets(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.uma_permission_tickets WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
