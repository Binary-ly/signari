package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oid4vci"
)

// What became of a credential after it left: where its bit is in a status list, whether
// that bit is set, and who it was issued to, which is what makes one revocable at all.

// ErrIssuedCredentialUnknown is a credential this organisation has no record of.
var ErrIssuedCredentialUnknown = errors.New("no issued credential by that id")

// IssuedCredential is one credential that can be revoked.
type IssuedCredential struct {
	ID, Configuration string
	// UserID and Email are empty once the person is gone.
	UserID, Email string
	IssuedAt      time.Time
	ExpiresAt     *time.Time
	RevokedAt     *time.Time
}

// AllocateCredentialStatus gives a credential about to be signed a place of its own,
// chosen at random in the list now filling. §12.5.1 recommends "non-sequential,
// pseudo-random or random indices", since a place handed out in order says how many came
// before it. userID is the person, and expiresAt nil when the credential has no exp.
func AllocateCredentialStatus(ctx context.Context, tx pgx.Tx, orgID, userID, configuration string,
	expiresAt *time.Time) (listID string, index int, err error) {

	err = tx.QueryRow(ctx, `
		UPDATE core.credential_status_lists
		   SET allocated = allocated + 1, full_up = allocated + 1 >= $2
		 WHERE id = (SELECT id FROM core.credential_status_lists
		              WHERE org_id = $1::uuid AND NOT full_up
		              ORDER BY org_id, full_up, created_at, id LIMIT 1 FOR UPDATE)
		RETURNING id::text`, orgID, oid4vci.StatusListFilledAt).Scan(&listID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `INSERT INTO core.credential_status_lists (org_id, allocated)
			VALUES ($1::uuid, 1) RETURNING id::text`, orgID).Scan(&listID)
	}
	if err != nil {
		return "", 0, fmt.Errorf("finding a status list: %w", err)
	}
	// A list stops at half, so each try finds a free place at least every other time.
	for range 64 {
		n, err := rand.Int(rand.Reader, big.NewInt(oid4vci.StatusListEntries))
		if err != nil {
			return "", 0, err
		}
		index = int(n.Int64())
		tag, err := tx.Exec(ctx, `
			INSERT INTO core.issued_credentials (org_id, user_id, configuration, list_id, idx, expires_at)
			VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6)
			ON CONFLICT (list_id, idx) DO NOTHING`, orgID, userID, configuration, listID, index, expiresAt)
		if err != nil {
			return "", 0, fmt.Errorf("recording the credential's place: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return listID, index, nil
		}
	}
	return "", 0, fmt.Errorf("no free place found in status list %s", listID)
}

// InvalidCredentialStatuses reads a list this instance serves: the places to set, and
// whether the list is here at all. Every place with nobody behind it is set, since a
// person deleted by any route takes their claim to the credential with them. Read per
// request, as every security-negative decision is (ADR-007).
func InvalidCredentialStatuses(ctx context.Context, q Querier, instanceID, listID string) ([]int, bool, error) {
	if _, err := uuid.Parse(listID); err != nil {
		return nil, false, nil
	}
	rows, err := q.Query(ctx, `
		SELECT c.idx FROM core.credential_status_lists l
		  LEFT JOIN core.issued_credentials c
		    ON c.list_id = l.id AND (c.revoked_at IS NOT NULL OR c.user_id IS NULL)
		 WHERE l.id = $1::uuid AND `+InInstance("l.org_id", "$2"), listID, instanceID)
	if err != nil {
		return nil, false, err
	}
	places, err := pgx.CollectRows(rows, pgx.RowTo[*int])
	if err != nil || len(places) == 0 {
		return nil, false, err
	}
	invalid := make([]int, 0, len(places))
	for _, place := range places {
		if place != nil {
			invalid = append(invalid, *place)
		}
	}
	return invalid, true, nil
}

// RevokeCredential takes one credential back, answering how many were still good.
func RevokeCredential(ctx context.Context, q outpostDB, orgID, credentialID string) (int64, error) {
	if _, err := uuid.Parse(credentialID); err != nil {
		return 0, ErrIssuedCredentialUnknown
	}
	var known bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.issued_credentials
		WHERE id = $1::uuid AND org_id = $2::uuid)`, credentialID, orgID).Scan(&known); err != nil {
		return 0, err
	}
	if !known {
		return 0, ErrIssuedCredentialUnknown
	}
	tag, err := q.Exec(ctx, `UPDATE core.issued_credentials SET revoked_at = now()
		WHERE id = $1::uuid AND org_id = $2::uuid AND revoked_at IS NULL`, credentialID, orgID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeCredentialsOf takes back everything a person holds.
func RevokeCredentialsOf(ctx context.Context, q outpostDB, orgID, userID string) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE core.issued_credentials SET revoked_at = now()
		WHERE user_id = $1::uuid AND org_id = $2::uuid AND revoked_at IS NULL`, userID, orgID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// IssuedCredentialsPage is a page of what an organisation has issued, or of what one
// person holds when userID is given, after the id `after`.
func IssuedCredentialsPage(ctx context.Context, q Querier, orgID, userID, after string, limit int) ([]IssuedCredential, error) {
	where, args := `c.org_id = $1::uuid`, []any{orgID, limit}
	order := `c.org_id, c.id`
	if userID != "" {
		args = append(args, userID)
		where += fmt.Sprintf(` AND c.user_id = $%d::uuid`, len(args))
		order = `c.user_id, c.id`
	}
	if after != "" {
		args = append(args, after)
		where += fmt.Sprintf(` AND c.id > $%d::uuid`, len(args))
	}
	rows, err := q.Query(ctx, `
		SELECT c.id::text, c.configuration, COALESCE(c.user_id::text, ''), COALESCE(u.email, ''),
		       c.issued_at, c.expires_at, c.revoked_at
		  FROM core.issued_credentials c
		  LEFT JOIN core.users u ON u.id = c.user_id
		 WHERE `+where+` ORDER BY `+order+` LIMIT $2`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (IssuedCredential, error) {
		var c IssuedCredential
		return c, row.Scan(&c.ID, &c.Configuration, &c.UserID, &c.Email, &c.IssuedAt, &c.ExpiresAt, &c.RevokedAt)
	})
}

// SweepCredentialStatusLists retires full lists whose every credential has expired,
// §13.1: "Once all Referenced Tokens are expired, the Issuer may stop serving the Status
// List Token." Only a full list, because one still filling hands out places, and its rows
// go with it, so no place is free to be handed out twice.
func SweepCredentialStatusLists(ctx context.Context, tx pgx.Tx, grace time.Duration, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.credential_status_lists WHERE id = ANY(ARRAY(
		SELECT l.id FROM core.credential_status_lists l
		 WHERE l.full_up AND NOT EXISTS (
		       SELECT 1 FROM core.issued_credentials c
		        WHERE c.list_id = l.id AND (c.expires_at IS NULL OR c.expires_at > now() - $1::interval))
		 LIMIT $2 FOR UPDATE SKIP LOCKED))`, grace.String(), limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
