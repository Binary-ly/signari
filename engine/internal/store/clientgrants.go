package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oauth"
)

// Grant Management (specs/grant-management.txt): what a person authorized a client to do,
// held under an identifier the client can come back to.

// ErrClientGrantUnknown is a grant that is not there, or not this caller's to know of.
var ErrClientGrantUnknown = errors.New("no such grant")

// ClientGrant is one grant.
type ClientGrant struct {
	ID, ClientID, UserID, OrgID string
	Scopes, Resources           []string
	Details                     json.RawMessage
	CreatedAt, UpdatedAt        time.Time
}

// ClientGrantHeld says whether a grant is this client's for this person, §5.4's condition
// for naming one in a request.
func ClientGrantHeld(ctx context.Context, q outpostDB, grantID, clientID, userID string) (bool, error) {
	var held bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.client_grants
		WHERE grant_id = $1 AND client_id = $2 AND user_id = $3::uuid)`, grantID, clientID, userID).Scan(&held)
	return held, err
}

// SettleClientGrant applies what an authorization request asked of a grant, now that its
// tokens are being claimed (§5.6.1), and leaves on code what those tokens are to carry. A
// merge or replace ends the tokens issued under the grant before: §5.2 has the refresh
// tokens invalidated, and the access tokens go with their lineage (§10).
func SettleClientGrant(ctx context.Context, tx pgx.Tx, code *ConsumedCode) (string, error) {
	switch code.GrantAction {
	case oauth.GrantActionCreate:
		id, err := newGrantID()
		if err != nil {
			return "", err
		}
		_, err = tx.Exec(ctx, `INSERT INTO core.client_grants (grant_id, org_id, client_id, user_id, scopes, resources, authorization_details)
			VALUES ($1, $2::uuid, $3, $4::uuid, $5, $6, $7)`, id, code.OrgID, code.ClientID, code.UserID,
			nonNil(code.Scopes), nonNil(code.Resources), code.Details)
		return id, err
	case oauth.GrantActionMerge:
		var scopes, resources []string
		var details []byte
		err := tx.QueryRow(ctx, `SELECT scopes, resources, authorization_details FROM core.client_grants
			WHERE grant_id = $1 AND client_id = $2 AND user_id = $3::uuid FOR UPDATE`,
			code.GrantID, code.ClientID, code.UserID).Scan(&scopes, &resources, &details)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrClientGrantUnknown
		}
		if err != nil {
			return "", err
		}
		code.Scopes = union(scopes, code.Scopes)
		code.Resources = union(resources, code.Resources)
		if code.Details, err = mergeDetails(details, code.Details); err != nil {
			return "", err
		}
	case oauth.GrantActionReplace:
	default:
		return "", fmt.Errorf("grant management action %q", code.GrantAction)
	}
	tag, err := tx.Exec(ctx, `UPDATE core.client_grants
		SET scopes = $4, resources = $5, authorization_details = $6, updated_at = now()
		WHERE grant_id = $1 AND client_id = $2 AND user_id = $3::uuid`, code.GrantID, code.ClientID, code.UserID,
		nonNil(code.Scopes), nonNil(code.Resources), code.Details)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrClientGrantUnknown
	}
	return code.GrantID, endGrantLineages(ctx, tx, code.GrantID)
}

// AttachFamilyToGrant puts a lineage under a grant, for revoking it to reach.
func AttachFamilyToGrant(ctx context.Context, tx pgx.Tx, familyID, grantID string) error {
	_, err := tx.Exec(ctx, `UPDATE core.refresh_token_families SET client_grant = $2 WHERE id = $1::uuid`, familyID, grantID)
	return err
}

// ClientGrantOf reads a grant for the client that holds it. Anybody else's is as unknown
// as one that does not exist.
func ClientGrantOf(ctx context.Context, q outpostDB, grantID, clientID string) (*ClientGrant, error) {
	g := ClientGrant{ID: grantID, ClientID: clientID}
	err := q.QueryRow(ctx, `SELECT user_id::text, scopes, resources, authorization_details, created_at, updated_at
		FROM core.client_grants WHERE grant_id = $1 AND client_id = $2`, grantID, clientID).
		Scan(&g.UserID, &g.Scopes, &g.Resources, &g.Details, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientGrantUnknown
	}
	return &g, err
}

// RevokeClientGrant ends a grant and everything issued under it, §6.5: "MUST revoke the
// grant and all refresh tokens issued based on that particular grant", and it "should
// revoke all access tokens", which go with their lineage.
func RevokeClientGrant(ctx context.Context, tx pgx.Tx, grantID, clientID string) (*ClientGrant, error) {
	g := ClientGrant{ID: grantID, ClientID: clientID}
	err := tx.QueryRow(ctx, `DELETE FROM core.client_grants WHERE grant_id = $1 AND client_id = $2
		RETURNING user_id::text, org_id::text`, grantID, clientID).Scan(&g.UserID, &g.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientGrantUnknown
	}
	if err != nil {
		return nil, err
	}
	return &g, endGrantLineages(ctx, tx, grantID)
}

func endGrantLineages(ctx context.Context, tx pgx.Tx, grantID string) error {
	_, err := tx.Exec(ctx, `UPDATE core.refresh_token_families SET revoked_at = now(), revocation_reason = 'grant_changed'
		WHERE client_grant = $1 AND revoked_at IS NULL`, grantID)
	return err
}

// SweepClientGrants removes grants nothing has touched in a long while and that no token
// still stands on (§5.6.3).
func SweepClientGrants(ctx context.Context, tx pgx.Tx, age time.Duration, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.client_grants WHERE grant_id = ANY(ARRAY(
		SELECT g.grant_id FROM core.client_grants g
		 WHERE g.updated_at < now() - $1::interval
		   AND NOT EXISTS (SELECT 1 FROM core.refresh_token_families f
		                    WHERE f.client_grant = g.grant_id AND f.revoked_at IS NULL)
		 LIMIT $2 FOR UPDATE SKIP LOCKED))`, age.String(), limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func newGrantID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// mergeDetails appends the new details to the old, leaving any already there as they are.
func mergeDetails(held, added []byte) ([]byte, error) {
	if len(held) == 0 {
		return added, nil
	}
	if len(added) == 0 {
		return held, nil
	}
	var old, more []json.RawMessage
	if err := json.Unmarshal(held, &old); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(added, &more); err != nil {
		return nil, err
	}
	for _, detail := range more {
		if !slices.ContainsFunc(old, func(have json.RawMessage) bool { return string(have) == string(detail) }) {
			old = append(old, detail)
		}
	}
	return json.Marshal(old)
}
