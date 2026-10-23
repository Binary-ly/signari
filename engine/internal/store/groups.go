package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GroupsForUser returns the group names a user belongs to, filtered by what a
// client is allowed to see.
//
// # Read at issuance, every time
//
// Never cached on the session and never carried in a cookie. A session
// established this morning must not still be minting tokens claiming a group
// somebody was removed from at lunchtime -- and the only way to guarantee that
// is to ask the database at the moment the claim is written.
//
// It costs one indexed query per token. That is the correct price for a value
// downstream software makes access decisions on.
//
// db is a pool or the caller's transaction. Token minting passes its
// transaction: reading from the pool while holding one takes a second
// connection, and enough concurrent redemptions each waiting for theirs leave
// the pool with no connection to give any of them.
func GroupsForUser(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, userID, clientID string) ([]string, error) {
	// Release is an ALLOW-LIST. A client with no row gets nothing, which is what
	// makes "add a client" a decision that does not silently disclose the
	// organisation's internal structure.
	var onlyGroups []string
	var released bool
	err := db.QueryRow(ctx, `
		SELECT only_groups, true FROM core.client_group_release WHERE client_id = $1`,
		clientID).Scan(&onlyGroups, &released)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the group release policy: %w", err)
	}

	rows, err := db.Query(ctx, `
		SELECT g.name
		FROM core.group_members m
		JOIN core.groups g ON g.id = m.group_id
		WHERE m.user_id = $1::uuid
		  AND (cardinality($2::text[]) = 0 OR g.name = ANY($2::text[]))
		ORDER BY g.name`, userID, onlyGroups)
	if err != nil {
		return nil, fmt.Errorf("reading group membership: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GroupsForSAML returns the groups released to a SAML provider, and the
// attribute name to publish them under.
func GroupsForSAML(ctx context.Context, tx pgx.Tx, userID, providerID string) (attr string, groups []string, err error) {
	var only []string
	err = tx.QueryRow(ctx, `
		SELECT attribute_name, only_groups FROM core.saml_group_release
		WHERE provider_id = $1::uuid`, providerID).Scan(&attr, &only)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil, nil
		}
		return "", nil, err
	}

	rows, qerr := tx.Query(ctx, `
		SELECT g.name
		FROM core.group_members m
		JOIN core.groups g ON g.id = m.group_id
		WHERE m.user_id = $1::uuid
		  AND (cardinality($2::text[]) = 0 OR g.name = ANY($2::text[]))
		ORDER BY g.name`, userID, only)
	if qerr != nil {
		return "", nil, qerr
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return "", nil, err
		}
		groups = append(groups, n)
	}
	return attr, groups, rows.Err()
}

// AllGroupsForUser returns every group a user is in, ignoring release policy.
//
// For the account page and the admin API only. Deliberately a different
// function from GroupsForUser so that a caller reaching for "the user's groups"
// on a token path cannot get the unfiltered set by accident.
func AllGroupsForUser(ctx context.Context, db interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, userID string) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT g.name FROM core.group_members m
		JOIN core.groups g ON g.id = m.group_id
		WHERE m.user_id = $1::uuid ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GroupIDNamed returns the id of the organisation's group of that name, or ""
// when it has none.
func GroupIDNamed(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, name string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		orgID, name).Scan(&id)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return id, err
}

// GroupMayImpersonate reports whether the organisation's group of that name
// lets its members impersonate others; false for no such group.
func GroupMayImpersonate(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, name string) (bool, error) {
	var may bool
	err := q.QueryRow(ctx, `SELECT may_impersonate FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		orgID, name).Scan(&may)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return may, err
}

// CreateGroup adds a group.
func CreateGroup(ctx context.Context, conn *pgx.Conn, orgID, name, displayName, description string) (string, error) {
	if displayName == "" {
		displayName = name
	}
	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO core.groups (org_id, name, display_name, description)
		VALUES ($1::uuid, $2, $3, NULLIF($4,''))
		RETURNING id::text`, orgID, name, displayName, description).Scan(&id)
	return id, err
}

// AddGroupMember puts a user in a group.
func AddGroupMember(ctx context.Context, conn *pgx.Conn, orgID, groupName, userID, addedBy string) error {
	tag, err := conn.Exec(ctx, `
		INSERT INTO core.group_members (group_id, user_id, org_id, added_by)
		SELECT g.id, $3::uuid, $1::uuid, NULLIF($4,'')::uuid
		FROM core.groups g WHERE g.org_id = $1::uuid AND g.name = $2
		ON CONFLICT (group_id, user_id) DO NOTHING`,
		orgID, groupName, userID, addedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Distinguishing "already a member" from "no such group" matters: the
		// first is fine and the second means the operator's intended grant did
		// not happen, silently.
		var exists bool
		if err := conn.QueryRow(ctx, `
			SELECT true FROM core.group_members m
			JOIN core.groups g ON g.id = m.group_id
			WHERE g.org_id = $1::uuid AND g.name = $2 AND m.user_id = $3::uuid`,
			orgID, groupName, userID).Scan(&exists); err != nil {
			return fmt.Errorf("no group named %q in that organisation", groupName)
		}
	}
	return nil
}

// RemoveGroupMember takes a user out of a group.
func RemoveGroupMember(ctx context.Context, conn *pgx.Conn, orgID, groupName, userID string) (bool, error) {
	tag, err := conn.Exec(ctx, `
		DELETE FROM core.group_members m
		USING core.groups g
		WHERE m.group_id = g.id AND g.org_id = $1::uuid AND g.name = $2
		  AND m.user_id = $3::uuid`, orgID, groupName, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ErrReleaseClientUnknown is a client the organisation does not have, so its
// group release is not the organisation's to set.
var ErrReleaseClientUnknown = errors.New("no client of that id in the organisation")

// ErrReleaseGroupUnknown is a group named in a release that the organisation
// does not have: released, it would release nothing, silently.
var ErrReleaseGroupUnknown = errors.New("no group of that name in the organisation")

// ReleaseGroupsToClient records that a client may see group membership: of
// only those groups, or of every group when only is empty. conn is the
// command's connection or the Admin API's transaction.
//
// The client must be the organisation's, and each group too (0.42). The row is
// keyed by client id alone, so the command, given another organisation's
// client, wrote that client's release under this organisation's id.
func ReleaseGroupsToClient(ctx context.Context, conn outpostDB, orgID, clientID string, only []string) error {
	var ours bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1 AND org_id = $2::uuid)`,
		clientID, orgID).Scan(&ours); err != nil {
		return err
	}
	if !ours {
		return ErrReleaseClientUnknown
	}
	for _, g := range only {
		id, err := GroupIDNamed(ctx, conn, orgID, g)
		if err != nil {
			return err
		}
		if id == "" {
			return fmt.Errorf("%w: %q", ErrReleaseGroupUnknown, g)
		}
	}
	// A nil slice encodes as SQL NULL, not as an empty array, and the column is
	// NOT NULL -- so "release every group" (the nil case) failed outright while
	// "release these two" worked. The empty array is the meaningful value here:
	// it is what the query reads as "no filter".
	if only == nil {
		only = []string{}
	}
	_, err := conn.Exec(ctx, `
		INSERT INTO core.client_group_release (client_id, org_id, only_groups)
		VALUES ($1, $2::uuid, $3)
		ON CONFLICT (client_id) DO UPDATE SET only_groups = EXCLUDED.only_groups`,
		clientID, orgID, only)
	return err
}

// GroupReleaseOf is what a client is told of group membership: released false
// for nothing, and otherwise the groups, every one when only is empty.
func GroupReleaseOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (only []string, released bool, err error) {
	err = q.QueryRow(ctx, `SELECT only_groups FROM core.client_group_release WHERE client_id = $1`,
		clientID).Scan(&only)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading the group release: %w", err)
	}
	return only, true, nil
}

// StopGroupRelease tells a client of no group membership from its next token,
// reporting whether it was told of any.
func StopGroupRelease(ctx context.Context, tx Execer, clientID string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.client_group_release WHERE client_id = $1`, clientID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
