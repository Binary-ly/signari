package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/scim"
)

// SCIM /Groups as a provisioning source.
//
// The users half has existed since migration 0049. This is the half an
// enterprise actually connects SCIM for: the users would arrive on first sign-in
// anyway, but "who is in Engineering" is what authorization rules read, and it
// is what did not arrive.

// SCIMGroup is one provisioned group.
type SCIMGroup struct {
	ResourceID  string
	ExternalID  string
	GroupID     string
	Name        string
	DisplayName string
	Members     []SCIMGroupMember
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SCIMGroupMember is one membership, named by the ids the upstream knows.
type SCIMGroupMember struct {
	// ResourceID is the /Users resource id, which is what a member's `value`
	// carries -- NOT the internal user id. An upstream only ever learned the
	// resource id, so answering with anything else makes every membership it
	// reads back look like one it did not create.
	ResourceID  string
	DisplayName string
}

func UpsertSCIMGroup(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	externalID, displayName string, memberResourceIDs []string) (SCIMGroup, error) {

	var out SCIMGroup
	name, err := scim.GroupNameFrom(displayName)
	if err != nil {
		return out, err
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Already linked? Then this is an update, and the local group is whichever
	// one the link already points at -- not whatever the derived name resolves
	// to now, because the name changes when the upstream renames the group.
	var groupID, resourceID string
	err = tx.QueryRow(ctx, `
		SELECT group_id::text, resource_id::text
		FROM core.scim_source_group_links
		WHERE source_id = $1::uuid AND external_id = $2`,
		src.ID, externalID).Scan(&groupID, &resourceID)

	switch {
	case err == nil:
		// Rename in place. core.groups.name is what tokens carry, so changing it
		// changes what every downstream application matches on -- but leaving it
		// stale means the console shows a name nobody uses. The upstream is the
		// system of record for a group it provisioned, so it wins.
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.groups SET name = $2, display_name = $3, updated_at = now()
			WHERE id = $1::uuid`, groupID, name, displayName); uerr != nil {
			return out, groupUniquenessError(uerr, name, displayName)
		}
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.scim_source_group_links
			SET display_name = $3, updated_at = now()
			WHERE source_id = $1::uuid AND external_id = $2`,
			src.ID, externalID, displayName); uerr != nil {
			return out, uerr
		}

	case errors.Is(err, pgx.ErrNoRows):
		err = tx.QueryRow(ctx, `
			INSERT INTO core.groups (org_id, name, display_name)
			VALUES ($1::uuid, $2, $3)
			ON CONFLICT (org_id, name) DO UPDATE SET display_name = EXCLUDED.display_name
			RETURNING id::text`, src.OrgID, name, displayName).Scan(&groupID)
		if err != nil {
			return out, groupUniquenessError(err, name, displayName)
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO core.scim_source_group_links
				(source_id, external_id, group_id, display_name)
			VALUES ($1::uuid, $2, $3::uuid, $4)
			RETURNING resource_id::text`,
			src.ID, externalID, groupID, displayName).Scan(&resourceID)
		if err != nil {
			return out, groupUniquenessError(err, name, displayName)
		}

	default:
		return out, err
	}

	// Members, when the caller supplied a list. A create with no `members` is
	// not the same as one with an empty list: the first says nothing about
	// membership, the second says there is none.
	if memberResourceIDs != nil {
		if err := replaceMembersTx(ctx, tx, src, groupID, memberResourceIDs); err != nil {
			return out, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return GetSCIMGroup(ctx, db, src, resourceID)
}

// groupUniquenessError turns a constraint violation into a 409-able error.
func groupUniquenessError(err error, name, displayName string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "groups_name_shape"):
		return fmt.Errorf("the display name %q derives the group name %q, which is "+
			"not a usable group name", displayName, name)
	case strings.Contains(msg, "duplicate key"), strings.Contains(msg, "unique constraint"):
		return &SCIMConflictError{Detail: fmt.Sprintf(
			"a group named %q already exists and belongs to a different upstream "+
				"record; two sources cannot both own one group", name)}
	}
	return err
}

// replaceMembersTx sets the membership to exactly the given resource ids.
func replaceMembersTx(ctx context.Context, tx pgx.Tx, src *SCIMSource,
	groupID string, resourceIDs []string) error {

	userIDs, err := usersForResourceIDs(ctx, tx, src, resourceIDs)
	if err != nil {
		return err
	}
	// Deleted first, then inserted, in one transaction. Doing it the other way
	// round would briefly grant everybody in the new list membership alongside
	// everybody in the old one -- and "briefly" is long enough for a token
	// request that happens to land in the middle.
	if _, err := tx.Exec(ctx,
		`DELETE FROM core.group_members WHERE group_id = $1::uuid`, groupID); err != nil {
		return err
	}
	for _, uid := range userIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.group_members (group_id, user_id, org_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid)
			ON CONFLICT DO NOTHING`, groupID, uid, src.OrgID); err != nil {
			return err
		}
	}
	return nil
}

// usersForResourceIDs maps /Users resource ids to local user ids.
//
// A member naming a resource id this source does not know is an ERROR, not a
// skipped row. Skipping would answer 200 to a membership change that did not
// happen, and the upstream would never send it again -- the same silent-success
// failure the PATCH parser exists to prevent.
func usersForResourceIDs(ctx context.Context, tx pgx.Tx, src *SCIMSource,
	resourceIDs []string) ([]string, error) {

	out := make([]string, 0, len(resourceIDs))
	for _, rid := range resourceIDs {
		var userID string
		err := tx.QueryRow(ctx, `
			SELECT user_id::text FROM core.scim_source_links
			WHERE source_id = $1::uuid AND resource_id::text = $2`,
			src.ID, rid).Scan(&userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("member %q is not a user provisioned by this "+
					"source, so the membership cannot be recorded; provision the user "+
					"before adding them to a group", rid)
			}
			return nil, err
		}
		out = append(out, userID)
	}
	return out, nil
}

// GetSCIMGroup reads one group by its SCIM resource id.
func GetSCIMGroup(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string) (SCIMGroup, error) {

	var g SCIMGroup
	err := db.QueryRow(ctx, `
		SELECT l.resource_id::text, l.external_id, l.group_id::text,
		       g.name, l.display_name, l.created_at, l.updated_at
		FROM core.scim_source_group_links l
		JOIN core.groups g ON g.id = l.group_id
		WHERE l.source_id = $1::uuid AND l.resource_id::text = $2`,
		src.ID, resourceID).
		Scan(&g.ResourceID, &g.ExternalID, &g.GroupID, &g.Name, &g.DisplayName,
			&g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return g, err
	}
	g.Members, err = membersOf(ctx, db, src, g.GroupID)
	return g, err
}

// membersOf lists a group's members as the upstream knows them.
//
// Joined through scim_source_links, so a member added in the CONSOLE rather than
// provisioned does not appear. That is correct rather than lossy: the upstream
// asked what it provisioned, and reporting a member it has no resource id for
// would have it try to reconcile an identifier that means nothing to it.
func membersOf(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	groupID string) ([]SCIMGroupMember, error) {

	rows, err := db.Query(ctx, `
		SELECT sl.resource_id::text, COALESCE(sl.user_name, '')
		FROM core.group_members gm
		JOIN core.scim_source_links sl
		  ON sl.user_id = gm.user_id AND sl.source_id = $1::uuid
		WHERE gm.group_id = $2::uuid
		ORDER BY sl.user_name`, src.ID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SCIMGroupMember{}
	for rows.Next() {
		var m SCIMGroupMember
		if err := rows.Scan(&m.ResourceID, &m.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListSCIMGroups pages through the groups this source provisioned.
func ListSCIMGroups(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	displayName string, start, count int) ([]SCIMGroup, int, error) {

	var total int
	if err := db.QueryRow(ctx, `
		SELECT count(*) FROM core.scim_source_group_links
		WHERE source_id = $1::uuid AND ($2 = '' OR display_name = $2)`,
		src.ID, displayName).Scan(&total); err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return []SCIMGroup{}, total, nil
	}

	rows, err := db.Query(ctx, `
		SELECT l.resource_id::text, l.external_id, l.group_id::text,
		       g.name, l.display_name, l.created_at, l.updated_at
		FROM core.scim_source_group_links l
		JOIN core.groups g ON g.id = l.group_id
		WHERE l.source_id = $1::uuid AND ($2 = '' OR l.display_name = $2)
		ORDER BY l.created_at, l.external_id
		OFFSET $3 LIMIT $4`, src.ID, displayName, start-1, count)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []SCIMGroup{}
	for rows.Next() {
		var g SCIMGroup
		if err := rows.Scan(&g.ResourceID, &g.ExternalID, &g.GroupID, &g.Name,
			&g.DisplayName, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	for i := range out {
		m, err := membersOf(ctx, db, src, out[i].GroupID)
		if err != nil {
			return nil, 0, err
		}
		out[i].Members = m
	}
	return out, total, nil
}

// PatchSCIMGroup applies a parsed PATCH.
func PatchSCIMGroup(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string, p *scim.GroupPatch) (SCIMGroup, error) {

	var out SCIMGroup
	tx, err := db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var groupID string
	if err := tx.QueryRow(ctx, `
		SELECT group_id::text FROM core.scim_source_group_links
		WHERE source_id = $1::uuid AND resource_id::text = $2`,
		src.ID, resourceID).Scan(&groupID); err != nil {
		return out, err
	}

	if p.DisplayName != nil {
		name, nerr := scim.GroupNameFrom(*p.DisplayName)
		if nerr != nil {
			return out, nerr
		}
		if _, err := tx.Exec(ctx, `
			UPDATE core.groups SET name = $2, display_name = $3, updated_at = now()
			WHERE id = $1::uuid`, groupID, name, *p.DisplayName); err != nil {
			return out, groupUniquenessError(err, name, *p.DisplayName)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE core.scim_source_group_links SET display_name = $3, updated_at = now()
			WHERE source_id = $1::uuid AND resource_id::text = $2`,
			src.ID, resourceID, *p.DisplayName); err != nil {
			return out, err
		}
	}

	// Replace first, then the deltas. An upstream that sends both in one request
	// means "set the list to this, then adjust", and applying the adjustments
	// first would have the replace discard them.
	if p.ReplaceMembers != nil {
		if err := replaceMembersTx(ctx, tx, src, groupID, *p.ReplaceMembers); err != nil {
			return out, err
		}
	}
	if len(p.AddMembers) > 0 {
		ids, err := usersForResourceIDs(ctx, tx, src, p.AddMembers)
		if err != nil {
			return out, err
		}
		for _, uid := range ids {
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.group_members (group_id, user_id, org_id)
				VALUES ($1::uuid, $2::uuid, $3::uuid) ON CONFLICT DO NOTHING`,
				groupID, uid, src.OrgID); err != nil {
				return out, err
			}
		}
	}
	if len(p.RemoveMembers) > 0 {
		ids, err := usersForResourceIDs(ctx, tx, src, p.RemoveMembers)
		if err != nil {
			return out, err
		}
		for _, uid := range ids {
			if _, err := tx.Exec(ctx,
				`DELETE FROM core.group_members WHERE group_id = $1::uuid AND user_id = $2::uuid`,
				groupID, uid); err != nil {
				return out, err
			}
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.scim_source_group_links SET updated_at = now()
		WHERE source_id = $1::uuid AND resource_id::text = $2`,
		src.ID, resourceID); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return GetSCIMGroup(ctx, db, src, resourceID)
}

// DeleteSCIMGroup removes a provisioned group.
//
// Unlike a user, a group IS deleted rather than deactivated. The reasons differ:
// deleting a person destroys the audit trail of everything they did, which is
// the thing you most need about somebody who has left. A group holds no history
// of its own -- the audit trail of who was added and when lives in the audit
// events, not in the row -- and a deprovisioned group that lingers keeps
// granting whatever it grants.
func DeleteSCIMGroup(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string) (SCIMGroup, error) {

	g, err := GetSCIMGroup(ctx, db, src, resourceID)
	if err != nil {
		return g, err
	}
	// The link goes, and so does the group. Removing only the link would leave a
	// group nothing manages, still attached to every member it had.
	if _, err := db.Exec(ctx, `DELETE FROM core.groups WHERE id = $1::uuid`,
		g.GroupID); err != nil {
		return g, err
	}
	return g, nil
}
