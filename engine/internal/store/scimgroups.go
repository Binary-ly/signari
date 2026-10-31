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
		// A new group, never an existing one with the same name. This once
		// upserted on (org_id, name) and then replaced the members, so an
		// upstream could take over any local group by naming it: one whose
		// members may impersonate, one an operator manages, or one another
		// source owns. Whatever that group reached, the upstream's users then
		// reached it too.
		err = tx.QueryRow(ctx, `
			INSERT INTO core.groups (org_id, name, display_name)
			VALUES ($1::uuid, $2, $3)
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
			"a group named %q already exists in this organisation and this source did "+
				"not create it; a source manages only the groups it creates", name)}
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
	return addMembersTx(ctx, tx, src, groupID, userIDs)
}

// addMembersTx adds people to a group in one statement. Named twice is a
// member once.
func addMembersTx(ctx context.Context, tx pgx.Tx, src *SCIMSource, groupID string, userIDs []string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT $1::uuid, unnest($2::uuid[]), $3::uuid
		ON CONFLICT DO NOTHING`, groupID, userIDs, src.OrgID)
	return err
}

// usersForResourceIDs maps /Users resource ids to local user ids, in one query
// on the index however long the list: this asked once per member, which is
// what a ten-thousand-member PUT spent its time on.
//
// A member naming a resource id this source does not know is an ERROR, not a
// skipped row. Skipping would answer 200 to a membership change that did not
// happen, and the upstream would never send it again -- the same silent-success
// failure the PATCH parser exists to prevent.
func usersForResourceIDs(ctx context.Context, tx pgx.Tx, src *SCIMSource,
	resourceIDs []string) ([]string, error) {

	wellFormed := make([]string, 0, len(resourceIDs))
	for _, rid := range resourceIDs {
		if ExactUUID(rid) {
			wellFormed = append(wellFormed, rid)
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT resource_id::text, user_id::text FROM core.scim_source_links
		WHERE source_id = $1::uuid AND resource_id = ANY($2::uuid[])`,
		src.ID, wellFormed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make(map[string]string, len(wellFormed))
	for rows.Next() {
		var rid, userID string
		if err := rows.Scan(&rid, &userID); err != nil {
			return nil, err
		}
		users[rid] = userID
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(resourceIDs))
	for _, rid := range resourceIDs {
		userID, ok := users[rid]
		if !ok {
			return nil, fmt.Errorf("member %q is not a user provisioned by this "+
				"source, so the membership cannot be recorded; provision the user "+
				"before adding them to a group", rid)
		}
		out = append(out, userID)
	}
	return out, nil
}

// GetSCIMGroup reads one group by its SCIM resource id.
func GetSCIMGroup(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string) (SCIMGroup, error) {

	var g SCIMGroup
	if !ExactUUID(resourceID) {
		return g, pgx.ErrNoRows
	}
	err := db.QueryRow(ctx, `
		SELECT l.resource_id::text, l.external_id, l.group_id::text,
		       g.name, l.display_name, l.created_at, l.updated_at
		FROM core.scim_source_group_links l
		JOIN core.groups g ON g.id = l.group_id
		WHERE l.source_id = $1::uuid AND l.resource_id = $2::uuid`,
		src.ID, resourceID).
		Scan(&g.ResourceID, &g.ExternalID, &g.GroupID, &g.Name, &g.DisplayName,
			&g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return g, err
	}
	members, err := membersOf(ctx, db, src, []string{g.GroupID})
	g.Members = members[g.GroupID]
	return g, err
}

// membersOf lists the members of each group as the upstream knows them, in one
// query however many groups: a page of groups asked once per group.
//
// Joined through scim_source_links, so a member added in the CONSOLE rather than
// provisioned does not appear. That is correct rather than lossy: the upstream
// asked what it provisioned, and reporting a member it has no resource id for
// would have it try to reconcile an identifier that means nothing to it.
func membersOf(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	groupIDs []string) (map[string][]SCIMGroupMember, error) {

	out := make(map[string][]SCIMGroupMember, len(groupIDs))
	for _, id := range groupIDs {
		out[id] = []SCIMGroupMember{}
	}
	rows, err := db.Query(ctx, `
		SELECT gm.group_id::text, sl.resource_id::text, COALESCE(sl.user_name, '')
		FROM core.group_members gm
		JOIN core.scim_source_links sl
		  ON sl.user_id = gm.user_id AND sl.source_id = $1::uuid
		WHERE gm.group_id = ANY($2::uuid[])
		ORDER BY gm.group_id, sl.user_name`, src.ID, groupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var groupID string
		var m SCIMGroupMember
		if err := rows.Scan(&groupID, &m.ResourceID, &m.DisplayName); err != nil {
			return nil, err
		}
		out[groupID] = append(out[groupID], m)
	}
	return out, rows.Err()
}

// ListSCIMGroups pages through the groups this source provisioned.
//
// SCIM pages by index (RFC 7644 §3.4.2.4, specs/rfc7644.txt:1431: "set the
// startIndex to 11 and re-fetch"), so there is no key to resume from and the
// offset stays. What it walks is the index behind the sort, and only the
// page's rows reach the join: a deep page used to sort the collection and join
// every row it skipped.
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
		WITH page AS (
			SELECT external_id FROM core.scim_source_group_links
			WHERE source_id = $1::uuid AND ($2 = '' OR display_name = $2)
			ORDER BY created_at, external_id
			OFFSET $3 LIMIT $4)
		SELECT l.resource_id::text, l.external_id, l.group_id::text,
		       g.name, l.display_name, l.created_at, l.updated_at
		FROM page
		JOIN core.scim_source_group_links l ON l.source_id = $1::uuid AND l.external_id = page.external_id
		JOIN core.groups g ON g.id = l.group_id
		ORDER BY l.created_at, l.external_id`, src.ID, displayName, start-1, count)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []SCIMGroup{}
	ids := []string{}
	for rows.Next() {
		var g SCIMGroup
		if err := rows.Scan(&g.ResourceID, &g.ExternalID, &g.GroupID, &g.Name,
			&g.DisplayName, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, g)
		ids = append(ids, g.GroupID)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	members, err := membersOf(ctx, db, src, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].Members = members[out[i].GroupID]
	}
	return out, total, nil
}

// PatchSCIMGroup applies a parsed PATCH.
func PatchSCIMGroup(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string, p *scim.GroupPatch) (SCIMGroup, error) {

	var out SCIMGroup
	if !ExactUUID(resourceID) {
		return out, pgx.ErrNoRows
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var groupID string
	if err := tx.QueryRow(ctx, `
		SELECT group_id::text FROM core.scim_source_group_links
		WHERE source_id = $1::uuid AND resource_id = $2::uuid`,
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
			WHERE source_id = $1::uuid AND resource_id = $2::uuid`,
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
		if err := addMembersTx(ctx, tx, src, groupID, ids); err != nil {
			return out, err
		}
	}
	if len(p.RemoveMembers) > 0 {
		ids, err := usersForResourceIDs(ctx, tx, src, p.RemoveMembers)
		if err != nil {
			return out, err
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM core.group_members WHERE group_id = $1::uuid AND user_id = ANY($2::uuid[])`,
			groupID, ids); err != nil {
			return out, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.scim_source_group_links SET updated_at = now()
		WHERE source_id = $1::uuid AND resource_id = $2::uuid`,
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
