package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Groups inside groups (11.09, migration 0303). An edge says a group is a member of
// another, so everybody in it is in that one and every group above it. Membership read
// through core.groups_of and core.members_of follows the edges; a read of
// core.group_members alone is direct membership, which is what editing, sync and
// export mean, and nothing that decides access may use it alone
// (TestEveryMembershipReadFollowsNesting).

// ErrNestingLoop is a nesting that would put a group inside itself, directly or
// through others.
var ErrNestingLoop = errors.New("the group is already above the one it would be nested in, so this would make a loop")

// ErrNestingGroupUnknown is a group the organisation does not have, on either side.
var ErrNestingGroupUnknown = errors.New("no group of that id in the organisation")

// Nesting is one edge: Group is a member of Parent.
type Nesting struct {
	GroupID  string
	Group    string
	ParentID string
	Parent   string
	AddedAt  string
}

// NestGroup puts group groupID inside parentID, both the organisation's, and reports
// whether it was not there already. addedBy is the person who asked, or "".
func NestGroup(ctx context.Context, db outpostDB, orgID, groupID, parentID, addedBy string) (bool, error) {
	if groupID == parentID {
		return false, ErrNestingLoop
	}
	tag, err := db.Exec(ctx, `
		INSERT INTO core.group_parents (group_id, parent_id, org_id, added_by)
		SELECT c.id, p.id, $1::uuid, NULLIF($4, '')::uuid
		  FROM core.groups c, core.groups p
		 WHERE c.id = $2::uuid AND c.org_id = $1::uuid AND p.id = $3::uuid AND p.org_id = $1::uuid
		ON CONFLICT (group_id, parent_id) DO NOTHING`,
		ExactUUIDOrNil(orgID), ExactUUIDOrNil(groupID), ExactUUIDOrNil(parentID), addedBy)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && (pg.ConstraintName == "group_parents_no_loop" ||
			pg.ConstraintName == "group_parents_not_itself") {
			return false, ErrNestingLoop
		}
		return false, err
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	// Nothing written: already nested, or a group that is not the organisation's,
	// which must not pass as "already done".
	var both bool
	if err := db.QueryRow(ctx, `SELECT count(*) = 2 FROM core.groups
		WHERE org_id = $1::uuid AND id IN ($2::uuid, $3::uuid)`,
		ExactUUIDOrNil(orgID), ExactUUIDOrNil(groupID), ExactUUIDOrNil(parentID)).Scan(&both); err != nil {
		return false, err
	}
	if !both {
		return false, ErrNestingGroupUnknown
	}
	return false, nil
}

// UnnestGroup takes group groupID out of parentID, reporting whether it was in it.
// Everybody who was in the parent only through it is out of the parent, and of every
// group above it, on their next request.
func UnnestGroup(ctx context.Context, db Execer, orgID, groupID, parentID string) (bool, error) {
	tag, err := db.Exec(ctx, `DELETE FROM core.group_parents
		WHERE org_id = $1::uuid AND group_id = $2::uuid AND parent_id = $3::uuid`,
		ExactUUIDOrNil(orgID), ExactUUIDOrNil(groupID), ExactUUIDOrNil(parentID))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GroupNestings is every edge in the organisation, in a stable order: by the
// member group's name, then its parent's. Made by hand, so there are few.
func GroupNestings(ctx context.Context, q Querier, orgID string) ([]Nesting, error) {
	rows, err := q.Query(ctx, `
		SELECT c.id::text, c.name, p.id::text, p.name,
		       to_char(n.added_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM')
		  FROM core.group_parents n
		  JOIN core.groups c ON c.id = n.group_id
		  JOIN core.groups p ON p.id = n.parent_id
		 WHERE n.org_id = $1::uuid
		 ORDER BY c.name, p.name`, ExactUUIDOrNil(orgID))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Nesting, error) {
		var n Nesting
		err := row.Scan(&n.GroupID, &n.Group, &n.ParentID, &n.Parent, &n.AddedAt)
		return n, err
	})
}

// ParentsOf is the groups groupID is directly inside, by name.
func ParentsOf(ctx context.Context, q Querier, groupID string) ([]Nesting, error) {
	rows, err := q.Query(ctx, `
		SELECT c.id::text, c.name, p.id::text, p.name,
		       to_char(n.added_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM')
		  FROM core.group_parents n
		  JOIN core.groups c ON c.id = n.group_id
		  JOIN core.groups p ON p.id = n.parent_id
		 WHERE n.group_id = $1::uuid
		 ORDER BY p.name`, ExactUUIDOrNil(groupID))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Nesting, error) {
		var n Nesting
		err := row.Scan(&n.GroupID, &n.Group, &n.ParentID, &n.Parent, &n.AddedAt)
		return n, err
	})
}
