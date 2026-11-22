package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// EveryObject is a delegation's object id for all the objects of a type.
const EveryObject = "*"

// RelationDelegation is what one organisation lets another hand out to its own
// people (11.11). The relations stay in the owner's core.relations, so the owner's
// decisions read what they always read; only who may write them crosses.
type RelationDelegation struct {
	ID           string
	OrgID        string
	GranteeOrgID string
	ObjectType   string
	ObjectID     string
	Relations    []string
	CreatedAt    time.Time
}

var (
	// ErrNotDelegated is a relation or an object outside what was delegated.
	ErrNotDelegated = errors.New("that is not what this delegation hands out")
	// ErrNotTheGrantees is a subject who is not a person of the grantee.
	ErrNotTheGrantees = errors.New("a delegation is handed to the grantee's own people, named by id")
)

// Covers reports whether the delegation hands out this relation on this object.
func (d RelationDelegation) Covers(relation, objectType, objectID string) bool {
	return objectType == d.ObjectType && (d.ObjectID == EveryObject || objectID == d.ObjectID) &&
		slices.Contains(d.Relations, relation)
}

// NewRelationDelegation records one.
func NewRelationDelegation(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, d RelationDelegation) (string, error) {
	var id string
	err := q.QueryRow(ctx, `
		INSERT INTO core.relation_delegations (org_id, grantee_org_id, object_type, object_id, relations)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)
		ON CONFLICT (org_id, grantee_org_id, object_type, object_id)
		DO UPDATE SET relations = EXCLUDED.relations
		RETURNING id::text`, d.OrgID, d.GranteeOrgID, d.ObjectType, d.ObjectID, d.Relations).Scan(&id)
	return id, err
}

const delegationColumns = `id::text, org_id::text, grantee_org_id::text, object_type, object_id, relations, created_at`

func scanDelegation(row pgx.Row, d *RelationDelegation) error {
	return row.Scan(&d.ID, &d.OrgID, &d.GranteeOrgID, &d.ObjectType, &d.ObjectID, &d.Relations, &d.CreatedAt)
}

// RelationDelegationsOf lists those an organisation is either side of, oldest first.
func RelationDelegationsOf(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]RelationDelegation, error) {
	rows, err := q.Query(ctx, `SELECT `+delegationColumns+` FROM core.relation_delegations
		WHERE org_id = $1::uuid OR grantee_org_id = $1::uuid ORDER BY created_at, id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RelationDelegation{}
	for rows.Next() {
		var d RelationDelegation
		if err := scanDelegation(rows, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RelationDelegationByID reads one, nil when there is none.
func RelationDelegationByID(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string) (*RelationDelegation, error) {
	var d RelationDelegation
	err := scanDelegation(q.QueryRow(ctx, `SELECT `+delegationColumns+`
		FROM core.relation_delegations WHERE id = $1::uuid`, id), &d)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// RemoveRelationDelegation takes one away, and what was handed out under it.
func RemoveRelationDelegation(ctx context.Context, e Execer, id string) (bool, error) {
	tag, err := e.Exec(ctx, `DELETE FROM core.relation_delegations WHERE id = $1::uuid`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GrantDelegated hands one of the delegation's relations to a person of the
// grantee, in the owner's relations. A relation the owner gave them itself stays
// the owner's: it does not go when the delegation does.
func GrantDelegated(ctx context.Context, q interface {
	Execer
	QueryRow(context.Context, string, ...any) pgx.Row
}, d RelationDelegation, r Relation) error {
	if !d.Covers(r.Relation, r.ObjectType, r.ObjectID) {
		return ErrNotDelegated
	}
	id, ok := CanonicalUUID(r.SubjectID)
	if r.SubjectType != "user" || !ok {
		return ErrNotTheGrantees
	}
	var theirs bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE id = $1::uuid AND org_id = $2::uuid)`,
		id, d.GranteeOrgID).Scan(&theirs); err != nil {
		return err
	}
	if !theirs {
		return ErrNotTheGrantees
	}
	_, err := q.Exec(ctx, `
		INSERT INTO core.relations
			(org_id, subject_type, subject_id, relation, object_type, object_id, expires_at, delegation_id)
		VALUES ($1::uuid, 'user', $2, $3, $4, $5, $6, $7::uuid)
		ON CONFLICT (org_id, subject_type, subject_id, relation, object_type, object_id)
		DO UPDATE SET expires_at = EXCLUDED.expires_at, granted_at = now()
		WHERE core.relations.delegation_id = EXCLUDED.delegation_id`,
		d.OrgID, id, r.Relation, r.ObjectType, r.ObjectID, r.ExpiresAt, d.ID)
	return err
}

// RevokeDelegated takes back what this delegation handed out, and nothing else.
func RevokeDelegated(ctx context.Context, e Execer, d RelationDelegation, r Relation) (bool, error) {
	tag, err := e.Exec(ctx, `
		DELETE FROM core.relations
		 WHERE org_id = $1::uuid AND delegation_id = $2::uuid AND subject_type = $3 AND subject_id = $4
		   AND relation = $5 AND object_type = $6 AND object_id = $7`,
		d.OrgID, d.ID, r.SubjectType, r.SubjectID, r.Relation, r.ObjectType, r.ObjectID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// DelegatedRelations lists what a delegation has handed out, and nothing else of
// the owner's: this is all a grantee's token reads of another organisation.
func DelegatedRelations(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, d RelationDelegation) ([]Relation, error) {
	rows, err := q.Query(ctx, `
		SELECT subject_type, subject_id, relation, object_type, object_id, expires_at
		  FROM core.relations
		 WHERE org_id = $1::uuid AND delegation_id = $2::uuid
		 ORDER BY id`, d.OrgID, d.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var r Relation
		if err := rows.Scan(&r.SubjectType, &r.SubjectID, &r.Relation, &r.ObjectType, &r.ObjectID, &r.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
