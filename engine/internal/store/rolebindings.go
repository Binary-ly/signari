package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Administrative role bindings (0191, 6.01). What each role may do is
// adminapi's; this is who holds which, in which organisation, and over which
// group.

// AdminRoles is every role a binding may name, as 0191's CHECK names them.
var AdminRoles = []string{"org-owner", "user-manager", "app-manager", "auditor"}

// DelegatedRole is the one role a binding may narrow to a group's members.
const DelegatedRole = "user-manager"

// RoleBinding is one row of core.admin_role_bindings. Exactly one of UserID
// and ClientID is set; GroupID is set only on a delegated user-manager.
type RoleBinding struct {
	ID        string
	OrgID     string
	UserID    string
	ClientID  string
	Role      string
	GroupID   string
	CreatedAt string
}

// The refusals a grant can meet, each the caller's mistake.
var (
	ErrRoleUnknown          = errors.New("no such role")
	ErrRoleSubject          = errors.New("a binding names exactly one of a user and a client")
	ErrRoleNotDelegated     = errors.New("only the user-manager role is narrowed to a group")
	ErrRoleSubjectElsewhere = errors.New("the user, client or group is not in the binding's organisation")
	ErrRoleHeld             = errors.New("that binding exists already")
	ErrRoleBindingUnknown   = errors.New("no such role binding in this organisation")
)

// GrantRole writes a binding and returns its id.
func GrantRole(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, b RoleBinding) (string, error) {
	known := false
	for _, r := range AdminRoles {
		known = known || r == b.Role
	}
	switch {
	case !known:
		return "", ErrRoleUnknown
	case (b.UserID == "") == (b.ClientID == ""):
		return "", ErrRoleSubject
	case b.GroupID != "" && b.Role != DelegatedRole:
		return "", ErrRoleNotDelegated
	}
	var id string
	err := q.QueryRow(ctx, `
		INSERT INTO core.admin_role_bindings (org_id, user_id, client_id, role, group_id)
		VALUES ($1::uuid, NULLIF($2, '')::uuid, NULLIF($3, ''), $4, NULLIF($5, '')::uuid)
		RETURNING id::text`, b.OrgID, b.UserID, b.ClientID, b.Role, b.GroupID).Scan(&id)
	var pg *pgconn.PgError
	switch {
	case errors.As(err, &pg) && pg.ConstraintName == "admin_role_bindings_once":
		return "", ErrRoleHeld
	case errors.As(err, &pg) && (pg.ConstraintName == "admin_role_bindings_subject_org" ||
		pg.ConstraintName == "admin_role_bindings_group_org" || pg.Code == "23503"):
		// 23503: a user, client or group that does not exist at all, which is
		// the same answer as one in another organisation, so neither can be
		// told from the other by a tenant probing for ids.
		return "", ErrRoleSubjectElsewhere
	case errors.As(err, &pg) && pg.Code == "22P02":
		return "", ErrRoleSubjectElsewhere
	case err != nil:
		return "", fmt.Errorf("granting a role: %w", err)
	}
	return id, nil
}

// RevokeRole removes a binding of orgID and returns what it was.
func RevokeRole(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, id string) (RoleBinding, error) {
	b, err := scanBinding(q.QueryRow(ctx, `
		DELETE FROM core.admin_role_bindings WHERE org_id = $1::uuid AND id::text = $2
		RETURNING `+bindingColumns, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleBinding{}, ErrRoleBindingUnknown
	}
	return b, err
}

// RoleBindingOf reads one binding of orgID.
func RoleBindingOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, id string) (RoleBinding, error) {
	b, err := scanBinding(q.QueryRow(ctx, `SELECT `+bindingColumns+`
		FROM core.admin_role_bindings WHERE org_id = $1::uuid AND id::text = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleBinding{}, ErrRoleBindingUnknown
	}
	return b, err
}

// RoleBindings lists orgID's bindings, oldest first.
func RoleBindings(ctx context.Context, q Querier, orgID string) ([]RoleBinding, error) {
	return queryBindings(ctx, q, `SELECT `+bindingColumns+` FROM core.admin_role_bindings
		WHERE org_id = $1::uuid ORDER BY created_at, id`, orgID)
}

// RoleBindingsFor is every binding a person or an application holds: what
// the Admin API reads on each of their requests.
func RoleBindingsFor(ctx context.Context, q Querier, userID, clientID string) ([]RoleBinding, error) {
	return queryBindings(ctx, q, `SELECT `+bindingColumns+` FROM core.admin_role_bindings
		WHERE ($1 <> '' AND user_id::text = $1) OR ($2 <> '' AND client_id = $2)
		ORDER BY created_at, id`, userID, clientID)
}

const bindingColumns = `id::text, org_id::text, COALESCE(user_id::text, ''), COALESCE(client_id, ''),
	role, COALESCE(group_id::text, ''), to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM')`

func scanBinding(row pgx.Row) (RoleBinding, error) {
	var b RoleBinding
	err := row.Scan(&b.ID, &b.OrgID, &b.UserID, &b.ClientID, &b.Role, &b.GroupID, &b.CreatedAt)
	return b, err
}

func queryBindings(ctx context.Context, q Querier, sql string, args ...any) ([]RoleBinding, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("reading role bindings: %w", err)
	}
	defer rows.Close()
	var out []RoleBinding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("reading role bindings: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
