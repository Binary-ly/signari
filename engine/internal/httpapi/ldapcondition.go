package httpapi

import (
	"context"
	"fmt"
	"strings"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/store"
)

// ldapConditionDepth bounds how deeply a condition may nest. A filter is
// reduced in this process, but an outpost's arrives as a request.
const ldapConditionDepth = 16

// ldapCondition writes a condition as SQL over core.users u, every value bound
// and none in the text, the organisation being $1. The directory checks each
// person it gets against the filter again, so this has to include everyone the
// filter matches and may include others; see ldapd's narrow.
//
// The login and address arms are each their own index (0199's, as sign-in reads
// them), which is what finds one person among a hundred thousand in one query.
func ldapCondition(c *ldapd.Condition, args *[]any) (string, error) {
	return conditionSQL(c, args, 0, personConditionSQL)
}

// ldapGroupCondition is ldapCondition over core.groups g.
func ldapGroupCondition(c *ldapd.Condition, args *[]any) (string, error) {
	return conditionSQL(c, args, 0, groupConditionSQL)
}

func conditionSQL(c *ldapd.Condition, args *[]any, depth int,
	leaf func(*ldapd.Condition, func(any) int) (string, bool)) (string, error) {

	if depth > ldapConditionDepth {
		return "", fmt.Errorf("a directory condition nests deeper than %d", ldapConditionDepth)
	}
	switch c.Op {
	case ldapd.CondAnd, ldapd.CondOr:
		if len(c.Of) == 0 {
			return "", fmt.Errorf("an empty %q in a directory condition", c.Op)
		}
		parts := make([]string, 0, len(c.Of))
		for _, child := range c.Of {
			part, err := conditionSQL(child, args, depth+1, leaf)
			if err != nil {
				return "", err
			}
			parts = append(parts, part)
		}
		return "(" + strings.Join(parts, " "+strings.ToUpper(c.Op)+" ") + ")", nil
	case ldapd.CondNone:
		return "false", nil
	}
	bind := func(v any) int {
		*args = append(*args, v)
		return len(*args)
	}
	if sql, ok := leaf(c, bind); ok {
		return sql, nil
	}
	return "", fmt.Errorf("an unknown directory condition %q", c.Op)
}

func personConditionSQL(c *ldapd.Condition, bind func(any) int) (string, bool) {
	switch c.Op {
	case ldapd.CondLogin:
		n := bind(c.Value)
		arms := fmt.Sprintf("u.username_fold = lower($%d) OR u.email_fold = lower($%d)", n, n)
		// A person with neither is named by their id. Only a uuid can be that,
		// and a cast of anything else would be an error rather than no match.
		if id, ok := store.CanonicalUUID(c.Value); ok {
			arms += fmt.Sprintf(" OR u.id = $%d::uuid", bind(id))
		}
		return "(" + arms + ")", true

	case ldapd.CondMail:
		return fmt.Sprintf("u.email_fold = lower($%d)", bind(c.Value)), true

	case ldapd.CondNumber:
		return fmt.Sprintf("u.posix_uid = $%d::int", bind(c.Value)), true

	case ldapd.CondMailPrefix:
		return foldPrefix("u.email_fold", bind(c.Value)), true

	case ldapd.CondLoginPrefix:
		// users_has_an_identifier lets a username be empty, and that person is
		// named by their id, which no index reads the beginning of, so they are
		// left in for the directory to check.
		n := bind(c.Value)
		return "(" + foldPrefix("u.username_fold", n) + " OR " + foldPrefix("u.email_fold", n) +
			" OR (u.username_fold = '' AND u.email_fold IS NULL))", true

	case ldapd.CondName:
		return fmt.Sprintf(`lower(COALESCE(NULLIF(u.display_name,''), NULLIF(u.username,''), u.email, u.id::text)) = lower($%d)`,
			bind(c.Value)), true

	case ldapd.CondGroup:
		return fmt.Sprintf(`u.id IN (SELECT m.user_id
			  FROM core.group_members m
			  JOIN core.groups g ON g.id = m.group_id
			 WHERE g.org_id = $1::uuid AND lower(g.name) = lower($%d))`, bind(c.Value)), true
	}
	return "", false
}

func groupConditionSQL(c *ldapd.Condition, bind func(any) int) (string, bool) {
	switch c.Op {
	case ldapd.CondName:
		return fmt.Sprintf("lower(g.name) = lower($%d)", bind(c.Value)), true
	case ldapd.CondNumber:
		return fmt.Sprintf("g.posix_gid = $%d::int", bind(c.Value)), true
	case ldapd.CondMember:
		n := bind(c.Value)
		return fmt.Sprintf(`g.id IN (SELECT m.group_id
			  FROM core.group_members m
			  JOIN core.users u ON u.id = m.user_id
			 WHERE u.org_id = $1::uuid AND (u.username_fold = lower($%d) OR u.email_fold = lower($%d)))`, n, n), true
	}
	return "", false
}

// foldPrefix is a stored fold beginning with parameter n, as a range rather
// than LIKE, whose function is not leakproof and so can use no index under row
// security (0.52).
func foldPrefix(column string, n int) string {
	return fmt.Sprintf("(%[1]s ~>=~ lower($%[2]d) AND %[1]s ~<~ (lower($%[2]d) || chr(1114111)))", column, n)
}

var _ ldapd.GroupLister = (*LDAPAuthenticator)(nil)

// Groups answers a page of the organisation's groups that have somebody active
// in them (7.02), each with its members, ordered by id as List is. Inactive
// people are not members here, as they are not entries here.
func (a *LDAPAuthenticator) Groups(ctx context.Context, q ldapd.Query) ([]*ldapd.Group, error) {
	if q.Limit <= 0 {
		return nil, nil
	}
	args := []any{a.orgID, q.Limit}
	var where strings.Builder
	if q.After != "" {
		after, ok := store.CanonicalUUID(q.After)
		if !ok {
			return nil, ldapd.ErrBadPosition
		}
		args = append(args, after)
		fmt.Fprintf(&where, " AND g.id > $%d::uuid", len(args))
	}
	if q.Narrow != nil {
		condition, err := ldapGroupCondition(q.Narrow, &args)
		if err != nil {
			return nil, err
		}
		where.WriteString(" AND " + condition)
	}
	rows, err := a.db.Query(ctx, `
		WITH page AS (
			SELECT g.id, g.name, g.posix_gid
			  FROM core.groups g
			 WHERE g.org_id = $1::uuid AND `+store.OrgInService("g.org_id")+where.String()+`
			   AND EXISTS (SELECT 1 FROM core.group_members m
			                 JOIN core.users u ON u.id = m.user_id
			                WHERE m.group_id = g.id AND u.status = 'active')
			 ORDER BY g.id
			 LIMIT $2)
		SELECT p.id::text, p.name, p.posix_gid,
		       (SELECT array_agg(COALESCE(NULLIF(u.username,''), u.email, u.id::text) ORDER BY u.id)
		          FROM core.group_members m
		          JOIN core.users u ON u.id = m.user_id
		         WHERE m.group_id = p.id AND u.status = 'active')
		  FROM page p
		 ORDER BY p.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*ldapd.Group
	for rows.Next() {
		var g ldapd.Group
		if err := rows.Scan(&g.Position, &g.Name, &g.GIDNumber, &g.Members); err != nil {
			return nil, err
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}
