package httpapi

import (
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
// The login and address arms are each their own index (0002's unique ones on
// lower(), as sign-in reads them), which is what finds one person among a
// hundred thousand in one query.
func ldapCondition(c *ldapd.Condition, args *[]any, depth int) (string, error) {
	if depth > ldapConditionDepth {
		return "", fmt.Errorf("a directory condition nests deeper than %d", ldapConditionDepth)
	}
	bind := func(v any) int {
		*args = append(*args, v)
		return len(*args)
	}
	switch c.Op {
	case ldapd.CondAnd, ldapd.CondOr:
		if len(c.Of) == 0 {
			return "", fmt.Errorf("an empty %q in a directory condition", c.Op)
		}
		parts := make([]string, 0, len(c.Of))
		for _, child := range c.Of {
			part, err := ldapCondition(child, args, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, part)
		}
		return "(" + strings.Join(parts, " "+strings.ToUpper(c.Op)+" ") + ")", nil

	case ldapd.CondLogin:
		n := bind(c.Value)
		arms := fmt.Sprintf("lower(u.username) = lower($%d) OR lower(u.email) = lower($%d)", n, n)
		// A person with neither is named by their id. Only a uuid can be that,
		// and a cast of anything else would be an error rather than no match.
		if id, ok := store.CanonicalUUID(c.Value); ok {
			arms += fmt.Sprintf(" OR u.id = $%d::uuid", bind(id))
		}
		return "(" + arms + ")", nil

	case ldapd.CondMail:
		return fmt.Sprintf("lower(u.email) = lower($%d)", bind(c.Value)), nil

	case ldapd.CondName:
		return fmt.Sprintf(`lower(COALESCE(NULLIF(u.display_name,''), NULLIF(u.username,''), u.email, u.id::text)) = lower($%d)`,
			bind(c.Value)), nil

	case ldapd.CondGroup:
		return fmt.Sprintf(`u.id IN (SELECT m.user_id
			  FROM core.group_members m
			  JOIN core.groups g ON g.id = m.group_id
			 WHERE g.org_id = $1::uuid AND lower(g.name) = lower($%d))`, bind(c.Value)), nil

	case ldapd.CondNone:
		return "false", nil
	}
	return "", fmt.Errorf("an unknown directory condition %q", c.Op)
}
