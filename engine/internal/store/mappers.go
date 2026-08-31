package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/tokens"
)

// Resolving operator-defined claims at token-mint time.
//
// # Nothing is released that a mapper did not name
//
// This function is the only path from a user attribute into a token, and it
// starts from the mapper table rather than from the attributes. An attribute
// with no mapper produces no claim, for any client, in any destination — so
// adding an attribute is never, by itself, a disclosure to anybody already
// integrated.
//
// # Read fresh, every time
//
// ADR-007: security-negative answers are never cached. A claim released because
// a mapper existed must stop being released the moment the mapper is deleted,
// and a value must stop being released the moment the subject is erased. Both
// fall out of reading on the request path, which is what this does.
//
// # An erased subject releases nothing, silently
//
// A personal attribute belonging to an erased subject cannot be unsealed. It is
// omitted rather than reported: a token is not a diagnostic surface, and a claim
// whose value is "this was erased" would republish the fact of erasure to every
// relying party. The admin API reports `readable: false` for exactly this,
// where somebody entitled to know is asking.

// ClaimDestination is where a mapped claim goes.
type ClaimDestination string

const (
	ClaimInIDToken     ClaimDestination = "id_token"
	ClaimInUserInfo    ClaimDestination = "userinfo"
	ClaimInAccessToken ClaimDestination = "access_token"
)

// MappedClaims resolves the operator-defined claims for one token.
//
// `granted` is the scope string actually carried by the grant, not what the
// client asked for. A mapper that requires a scope releases nothing unless the
// grant carries it — which is what keeps a consent decision meaningful after
// the fact.
func MappedClaims(ctx context.Context, tx pgx.Tx, userID, orgID, clientID string,
	dest ClaimDestination, granted string, root *keys.RootKey) (map[string]any, error) {

	rows, err := tx.Query(ctx, `
		SELECT m.claim_name, m.required_scope, s.name, s.personal, s.value_type,
		       a.value, a.value_sealed
		FROM core.claim_mappers m
		JOIN core.user_attribute_schema s ON s.id = m.attribute_id
		JOIN core.user_attributes a
		  ON a.attribute_id = s.id AND a.user_id = $1::uuid
		WHERE m.org_id = $2::uuid
		  AND m.destination = $3
		  -- NULL client_id means every client in the organisation.
		  AND (m.client_id IS NULL OR m.client_id = $4)`,
		userID, orgID, string(dest), clientID)
	if err != nil {
		return nil, fmt.Errorf("resolving mapped claims: %w", err)
	}

	type pending struct {
		claim     string
		reqScope  string
		attrName  string
		personal  bool
		valueType string
		clear     *string
		sealed    []byte
	}
	var batch []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.claim, &p.reqScope, &p.attrName, &p.personal,
			&p.valueType, &p.clear, &p.sealed); err != nil {
			rows.Close()
			return nil, err
		}
		batch = append(batch, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return nil, nil
	}

	// The subject key is unwrapped at most once, and only if a personal
	// attribute survived the scope check. A token with ten mapped claims must
	// not unwrap ten keys, and a grant that carries none of the required scopes
	// must not unwrap any.
	var sk *keys.SubjectKey
	var skTried bool

	out := map[string]any{}
	for _, p := range batch {
		if p.reqScope != "" && !tokens.HasScope(granted, p.reqScope) {
			continue
		}

		var value string
		switch {
		case p.clear != nil:
			value = *p.clear
		default:
			if !skTried {
				sk, _ = keys.LoadSubjectKey(ctx, tx, userID, root)
				skTried = true
			}
			if sk == nil {
				// Erased, or no key. Omitted rather than reported -- see the
				// file comment.
				continue
			}
			plain, err := sk.Open(p.sealed, attributeContext(p.attrName))
			if err != nil {
				continue
			}
			value = string(plain)
		}

		out[p.claim] = typedValue(value, p.valueType)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// typedValue renders a stored string as the declared JSON type.
//
// Stored as text and typed on the way out, rather than typed columns per kind.
// A claim's JSON type is part of what a relying party parses, so `"age": "41"`
// and `"age": 41` are different tokens — but the storage does not need four
// columns to say so, and four columns would make the "exactly one value" check
// four times harder to state.
func typedValue(raw, valueType string) any {
	switch valueType {
	case "boolean":
		return raw == "true"
	case "number":
		var f float64
		if _, err := fmt.Sscanf(raw, "%g", &f); err == nil {
			return f
		}
		// Falls back to the string rather than to zero. A malformed number
		// released as `0` is a claim that says something false; released as
		// text it is visibly wrong to whoever reads it.
		return raw
	default:
		// string and date. A date stays a string because every profile that
		// defines one -- OIDC's `birthdate`, SCIM's timestamps -- defines it as
		// a formatted string rather than a JSON number.
		return raw
	}
}
