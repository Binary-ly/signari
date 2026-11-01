package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/tokens"
)

// claimReader is what resolving a claim reads through: a transaction at a mint,
// and the pool at userinfo, which has nothing to hold one open for.
type claimReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

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
func MappedClaims(ctx context.Context, q claimReader, userID, orgID, clientID string,
	dest ClaimDestination, granted string, root *keys.RootKey) (map[string]any, error) {

	rows, err := q.Query(ctx, `
		SELECT m.claim_name, m.required_scope, m.source, m.source_value, m.transform, m.transform_arg,
		       COALESCE(s.name, ''), COALESCE(s.personal, false), COALESCE(s.value_type, ''),
		       a.value, a.value_sealed
		FROM core.claim_mappers m
		LEFT JOIN core.user_attribute_schema s ON s.id = m.attribute_id
		LEFT JOIN core.user_attributes a
		  ON a.attribute_id = s.id AND a.user_id = $1::uuid
		WHERE m.org_id = $2::uuid
		  AND m.destination = $3
		  -- NULL client_id means every client in the organisation.
		  AND (m.client_id IS NULL OR m.client_id = $4)
		  -- An attribute the person does not hold says nothing.
		  AND (m.attribute_id IS NULL OR a.user_id IS NOT NULL)`,
		userID, orgID, string(dest), clientID)
	if err != nil {
		return nil, fmt.Errorf("resolving mapped claims: %w", err)
	}

	type pending struct {
		claim     string
		reqScope  string
		source    string
		value     string
		transform string
		arg       string
		attrName  string
		personal  bool
		valueType string
		clear     *string
		sealed    []byte
	}
	var batch []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.claim, &p.reqScope, &p.source, &p.value, &p.transform, &p.arg, &p.attrName,
			&p.personal, &p.valueType, &p.clear, &p.sealed); err != nil {
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

	// A person's own record, read once, for the mappers that ask.
	var record map[string]string

	out := map[string]any{}
	for _, p := range batch {
		if p.reqScope != "" && !tokens.HasScope(granted, p.reqScope) {
			continue
		}

		var list []string
		switch p.source {
		case "constant":
			if v, ok := applyTransform(p.value, p.transform, p.arg); ok {
				out[p.claim] = v
			}
			continue
		case "user_field":
			if record == nil {
				if record, err = userRecord(ctx, q, userID); err != nil {
					return nil, err
				}
			}
			if v, ok := applyTransform(record[p.value], p.transform, p.arg); ok && v != "" {
				out[p.claim] = v
			}
			continue
		case "groups":
			if list, err = GroupsForUser(ctx, q, userID, clientID); err != nil {
				return nil, fmt.Errorf("reading groups for a claim: %w", err)
			}
		case "relation":
			if list, err = ApplicationRoles(ctx, q, orgID, userID, clientID); err != nil {
				return nil, fmt.Errorf("reading roles for a claim: %w", err)
			}
		}
		if p.source == "groups" || p.source == "relation" {
			kept := make([]string, 0, len(list))
			for _, v := range list {
				if t, ok := applyTransform(v, p.transform, p.arg); ok {
					kept = append(kept, t)
				}
			}
			if len(kept) > 0 {
				out[p.claim] = kept
			}
			continue
		}

		var value string
		switch {
		case p.clear != nil:
			value = *p.clear
		default:
			if !skTried {
				sk, _ = keys.LoadSubjectKey(ctx, q, userID, root)
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

		transformed, ok := applyTransform(value, p.transform, p.arg)
		if !ok {
			continue
		}
		out[p.claim] = typedValue(transformed, p.valueType)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// applyTransform shapes a claim's value, and says false when nothing is left of it:
// a pattern that does not match releases nothing, rather than the value it was
// meant to reduce.
func applyTransform(value, transform, arg string) (string, bool) {
	switch transform {
	case "lower":
		return strings.ToLower(value), true
	case "prefix":
		return arg + value, true
	case "extract":
		re, err := regexp.Compile(arg)
		if err != nil {
			return "", false
		}
		m := re.FindStringSubmatch(value)
		switch {
		case m == nil:
			return "", false
		case len(m) > 1:
			return m[1], true
		}
		return m[0], true
	}
	return value, true
}

// userRecord reads the fields a claim can be made from.
func userRecord(ctx context.Context, q claimReader, userID string) (map[string]string, error) {
	var email, username, display, given, surname, locale *string
	if err := q.QueryRow(ctx, `SELECT email, username, display_name, given_name, surname, locale
		FROM core.users WHERE id = $1::uuid`, userID).Scan(&email, &username, &display, &given, &surname,
		&locale); err != nil {
		return nil, fmt.Errorf("reading a person's record for a claim: %w", err)
	}
	out := map[string]string{}
	for name, v := range map[string]*string{"email": email, "username": username, "display_name": display,
		"given_name": given, "surname": surname, "locale": locale} {
		if v != nil {
			out[name] = *v
		}
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

// SAMLAttributes resolves a service provider's declared attribute release.
//
// # The column this reads was dead for months
//
// `core.saml_providers.attributes` maps a SAML attribute name to one of this
// organisation's user attributes, and nothing read it. An operator could
// configure a release, see the column hold exactly what they had asked for, and
// receive assertions carrying none of it — a disclosure control failing in the
// direction that looks like success.
//
// # Why it goes through the same sealed store as OIDC claims
//
// A SAML assertion is a token by another name. Releasing attributes here from
// some separate plaintext path would make SAML the one surface where an erased
// subject still discloses, and erasure would be complete everywhere except the
// protocol enterprises actually use.
//
// So a personal attribute is unsealed with the subject key, exactly as for a
// mapped OIDC claim, and an erased subject releases nothing.
func SAMLAttributes(ctx context.Context, tx claimReader, userID, providerID string,
	root *keys.RootKey) (map[string]string, error) {

	// The provider's release map, and the organisation it belongs to.
	var release map[string]string
	var orgID string
	if err := tx.QueryRow(ctx, `
		SELECT attributes, org_id::text FROM core.saml_providers WHERE id = $1::uuid`,
		providerID).Scan(&release, &orgID); err != nil {
		return nil, fmt.Errorf("reading the SAML attribute release: %w", err)
	}
	if len(release) == 0 {
		return nil, nil
	}

	// The user's values for the attributes named in the release, and only those.
	values, err := UserAttributes(ctx, tx, userID, orgID, root)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]AttributeValue, len(values))
	for _, v := range values {
		byName[v.Name] = v
	}

	out := map[string]string{}
	for samlName, attrName := range release {
		v, ok := byName[attrName]
		// Not readable means erased. Omitted rather than reported, for the same
		// reason a mapped OIDC claim is: an assertion is not a diagnostic
		// surface, and a value saying "this was erased" would republish the fact
		// of erasure to every service provider.
		if !ok || !v.Readable || v.Value == "" {
			continue
		}
		out[samlName] = v.Value
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
