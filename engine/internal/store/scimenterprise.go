package store

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/scim"
)

// ErrSCIMValue is a value an attribute cannot hold, which RFC 7644 Table 9 calls
// invalidValue (specs/rfc7644.txt:3883): an upstream stops on it and an operator
// can read why, where a 500 is retried for ever.
var ErrSCIMValue = errors.New("scim value")

// applySCIMEnterprise writes the extension's values onto the attributes the
// organisation declares, and says which moved and which it does not declare,
// which are not stored. The sealing, and the type, are SetUserAttribute's, so an
// upstream is held to what the attribute's declaration says.
func applySCIMEnterprise(ctx context.Context, tx pgx.Tx, orgID, userID string, values map[string]*string,
	root *keys.RootKey) (written, notStored []string, err error) {

	if len(values) == 0 {
		return nil, nil, nil
	}
	same, err := refuseChangedAttributes(ctx, tx, orgID, userID, values, root)
	if err != nil || same {
		return nil, nil, err
	}

	for _, name := range slices.Sorted(maps.Keys(values)) {
		var err error
		switch v := values[name]; {
		case v == nil:
			err = RemoveUserAttribute(ctx, tx, userID, orgID, name)
		case root == nil:
			// With no root key a personal value could not be sealed, and which
			// are personal is the declaration's to say.
			err = ErrNoSuchAttribute
		default:
			err = SetUserAttribute(ctx, tx, userID, orgID, name, *v, root)
		}
		switch {
		case err == nil:
			written = append(written, name)
		case errors.Is(err, ErrAttributeNotSet):
		case errors.Is(err, ErrNoSuchAttribute):
			notStored = append(notStored, name)
		case errors.Is(err, ErrInvalidAttributeValue), errors.Is(err, ErrAttributeRequired):
			return nil, nil, fmt.Errorf("%w: %w", ErrSCIMValue, err)
		default:
			return nil, nil, err
		}
	}
	return written, notStored, nil
}

// refuseChangedAttributes holds an upstream to what it may do to a person who
// may act as other users. An attribute can be a claim, and a claim can be what a
// relying party decides on, so changing one is refused as changing the address
// is (refuseIfPrivileged). Resent as they stand is not a rewrite, and reports
// that nothing is left to do, or a sync would fail for ever on one administrator.
func refuseChangedAttributes(ctx context.Context, tx pgx.Tx, orgID, userID string, values map[string]*string,
	root *keys.RootKey) (same bool, err error) {

	_, privileged, _, err := PrivilegedUser(ctx, tx, userID)
	if err != nil || !privileged {
		return false, err
	}
	var held []AttributeValue
	if root != nil {
		if held, err = UserAttributes(ctx, tx, userID, orgID, root); err != nil {
			return false, err
		}
	}
	current := map[string]string{}
	for _, a := range held {
		if a.Readable {
			current[a.Name] = a.Value
		}
	}
	for name, v := range values {
		have, set := current[name]
		if (v == nil && set) || (v != nil && (!set || have != *v)) {
			return false, refuseIfPrivileged(ctx, tx, userID, "change the attributes of")
		}
	}
	return true, nil
}

// SCIMEnterpriseValues reads what the extension shows of a page of people: the
// attributes held for each, by user attribute. A value whose subject was erased
// cannot be read and is not shown. Keys are loaded together, since an attribute
// is personal by default and a page would otherwise cost a statement per person.
func SCIMEnterpriseValues(ctx context.Context, db *pgxpool.Pool, orgID string, userIDs []string,
	root *keys.RootKey) (map[string]map[string]string, error) {

	names := make([]string, 0, len(scim.EnterpriseAttributes))
	for _, a := range scim.EnterpriseAttributes {
		names = append(names, a.Attribute)
	}
	rows, err := db.Query(ctx, `
		SELECT a.user_id::text, s.name, a.value, a.value_sealed
		  FROM core.user_attribute_schema s
		  JOIN core.user_attributes a ON a.attribute_id = s.id
		 WHERE s.org_id = $1::uuid AND s.name = ANY($2::text[]) AND a.user_id = ANY($3::uuid[])`,
		orgID, names, userIDs)
	if err != nil {
		return nil, fmt.Errorf("reading the enterprise extension: %w", err)
	}
	defer rows.Close()

	type sealed struct {
		user, name string
		value      []byte
	}
	out := map[string]map[string]string{}
	put := func(user, name, value string) {
		if out[user] == nil {
			out[user] = map[string]string{}
		}
		out[user][name] = value
	}
	var toOpen []sealed
	var subjects []string
	for rows.Next() {
		var user, name string
		var clear *string
		var seal []byte
		if err := rows.Scan(&user, &name, &clear, &seal); err != nil {
			return nil, err
		}
		if clear != nil {
			put(user, name, *clear)
			continue
		}
		toOpen = append(toOpen, sealed{user, name, seal})
		subjects = append(subjects, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(toOpen) == 0 || root == nil {
		return out, nil
	}

	subjectKeys, err := keys.LoadSubjectKeys(ctx, db, subjects, root)
	if err != nil {
		return nil, err
	}
	for _, s := range toOpen {
		if key := subjectKeys[s.user]; key != nil {
			if plain, err := key.Open(s.value, attributeContext(s.name)); err == nil {
				put(s.user, s.name, string(plain))
			}
		}
	}
	return out, nil
}

// DeclaredSCIMEnterprise says which of the extension's attributes the
// organisation declares, by their SCIM names, in the extension's order: what
// discovery can truthfully offer.
func DeclaredSCIMEnterprise(ctx context.Context, q Querier, orgID string) ([]string, error) {
	names := make([]string, 0, len(scim.EnterpriseAttributes))
	for _, a := range scim.EnterpriseAttributes {
		names = append(names, a.Attribute)
	}
	rows, err := q.Query(ctx, `SELECT name FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = ANY($2::text[])`, orgID, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	declared := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		declared[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []string
	for _, a := range scim.EnterpriseAttributes {
		if declared[a.Attribute] {
			out = append(out, a.SCIM)
		}
	}
	return out, nil
}
