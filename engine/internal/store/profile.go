package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// Operator-defined user attributes.
//
// # The seal decision is made HERE, from the schema, never by the caller
//
// Whether a value is sealed under the subject's key or stored in the clear is
// read from `core.user_attribute_schema.personal` inside the same transaction
// that writes it. No caller passes a flag and no caller may override it.
//
// That is the whole safety argument. A boolean parameter would be got wrong at
// exactly one call site, and the wrong value in the "store it in the clear"
// direction produces a personal attribute that survives erasure — sitting in a
// table nobody thinks to check, readable, for as long as the row exists, after
// the deployment has told a person their data was destroyed.
//
// # What erasure does to these, and why nothing here has to know
//
// A personal value is sealed with the subject's DEK. `EraseSubject` destroys
// that DEK. So every personal attribute becomes unrecoverable at the same
// instant, by the same mechanism, without erasure holding a list of tables to
// visit — and a list of tables to visit is the thing that goes stale the first
// time somebody adds a table.
//
// Non-personal values are deliberately NOT destroyed by erasure. A cost centre
// or a licence tier is not about a person, survives them in every other system,
// and destroying it would corrupt the organisation's own records to satisfy a
// request that never covered it.

// ErrNoSuchAttribute is returned when an attribute is not declared for the org.
var ErrNoSuchAttribute = errors.New("no such attribute is declared")

// Attribute is one declared attribute.
type Attribute struct {
	ID           string
	Name         string
	DisplayName  string
	ValueType    string
	Personal     bool
	UserReadable bool
	UserWritable bool
	Required     bool
}

// AttributeValue is one attribute as held for one user.
type AttributeValue struct {
	Attribute
	// Value is the plaintext. For a personal attribute it is the UNSEALED value,
	// so a caller never sees ciphertext and never has to know which storage was
	// used.
	Value string
	// Readable is false when a personal value could not be unsealed, which
	// happens for exactly one reason: the subject has been erased.
	//
	// Reported rather than treated as "no value". An administrator looking at a
	// profile needs to know the difference between "never set" and "destroyed on
	// request", and so does anybody investigating whether an erasure completed.
	Readable bool
}

// DeclareAttribute creates or updates an attribute declaration.
//
// # `personal` is set once and never changed by an update
//
// Flipping it on an attribute that already holds values would leave rows in the
// wrong storage: sealed values the code now reads from the clear column and
// finds empty, or clear values a later erasure believes it destroyed and did
// not. The second is the dangerous one -- it turns a completed erasure into a
// false record, which is the failure this whole design exists to prevent.
//
// Changing an attribute's sensitivity therefore means declaring a new one and
// migrating deliberately. That is the honest amount of work for a change that
// moves personal data between storage classes.
func DeclareAttribute(ctx context.Context, tx pgx.Tx, orgID string, a Attribute) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO core.user_attribute_schema
			(org_id, name, display_name, value_type, personal,
			 user_readable, user_writable, required)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (org_id, name) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			value_type   = EXCLUDED.value_type,
			-- The personal flag is deliberately NOT updated here; see the note
			-- above DeclareAttribute.
			user_readable = EXCLUDED.user_readable,
			user_writable = EXCLUDED.user_writable,
			required      = EXCLUDED.required,
			updated_at    = now()
		RETURNING id::text`,
		orgID, a.Name, a.DisplayName, a.ValueType, a.Personal,
		a.UserReadable, a.UserWritable, a.Required).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("declaring attribute %q: %w", a.Name, err)
	}
	return id, nil
}

// Attributes returns an organisation's declarations.
func Attributes(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]Attribute, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, name, display_name, value_type, personal,
		       user_readable, user_writable, required
		FROM core.user_attribute_schema
		WHERE org_id = $1::uuid
		ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing attributes: %w", err)
	}
	defer rows.Close()

	out := []Attribute{}
	for rows.Next() {
		var a Attribute
		if err := rows.Scan(&a.ID, &a.Name, &a.DisplayName, &a.ValueType,
			&a.Personal, &a.UserReadable, &a.UserWritable, &a.Required); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetUserAttribute writes one value, sealing it when the schema says to.
func SetUserAttribute(ctx context.Context, tx pgx.Tx, userID, orgID, name, value string,
	root *keys.RootKey) error {

	var attrID string
	var personal bool
	err := tx.QueryRow(ctx, `
		SELECT id::text, personal FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2`, orgID, name).Scan(&attrID, &personal)
	if errors.Is(err, pgx.ErrNoRows) {
		// Refused rather than stored. An undeclared attribute has no
		// sensitivity, no type and no read rules, so storing it would be storing
		// data nobody has decided anything about -- which is how a bag of
		// personal data with no erasure story appears.
		return fmt.Errorf("%w: %q", ErrNoSuchAttribute, name)
	}
	if err != nil {
		return fmt.Errorf("reading the declaration for %q: %w", name, err)
	}

	if !personal {
		_, err = tx.Exec(ctx, `
			INSERT INTO core.user_attributes (user_id, attribute_id, org_id, value, value_sealed)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, NULL)
			ON CONFLICT (user_id, attribute_id) DO UPDATE SET
				value = EXCLUDED.value, value_sealed = NULL, updated_at = now()`,
			userID, attrID, orgID, value)
		if err != nil {
			return fmt.Errorf("writing attribute %q: %w", name, err)
		}
		return nil
	}

	sk, err := keys.LoadOrCreateSubjectKey(ctx, tx, userID, root)
	if err != nil {
		// Includes keys.ErrErased. Writing a personal attribute for an erased
		// subject would mint them a new key and make data readable under an
		// identity somebody is entitled to believe was destroyed.
		return fmt.Errorf("subject key for attribute %q: %w", name, err)
	}
	sealed, err := sk.Seal([]byte(value), attributeContext(name))
	if err != nil {
		return fmt.Errorf("sealing attribute %q: %w", name, err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO core.user_attributes (user_id, attribute_id, org_id, value, value_sealed)
		VALUES ($1::uuid, $2::uuid, $3::uuid, NULL, $4)
		ON CONFLICT (user_id, attribute_id) DO UPDATE SET
			value = NULL, value_sealed = EXCLUDED.value_sealed, updated_at = now()`,
		userID, attrID, orgID, sealed)
	if err != nil {
		return fmt.Errorf("writing attribute %q: %w", name, err)
	}
	return nil
}

// attributeContext binds a sealed value to the attribute it belongs to.
//
// Without it, a ciphertext copied from one attribute's row to another's would
// decrypt cleanly and be reported as that attribute's value -- so a database
// write that moved `home_address` into `job_title` would silently publish it.
func attributeContext(name string) string { return "user-attribute:" + name }

// UserAttributes returns a user's attributes, unsealing what it can.
func UserAttributes(ctx context.Context, tx pgx.Tx, userID, orgID string,
	root *keys.RootKey) ([]AttributeValue, error) {

	rows, err := tx.Query(ctx, `
		SELECT s.id::text, s.name, s.display_name, s.value_type, s.personal,
		       s.user_readable, s.user_writable, s.required,
		       a.value, a.value_sealed
		FROM core.user_attribute_schema s
		JOIN core.user_attributes a
		  ON a.attribute_id = s.id AND a.user_id = $1::uuid
		WHERE s.org_id = $2::uuid
		ORDER BY s.name`, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("reading attributes: %w", err)
	}

	type row struct {
		av     AttributeValue
		clear  *string
		sealed []byte
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.av.ID, &r.av.Name, &r.av.DisplayName, &r.av.ValueType,
			&r.av.Personal, &r.av.UserReadable, &r.av.UserWritable, &r.av.Required,
			&r.clear, &r.sealed); err != nil {
			rows.Close()
			return nil, err
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The subject key is loaded ONCE, outside the loop, and only when something
	// needs it. A profile of twenty attributes must not unwrap twenty keys.
	var sk *keys.SubjectKey
	var skErr error
	needSubjectKey := false
	for _, r := range batch {
		if r.sealed != nil {
			needSubjectKey = true
			break
		}
	}
	if needSubjectKey {
		sk, skErr = keys.LoadSubjectKey(ctx, tx, userID, root)
	}

	out := make([]AttributeValue, 0, len(batch))
	for _, r := range batch {
		av := r.av
		switch {
		case r.clear != nil:
			av.Value, av.Readable = *r.clear, true
		case skErr != nil:
			// The subject was erased. Reported as unreadable rather than as
			// absent: "destroyed on request" and "never set" are different
			// facts, and an investigation into whether an erasure completed
			// needs to tell them apart.
			av.Readable = false
		default:
			plain, err := sk.Open(r.sealed, attributeContext(av.Name))
			if err != nil {
				av.Readable = false
			} else {
				av.Value, av.Readable = string(plain), true
			}
		}
		out = append(out, av)
	}
	return out, nil
}
