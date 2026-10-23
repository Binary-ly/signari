package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

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

// ErrInvalidAttributeValue is a value its attribute's declared type cannot hold.
var ErrInvalidAttributeValue = errors.New("the value does not fit the attribute's type")

// ErrAttributeTypeInUse is a change of type to an attribute holding values.
var ErrAttributeTypeInUse = errors.New("the attribute holds values, so its type cannot change")

// jsonNumber is the form a number claim carries, RFC 8259 §6
// (rfc-editor.org/rfc/rfc8259.txt): `number = [ minus ] int [ frac ] [ exp ]`,
// `int = zero / ( digit1-9 *DIGIT )`, `frac = decimal-point 1*DIGIT`,
// `exp = e [ minus / plus ] 1*DIGIT`. No leading zeros, no Infinity or NaN.
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// checkAttributeValue refuses a value its declared type would misstate.
//
// Values are stored as text and typed on the way out (typedValue). A boolean
// released from anything but "true" was `false`, so "yes" became a claim that
// said no; a number that did not parse went out as a string under a claim a
// relying party parses as a number. Both are refused here, where the person
// writing can be told. A string holds anything, and a date is a formatted
// string whose format the profiles that define one do not agree on.
func checkAttributeValue(name, valueType, value string) error {
	switch valueType {
	case "boolean":
		if value != "true" && value != "false" {
			return fmt.Errorf("%w: %q is a boolean, true or false", ErrInvalidAttributeValue, name)
		}
	case "number":
		if !jsonNumber.MatchString(value) {
			return fmt.Errorf("%w: %q is a number", ErrInvalidAttributeValue, name)
		}
	}
	return nil
}

// CheckPromptAttribute reports whether a prompt field may write attribute name
// (5.14): it is declared in the organisation, and every value the field can
// answer with is one the attribute's type accepts. Asked when the prompt is
// defined, so a mapping that could never be written is refused there rather
// than at somebody's sign-in.
func CheckPromptAttribute(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, name string, candidates []string) error {
	var valueType string
	err := q.QueryRow(ctx, `SELECT value_type FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2`, orgID, name).Scan(&valueType)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %q", ErrNoSuchAttribute, name)
	}
	if err != nil {
		return err
	}
	for _, v := range candidates {
		if err := checkAttributeValue(name, valueType, v); err != nil {
			return fmt.Errorf("%w (the field can answer %q)", err, v)
		}
	}
	return nil
}

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
//
// # `value_type` changes only while nothing is stored
//
// The values were checked against the type they were written under. Retyping a
// string attribute holding "yes" as a boolean would release it as `false`, the
// failure the check at write exists to stop, arriving by the other door.
func DeclareAttribute(ctx context.Context, tx pgx.Tx, orgID string, a Attribute) (string, error) {
	// Locked first and counted second, in separate statements: a value written
	// while the lock was awaited is visible to the count, and SetUserAttribute's
	// share lock keeps a new one out until this commits.
	var attrID, current string
	err := tx.QueryRow(ctx, `
		SELECT id::text, value_type FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2
		FOR UPDATE`, orgID, a.Name).Scan(&attrID, &current)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return "", fmt.Errorf("reading the declaration of %q: %w", a.Name, err)
	case current != a.ValueType:
		var held bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM core.user_attributes WHERE attribute_id = $1::uuid)`,
			attrID).Scan(&held); err != nil {
			return "", fmt.Errorf("counting the values of %q: %w", a.Name, err)
		}
		if held {
			return "", fmt.Errorf("%w: %q is a %s", ErrAttributeTypeInUse, a.Name, current)
		}
	}

	var id string
	err = tx.QueryRow(ctx, `
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

	var attrID, valueType string
	var personal bool
	err := tx.QueryRow(ctx, `
		SELECT id::text, personal, value_type FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2
		FOR SHARE`, orgID, name).Scan(&attrID, &personal, &valueType)
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
	if err := checkAttributeValue(name, valueType, value); err != nil {
		return err
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

// ClearUserAttribute removes one of a person's values.
func ClearUserAttribute(ctx context.Context, tx pgx.Tx, userID, orgID, name string) error {
	if _, err := tx.Exec(ctx, `
		DELETE FROM core.user_attributes a USING core.user_attribute_schema s
		 WHERE a.attribute_id = s.id AND a.user_id = $1::uuid AND s.org_id = $2::uuid AND s.name = $3`,
		userID, orgID, name); err != nil {
		return fmt.Errorf("clearing attribute %q: %w", name, err)
	}
	return nil
}

// ErrAttributeRequired is a required attribute left empty.
var ErrAttributeRequired = errors.New("this attribute is required")

// ErrAttributeNotSet is a value cleared that the person does not have.
var ErrAttributeNotSet = errors.New("the person has no value for that attribute")

// RemoveUserAttribute clears one of a person's values as an administrator
// does it (6.07). The attribute must be declared, and a required one is
// replaced rather than cleared, as the person's own profile refuses to clear
// it: an empty required attribute is a state nothing else can put a person in.
func RemoveUserAttribute(ctx context.Context, tx pgx.Tx, userID, orgID, name string) error {
	var attrID string
	var required bool
	err := tx.QueryRow(ctx, `SELECT id::text, required FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2`, orgID, name).Scan(&attrID, &required)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %q", ErrNoSuchAttribute, name)
	}
	if err != nil {
		return fmt.Errorf("reading the declaration for %q: %w", name, err)
	}
	if required {
		return fmt.Errorf("%w: %q is required, so give it another value instead", ErrAttributeRequired, name)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM core.user_attributes WHERE user_id = $1::uuid AND attribute_id = $2::uuid`,
		userID, attrID)
	if err != nil {
		return fmt.Errorf("clearing attribute %q: %w", name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %q", ErrAttributeNotSet, name)
	}
	return nil
}

// SetOwnAttributes writes what a person set for themselves, from their profile
// or at sign-up: only the attributes they may write, each checked against its
// type and sealed as its declaration says. values maps a name to its new value;
// an empty value clears an optional attribute and is refused for a required
// one. A name the person may not write is refused (ErrNoSuchAttribute) rather
// than skipped, so an administrator's attribute cannot be set by posting it.
// changed is the names that were written or cleared.
func SetOwnAttributes(ctx context.Context, tx pgx.Tx, userID, orgID string, values map[string]string,
	root *keys.RootKey) (changed []string, err error) {

	decl, err := Attributes(ctx, tx, orgID)
	if err != nil {
		return nil, err
	}
	writable := map[string]Attribute{}
	for _, a := range decl {
		if a.UserWritable {
			writable[a.Name] = a
		}
	}
	for name := range values {
		if _, ok := writable[name]; !ok {
			return nil, fmt.Errorf("%w: %q is not one you can set", ErrNoSuchAttribute, name)
		}
	}
	for _, a := range decl {
		v, posted := values[a.Name]
		if !a.UserWritable || !posted {
			continue
		}
		if v == "" {
			if a.Required {
				return nil, fmt.Errorf("%w: %s", ErrAttributeRequired, attributeLabel(a))
			}
			if err := ClearUserAttribute(ctx, tx, userID, orgID, a.Name); err != nil {
				return nil, err
			}
		} else if err := SetUserAttribute(ctx, tx, userID, orgID, a.Name, v, root); err != nil {
			return nil, err
		}
		changed = append(changed, a.Name)
	}
	return changed, nil
}

func attributeLabel(a Attribute) string {
	if a.DisplayName != "" {
		return a.DisplayName
	}
	return a.Name
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

// ApplyIDPAttributeMapping writes an upstream provider's mapped claims.
//
// # Only the claims an operator named
//
// The mapping is read first and each claim is looked up BY NAME in the verified
// payload. Nothing else in that payload is decoded, so whoever runs the upstream
// provider cannot write local state by adding a claim — they can only supply a
// value for one this deployment already decided to trust them for.
//
// That direction matters more than the outbound one. If any access policy ever
// reads an attribute, an unmapped copy-everything design would make the upstream
// provider a participant in local authorization decisions.
//
// # Values are bounded, and over-length is refused rather than truncated
//
// The provider chooses these strings. A truncated value is a wrong value that
// looks like a right one -- a department cut from "Engineering (Platform)" to
// "Engineering" reads as correct and is not -- so an over-length value is
// dropped with a count returned, and the caller logs it.
//
// # A failure here never fails the sign-in
//
// The caller treats the error as advisory. Somebody who has just authenticated
// correctly at their provider must not be refused entry because an optional
// profile field could not be written; the sign-in is the security decision and
// the attribute is decoration on it.
func ApplyIDPAttributeMapping(ctx context.Context, tx pgx.Tx, userID, orgID, providerID string,
	rawClaims []byte, root *keys.RootKey) (applied, skipped int, err error) {

	if len(rawClaims) == 0 {
		return 0, 0, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT m.upstream_claim, s.name, m.overwrite, m.max_length
		FROM core.idp_attribute_map m
		JOIN core.user_attribute_schema s ON s.id = m.attribute_id
		WHERE m.provider_id = $1::uuid AND m.org_id = $2::uuid`, providerID, orgID)
	if err != nil {
		return 0, 0, fmt.Errorf("reading the provider's attribute mapping: %w", err)
	}
	type mapping struct {
		claim     string
		attribute string
		overwrite bool
		maxLen    int
	}
	var maps []mapping
	for rows.Next() {
		var m mapping
		if err := rows.Scan(&m.claim, &m.attribute, &m.overwrite, &m.maxLen); err != nil {
			rows.Close()
			return 0, 0, err
		}
		maps = append(maps, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if len(maps) == 0 {
		return 0, 0, nil
	}

	// Decoded once, into a generic map, AFTER establishing that at least one
	// mapping exists. A provider nobody has configured a mapping for costs no
	// parse at all.
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return 0, 0, fmt.Errorf("decoding the upstream claims: %w", err)
	}

	// What the user already has, so `overwrite = false` can mean something.
	existing, err := UserAttributes(ctx, tx, userID, orgID, root)
	if err != nil {
		return 0, 0, err
	}
	present := map[string]bool{}
	for _, e := range existing {
		// A value that exists but cannot be read (erased) still counts as
		// present: overwriting it would write new personal data for a subject
		// whose data was destroyed.
		present[e.Name] = true
	}

	for _, m := range maps {
		v, ok := claims[m.claim]
		if !ok || v == nil {
			continue
		}
		value := claimToString(v)
		if value == "" {
			continue
		}
		if len(value) > m.maxLen {
			skipped++
			continue
		}
		if present[m.attribute] && !m.overwrite {
			continue
		}
		if err := SetUserAttribute(ctx, tx, userID, orgID, m.attribute, value, root); err != nil {
			// One unmappable attribute must not abandon the rest.
			skipped++
			continue
		}
		applied++
	}
	return applied, skipped, nil
}

// claimToString renders a JSON claim as the text an attribute stores.
//
// Objects and arrays return "" rather than their JSON encoding. Storing
// `{"a":1}` in a field an operator declared as a string produces a value that
// every consumer downstream has to guess the shape of, and the honest answer to
// "map this object onto a string attribute" is that it does not map.
func claimToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// %v on a float64 gives 1e+06 for a million, which is not what anybody
		// means by an employee number.
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}
