package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A value is checked against its attribute's declared type when it is written
// (2.32). It is typed when it is released, so a boolean holding "yes" went out
// as `false`, and a number holding "abc" went out as a string under a claim a
// relying party parses as a number. And the type cannot be changed under
// stored values, which would bring the same release in by the other door.
func TestAnAttributeValueMustFitItsType(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// Rolled back: visible to this connection, residue for nobody.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	var orgID, userID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://attributetype-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'attributetype-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256('attributetype-a'::bytea) || sha256('attributetype-b'::bytea),
		        'probe@attributetype.invalid')
		RETURNING id::text`, orgID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	for name, kind := range map[string]string{
		"on_call": "boolean", "employee_number": "number", "nickname": "string", "hired": "date",
	} {
		// Not personal, so nothing here needs a root key to seal with.
		if _, err := DeclareAttribute(ctx, tx, orgID, Attribute{
			Name: name, ValueType: kind, Personal: false,
		}); err != nil {
			t.Fatalf("declaring %s: %v", name, err)
		}
	}

	for _, c := range []struct {
		name, value string
		ok          bool
	}{
		{"on_call", "true", true},
		{"on_call", "false", true},
		{"on_call", "yes", false},
		{"on_call", "True", false},
		{"on_call", "", false},
		{"employee_number", "41", true},
		{"employee_number", "-1.5e3", true},
		{"employee_number", "0", true},
		{"employee_number", "abc", false},
		{"employee_number", "041", false},
		{"employee_number", "1.", false},
		{"employee_number", "+1", false},
		{"employee_number", "NaN", false},
		{"employee_number", "Infinity", false},
		{"employee_number", " 41", false},
		{"nickname", "anything at all", true},
		{"hired", "2026-10-19", true},
	} {
		// A savepoint per case, so a refusal leaves the transaction usable.
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		err = SetUserAttribute(ctx, sp, userID, orgID, c.name, c.value, nil)
		_ = sp.Rollback(ctx)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s = %q was refused: %v", c.name, c.value, err)
		case !c.ok && !errors.Is(err, ErrInvalidAttributeValue):
			t.Errorf("%s = %q gave %v, want ErrInvalidAttributeValue", c.name, c.value, err)
		}
	}

	// Retyping: allowed while nothing is held, refused once something is, and
	// re-declaring with the same type is not a change.
	if _, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: "nickname", ValueType: "boolean", Personal: false,
	}); err != nil {
		t.Fatalf("retyping an attribute that holds nothing was refused: %v", err)
	}
	if _, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: "nickname", ValueType: "string", Personal: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := SetUserAttribute(ctx, tx, userID, orgID, "nickname", "yes", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: "nickname", ValueType: "string", Personal: false, DisplayName: "Nickname",
	}); err != nil {
		t.Errorf("re-declaring with the same type was refused: %v", err)
	}
	_, err = DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: "nickname", ValueType: "boolean", Personal: false,
	})
	if !errors.Is(err, ErrAttributeTypeInUse) {
		t.Errorf("retyping a string holding \"yes\" as a boolean gave %v, want "+
			"ErrAttributeTypeInUse: the value would be released as false", err)
	}
}
