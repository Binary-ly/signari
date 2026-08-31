package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
)

// User attributes, and the property the whole design exists for.
//
// # What is being proved
//
// An attribute bag is a place personal data accumulates. The question that
// decides whether it is safe to have one is: when somebody exercises a right to
// erasure, does the data in it actually become unreadable?
//
// Here it does, and not because erasure knows about this table. Personal values
// are sealed under the subject's own DEK, and `EraseSubject` destroys that DEK —
// so every personal attribute dies at the same instant, by the same mechanism,
// with no list of places for erasure to visit. A list is the thing that goes
// stale the first time somebody adds a table, and going stale here means
// telling a person their data was destroyed when it was not.
//
// The tests below hold both halves: the personal value becomes unreadable, and
// the non-personal one deliberately survives.

func profileRoot(t *testing.T) *keys.RootKey {
	t.Helper()
	secret := make([]byte, 32)
	secret[0] = 7
	root, err := keys.NewRootKey("test", secret)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// profileFixture creates an org, a user, and returns both.
func profileFixture(t *testing.T) (ctx context.Context, orgID, userID string) {
	t.Helper()
	ctx = context.Background()
	conn := connect(t)

	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no organisation available: %v", err)
	}
	stamp := time.Now().UnixNano()
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4)
		RETURNING id::text`,
		orgID,
		[]byte(fmt.Sprintf("prof-a-%d", stamp)),
		[]byte(fmt.Sprintf("prof-b-%d", stamp)),
		fmt.Sprintf("prof-%d@example.test", stamp)).Scan(&userID); err != nil {
		t.Fatalf("creating the fixture user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(),
			`DELETE FROM core.users WHERE id = $1::uuid`, userID)
	})
	return ctx, orgID, userID
}

func TestErasureDestroysPersonalAttributesAndSparesTheRest(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	stamp := time.Now().UnixNano()

	personal := fmt.Sprintf("home_address_%d", stamp)
	business := fmt.Sprintf("cost_centre_%d", stamp)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: personal, ValueType: "string", Personal: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: business, ValueType: "string", Personal: false,
	}); err != nil {
		t.Fatal(err)
	}

	must(t, SetUserAttribute(ctx, tx, userID, orgID, personal, "12 Rue de la Paix", root))
	must(t, SetUserAttribute(ctx, tx, userID, orgID, business, "CC-4471", root))

	// Both readable before erasure, or the test proves nothing about after.
	before, err := UserAttributes(ctx, tx, userID, orgID, root)
	must(t, err)
	if len(before) != 2 {
		t.Fatalf("read %d attributes, want 2", len(before))
	}
	for _, a := range before {
		if !a.Readable || a.Value == "" {
			t.Fatalf("%s is not readable before erasure", a.Name)
		}
	}

	// The personal value must not be sitting in the clear column.
	var clear *string
	must(t, tx.QueryRow(ctx, `
		SELECT a.value FROM core.user_attributes a
		JOIN core.user_attribute_schema s ON s.id = a.attribute_id
		WHERE a.user_id = $1::uuid AND s.name = $2`, userID, personal).Scan(&clear))
	if clear != nil {
		t.Fatalf("the personal attribute is stored in the clear (%q). Erasure "+
			"would not reach it and the deployment would report success.", *clear)
	}

	// Erase.
	must(t, keys.EraseSubject(ctx, tx, userID))

	after, err := UserAttributes(ctx, tx, userID, orgID, root)
	must(t, err)

	var sawPersonal, sawBusiness bool
	for _, a := range after {
		switch a.Name {
		case personal:
			sawPersonal = true
			if a.Readable {
				t.Errorf("the personal attribute is still readable after erasure: %q", a.Value)
			}
			if a.Value != "" {
				t.Errorf("the personal attribute still yields a value after erasure: %q", a.Value)
			}
		case business:
			sawBusiness = true
			if !a.Readable || a.Value != "CC-4471" {
				t.Errorf("the non-personal attribute was destroyed by erasure "+
					"(readable=%v value=%q). A cost centre is not about a person "+
					"and destroying it corrupts the organisation's own records.",
					a.Readable, a.Value)
			}
		}
	}
	if !sawPersonal || !sawBusiness {
		t.Fatalf("attributes went missing entirely after erasure; personal=%v business=%v. "+
			"An erased attribute must still be REPORTED as unreadable -- "+
			"'destroyed on request' and 'never set' are different facts.",
			sawPersonal, sawBusiness)
	}
}

// An undeclared attribute is refused, not stored.
//
// Storing one would mean storing data nobody has decided anything about: no
// sensitivity, so no erasure story; no type; no read rules. That is exactly how
// a bag of personal data with no way to delete it comes into existence.
func TestAnUndeclaredAttributeIsRefused(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	err = SetUserAttribute(ctx, tx, userID, orgID, "never_declared", "x", root)
	if !errors.Is(err, ErrNoSuchAttribute) {
		t.Fatalf("storing an undeclared attribute gave %v, want ErrNoSuchAttribute", err)
	}
}

// A sealed value is bound to its own attribute.
//
// Without the context binding, a ciphertext moved between rows would decrypt
// cleanly and be reported as the other attribute's value — so a database write
// that put `home_address` into `job_title` would silently publish it.
func TestASealedValueCannotBeMovedBetweenAttributes(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	stamp := time.Now().UnixNano()

	a := fmt.Sprintf("addr_%d", stamp)
	b := fmt.Sprintf("title_%d", stamp)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	for _, name := range []string{a, b} {
		if _, err := DeclareAttribute(ctx, tx, orgID, Attribute{
			Name: name, ValueType: "string", Personal: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	must(t, SetUserAttribute(ctx, tx, userID, orgID, a, "12 Rue de la Paix", root))
	must(t, SetUserAttribute(ctx, tx, userID, orgID, b, "Engineer", root))

	// Move a's ciphertext into b's row, as a rogue write would.
	_, err = tx.Exec(ctx, `
		UPDATE core.user_attributes SET value_sealed = (
			SELECT a2.value_sealed FROM core.user_attributes a2
			JOIN core.user_attribute_schema s2 ON s2.id = a2.attribute_id
			WHERE a2.user_id = $1::uuid AND s2.name = $2)
		WHERE user_id = $1::uuid AND attribute_id = (
			SELECT id FROM core.user_attribute_schema WHERE org_id = $3::uuid AND name = $4)`,
		userID, a, orgID, b)
	must(t, err)

	got, err := UserAttributes(ctx, tx, userID, orgID, root)
	must(t, err)
	for _, av := range got {
		if av.Name == b && av.Value == "12 Rue de la Paix" {
			t.Fatal("a ciphertext moved between attributes decrypted as the " +
				"target attribute's value. The context binding is missing, so a " +
				"stray write can republish one field as another.")
		}
	}
}

// Both storage columns can never be set, and neither can be empty.
func TestAnAttributeRowHoldsExactlyOneValue(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("both_%d", time.Now().UnixNano())
	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: name, ValueType: "string", Personal: false,
	})
	must(t, err)

	for _, c := range []struct {
		what          string
		clear, sealed any
	}{
		{"both", "x", []byte("y")},
		{"neither", nil, nil},
	} {
		_, err := tx.Exec(ctx, `
			INSERT INTO core.user_attributes (user_id, attribute_id, org_id, value, value_sealed)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)`,
			userID, attrID, orgID, c.clear, c.sealed)
		if err == nil {
			t.Errorf("a row holding %s value was accepted", c.what)
		}
		// Each failed statement aborts the transaction, so restart it.
		_ = tx.Rollback(ctx)
		tx, err = conn.Begin(ctx)
		must(t, err)
	}
	_ = tx.Rollback(ctx)
}
