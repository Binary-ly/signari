package store

import (
	"fmt"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
)

// A service provider's declared attribute release actually reaches the
// assertion, and an erased subject's does not.
//
// `saml_providers.attributes` was configurable and read by nothing, which is a
// disclosure control failing in the direction that looks like success: the
// operator sees the column hold what they asked for and believes it applied.
func TestSAMLAttributeReleaseUsesTheSealedStore(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	stamp := time.Now().UnixNano()

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	attrName := fmt.Sprintf("dept_%d", stamp)
	_, err = DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attrName, "Engineering", root))

	// A provider that releases it under a SAML attribute name.
	var providerID string
	must(t, tx.QueryRow(ctx, `
		INSERT INTO core.saml_providers (org_id, entity_id, display_name, attributes)
		VALUES ($1::uuid, $2, 'SP', jsonb_build_object($3::text, $4::text))
		RETURNING id::text`,
		orgID, fmt.Sprintf("https://sp-%d.test", stamp),
		"http://schemas.example/department", attrName).Scan(&providerID))

	got, err := SAMLAttributes(ctx, tx, userID, providerID, root)
	must(t, err)
	if got["http://schemas.example/department"] != "Engineering" {
		t.Fatalf("released = %v, want the department. The column was configurable "+
			"and read by nothing for months; this is the test that it is wired.", got)
	}

	// After erasure it releases nothing, silently.
	must(t, keys.EraseSubject(ctx, tx, userID))
	after, err := SAMLAttributes(ctx, tx, userID, providerID, root)
	must(t, err)
	if len(after) != 0 {
		t.Fatalf("an erased subject still releases %v through SAML. Erasure "+
			"cannot be complete everywhere except the protocol enterprises "+
			"actually use.", after)
	}
}

// A provider that declares no release gets no attributes.
func TestASAMLProviderWithNoReleaseGetsNothing(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	stamp := time.Now().UnixNano()

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	attrName := fmt.Sprintf("secret_%d", stamp)
	_, err = DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attrName, "do not release", root))

	var providerID string
	must(t, tx.QueryRow(ctx, `
		INSERT INTO core.saml_providers (org_id, entity_id, display_name)
		VALUES ($1::uuid, $2, 'SP') RETURNING id::text`,
		orgID, fmt.Sprintf("https://quiet-sp-%d.test", stamp)).Scan(&providerID))

	got, err := SAMLAttributes(ctx, tx, userID, providerID, root)
	must(t, err)
	if len(got) != 0 {
		t.Fatalf("a provider declaring no release received %v. An attribute "+
			"existing must not disclose it to a service provider.", got)
	}
}
