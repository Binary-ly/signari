package store

import (
	"fmt"
	"testing"
	"time"
)

// Mapping an upstream provider's claims into local attributes.
//
// The direction that matters: this decides what a party this deployment does
// NOT control may write into it. Default deny, because a shape that copied
// every claim would let whoever runs the upstream provider write arbitrary
// state onto local accounts — and if any access policy ever reads an attribute,
// that is the provider deciding local authorization.

func idpFixture(t *testing.T, orgID string) string {
	t.Helper()
	conn := connect(t)
	var id string
	must(t, conn.QueryRow(t.Context(), `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, $2, 'Upstream', 'oidc', 'cid')
		RETURNING id::text`,
		orgID, fmt.Sprintf("idp-%d", time.Now().UnixNano())).Scan(&id))
	t.Cleanup(func() {
		_, _ = conn.Exec(t.Context(),
			`DELETE FROM core.identity_providers WHERE id = $1::uuid`, id)
	})
	return id
}

// An unmapped claim is never written, however helpful it looks.
func TestAnUnmappedUpstreamClaimIsNotWritten(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	providerID := idpFixture(t, orgID)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("dept_%d", time.Now().UnixNano())
	_, err = DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: name, ValueType: "string", Personal: true,
	})
	must(t, err)

	// No mapping declared. The provider sends the claim anyway.
	raw := []byte(fmt.Sprintf(`{"sub":"u1","%s":"Engineering","role":"admin"}`, name))
	applied, _, err := ApplyIDPAttributeMapping(ctx, tx, userID, orgID, providerID, raw, root)
	must(t, err)
	if applied != 0 {
		t.Fatalf("wrote %d attributes with no mapping declared. An upstream "+
			"provider must not be able to write local state by adding a claim.",
			applied)
	}
}

// A mapped claim is written, and only that one.
func TestOnlyMappedClaimsAreWritten(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	providerID := idpFixture(t, orgID)
	stamp := time.Now().UnixNano()

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	mapped := fmt.Sprintf("dept_%d", stamp)
	unmapped := fmt.Sprintf("clearance_%d", stamp)
	mappedID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: mapped, ValueType: "string", Personal: true,
	})
	must(t, err)
	_, err = DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: unmapped, ValueType: "string", Personal: true,
	})
	must(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO core.idp_attribute_map (provider_id, org_id, upstream_claim, attribute_id)
		VALUES ($1::uuid, $2::uuid, 'department', $3::uuid)`, providerID, orgID, mappedID)
	must(t, err)

	// The provider sends both. Only the mapped one may land.
	raw := []byte(fmt.Sprintf(`{"department":"Engineering","%s":"TOP SECRET"}`, unmapped))
	applied, _, err := ApplyIDPAttributeMapping(ctx, tx, userID, orgID, providerID, raw, root)
	must(t, err)
	if applied != 1 {
		t.Fatalf("applied %d, want 1", applied)
	}

	got, err := UserAttributes(ctx, tx, userID, orgID, root)
	must(t, err)
	for _, a := range got {
		if a.Name == unmapped {
			t.Fatalf("an unmapped attribute was written from an upstream claim: %q", a.Value)
		}
		if a.Name == mapped && a.Value != "Engineering" {
			t.Errorf("mapped value = %q, want Engineering", a.Value)
		}
	}
}

// An over-length value is refused, not truncated.
//
// A truncated value is a wrong value that looks like a right one: a department
// cut from "Engineering (Platform)" to "Engineering" reads as correct.
func TestAnOverLengthClaimIsRefusedNotTruncated(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	providerID := idpFixture(t, orgID)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("note_%d", time.Now().UnixNano())
	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: name, ValueType: "string", Personal: true,
	})
	must(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO core.idp_attribute_map
			(provider_id, org_id, upstream_claim, attribute_id, max_length)
		VALUES ($1::uuid, $2::uuid, 'note', $3::uuid, 8)`, providerID, orgID, attrID)
	must(t, err)

	raw := []byte(`{"note":"far too long for the declared bound"}`)
	applied, skipped, err := ApplyIDPAttributeMapping(ctx, tx, userID, orgID, providerID, raw, root)
	must(t, err)
	if applied != 0 || skipped != 1 {
		t.Fatalf("applied=%d skipped=%d, want 0 and 1", applied, skipped)
	}

	got, err := UserAttributes(ctx, tx, userID, orgID, root)
	must(t, err)
	for _, a := range got {
		if a.Name == name {
			t.Fatalf("an over-length value was stored as %q. Truncating produces "+
				"a wrong value that reads as a right one.", a.Value)
		}
	}
}

// An existing value is not overwritten unless the mapping says so.
func TestAnExistingValueSurvivesUnlessOverwriteIsSet(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	providerID := idpFixture(t, orgID)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("title_%d", time.Now().UnixNano())
	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: name, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, name, "Set by an administrator", root))

	_, err = tx.Exec(ctx, `
		INSERT INTO core.idp_attribute_map (provider_id, org_id, upstream_claim, attribute_id)
		VALUES ($1::uuid, $2::uuid, 'title', $3::uuid)`, providerID, orgID, attrID)
	must(t, err)

	raw := []byte(`{"title":"Set by the provider"}`)
	_, _, err = ApplyIDPAttributeMapping(ctx, tx, userID, orgID, providerID, raw, root)
	must(t, err)

	got, err := UserAttributes(ctx, tx, userID, orgID, root)
	must(t, err)
	for _, a := range got {
		if a.Name == name && a.Value != "Set by an administrator" {
			t.Fatalf("value = %q; an administrator's value must not be silently "+
				"replaced by the provider's unless overwrite was chosen", a.Value)
		}
	}
}

// Objects and arrays do not map onto a string attribute.
func TestAStructuredClaimIsNotFlattenedIntoAnAttribute(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	providerID := idpFixture(t, orgID)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("obj_%d", time.Now().UnixNano())
	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: name, ValueType: "string", Personal: false,
	})
	must(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO core.idp_attribute_map (provider_id, org_id, upstream_claim, attribute_id)
		VALUES ($1::uuid, $2::uuid, 'address', $3::uuid)`, providerID, orgID, attrID)
	must(t, err)

	raw := []byte(`{"address":{"street":"12 Rue de la Paix","city":"Paris"}}`)
	applied, _, err := ApplyIDPAttributeMapping(ctx, tx, userID, orgID, providerID, raw, root)
	must(t, err)
	if applied != 0 {
		t.Fatal("a JSON object was flattened into a string attribute. Every " +
			"consumer downstream would then have to guess its shape.")
	}
}
