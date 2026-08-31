package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// Claim mappers, and the three properties that make them safe to have.
//
//  1. Default deny. An attribute with no mapper reaches no token.
//  2. Scope-gating. A mapper that requires a scope releases nothing to a grant
//     that does not carry it, so a declined consent stays declined.
//  3. Erasure. A personal attribute belonging to an erased subject is omitted,
//     not reported, because a token is not a diagnostic surface.
//
// The first is the one that separates this design from the common one. Most
// products let attributes flow into tokens automatically and hold the sensitive
// ones back with a deny-list — which means adding an attribute is a disclosure
// to every relying party already integrated, made by whoever added it.

// mapperFixture declares an attribute, sets a value, and returns the ids.
func mapperFixture(t *testing.T) (ctx context.Context, orgID, userID, attrName string) {
	t.Helper()
	ctx, orgID, userID = profileFixture(t)
	attrName = fmt.Sprintf("mapped_%d", time.Now().UnixNano())
	return ctx, orgID, userID, attrName
}

func TestAnAttributeWithNoMapperReachesNoToken(t *testing.T) {
	ctx, orgID, userID, attrName := mapperFixture(t)
	conn := connect(t)
	root := profileRoot(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attrName, "secret value", root))

	// No mapper declared.
	claims, err := MappedClaims(ctx, tx, userID, orgID, "any-client",
		ClaimInIDToken, "openid profile", root)
	must(t, err)

	if len(claims) != 0 {
		t.Fatalf("an attribute with no mapper produced %d claims: %v.\n"+
			"Adding an attribute must never, by itself, disclose anything to a "+
			"relying party that is already integrated.", len(claims), claims)
	}
}

func TestAMappedClaimIsReleasedToTheNamedDestination(t *testing.T) {
	ctx, orgID, userID, attrName := mapperFixture(t)
	conn := connect(t)
	root := profileRoot(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attrName, "Engineering", root))

	declareMapper(t, ctx, tx, orgID, attrID, "department", "id_token", "")

	got, err := MappedClaims(ctx, tx, userID, orgID, "c1", ClaimInIDToken, "openid", root)
	must(t, err)
	if got["department"] != "Engineering" {
		t.Fatalf("id_token claims = %v, want department=Engineering", got)
	}

	// And NOT to a destination nobody named. An access token goes to resource
	// servers the user never saw a consent screen for, so it is the one that
	// leaks furthest.
	other, err := MappedClaims(ctx, tx, userID, orgID, "c1", ClaimInAccessToken, "openid", root)
	must(t, err)
	if len(other) != 0 {
		t.Fatalf("a claim mapped to the id_token appeared in the access token: %v", other)
	}
}

// A scope-gated claim is withheld from a grant that does not carry the scope.
func TestAScopeGatedClaimHonoursTheGrantedScope(t *testing.T) {
	ctx, orgID, userID, attrName := mapperFixture(t)
	conn := connect(t)
	root := profileRoot(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attrName, "Chief Engineer", root))

	declareMapper(t, ctx, tx, orgID, attrID, "job_title", "userinfo", "profile")

	withScope, err := MappedClaims(ctx, tx, userID, orgID, "c1",
		ClaimInUserInfo, "openid profile", root)
	must(t, err)
	if withScope["job_title"] != "Chief Engineer" {
		t.Fatalf("with the required scope, claims = %v", withScope)
	}

	without, err := MappedClaims(ctx, tx, userID, orgID, "c1",
		ClaimInUserInfo, "openid email", root)
	must(t, err)
	if _, present := without["job_title"]; present {
		t.Fatal("a scope-gated claim was released to a grant that does not carry " +
			"the scope. A user who declined `profile` must not receive a token " +
			"carrying their job title anyway.")
	}
}

// A mapper naming one client releases nothing to another.
func TestAClientScopedMapperDoesNotLeakToOtherClients(t *testing.T) {
	ctx, orgID, userID, attrName := mapperFixture(t)
	conn := connect(t)
	root := profileRoot(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	// A real client to reference, since client_id is a foreign key.
	clientID := fmt.Sprintf("mapper-client-%d", time.Now().UnixNano())
	_, err = tx.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash)
		VALUES ($1, $2::uuid, 'T', 'confidential', 'x')`, clientID, orgID)
	must(t, err)

	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attrName, "12 Rue de la Paix", root))

	_, err = tx.Exec(ctx, `
		INSERT INTO core.claim_mappers
			(org_id, client_id, attribute_id, claim_name, destination, required_scope)
		VALUES ($1::uuid, $2, $3::uuid, 'address', 'userinfo', '')`,
		orgID, clientID, attrID)
	must(t, err)

	mine, err := MappedClaims(ctx, tx, userID, orgID, clientID, ClaimInUserInfo, "openid", root)
	must(t, err)
	if mine["address"] != "12 Rue de la Paix" {
		t.Fatalf("the named client did not receive the claim: %v", mine)
	}

	theirs, err := MappedClaims(ctx, tx, userID, orgID, "some-other-client",
		ClaimInUserInfo, "openid", root)
	must(t, err)
	if _, present := theirs["address"]; present {
		t.Fatal("a mapper naming one client released to another")
	}
}

// An erased subject's personal claim is omitted, not reported.
func TestAnErasedSubjectReleasesNoPersonalClaim(t *testing.T) {
	ctx, orgID, userID, attrName := mapperFixture(t)
	conn := connect(t)
	root := profileRoot(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: true,
	})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attrName, "12 Rue de la Paix", root))
	declareMapper(t, ctx, tx, orgID, attrID, "address", "userinfo", "")

	before, err := MappedClaims(ctx, tx, userID, orgID, "c1", ClaimInUserInfo, "openid", root)
	must(t, err)
	if before["address"] == nil {
		t.Fatal("the fixture claim is not released before erasure")
	}

	must(t, keys.EraseSubject(ctx, tx, userID))

	after, err := MappedClaims(ctx, tx, userID, orgID, "c1", ClaimInUserInfo, "openid", root)
	must(t, err)
	if v, present := after["address"]; present {
		t.Fatalf("an erased subject still releases a personal claim: %v", v)
	}
}

// The database refuses a mapper that would forge a protocol claim.
//
// A mapper writing `sub` would let an organisation issue tokens impersonating
// any subject at every relying party trusting this issuer. `acr` and `amr` are
// one step removed and just as bad: they are what a relying party reads to
// decide the authentication was strong enough.
func TestAMapperCannotOverwriteAProtocolClaim(t *testing.T) {
	ctx, orgID, _, attrName := mapperFixture(t)
	conn := connect(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	attrID, err := DeclareAttribute(ctx, tx, orgID, Attribute{
		Name: attrName, ValueType: "string", Personal: false,
	})
	must(t, err)

	for _, claim := range []string{"sub", "iss", "aud", "exp", "acr", "amr", "scope", "cnf"} {
		_, err := tx.Exec(ctx, `
			INSERT INTO core.claim_mappers
				(org_id, attribute_id, claim_name, destination, required_scope)
			VALUES ($1::uuid, $2::uuid, $3, 'id_token', '')`,
			orgID, attrID, claim)
		if err == nil {
			t.Errorf("a mapper writing %q was accepted", claim)
		}
		_ = tx.Rollback(ctx)
		tx, err = conn.Begin(ctx)
		must(t, err)
	}
	_ = tx.Rollback(ctx)
}

func declareMapper(t *testing.T, ctx context.Context, tx pgx.Tx,
	orgID, attrID, claim, dest, scope string) {
	t.Helper()
	_, err := tx.Exec(ctx, `
		INSERT INTO core.claim_mappers
			(org_id, client_id, attribute_id, claim_name, destination, required_scope)
		VALUES ($1::uuid, NULL, $2::uuid, $3, $4, $5)`,
		orgID, attrID, claim, dest, scope)
	must(t, err)
}
