package store

import "testing"

// An allow-list is only a control when the value it filters is vouched for.
//
// With attestation conveyance `none` the AAGUID is self-asserted: a software
// authenticator can put a hardware vendor's identifier in the field. Comparing
// it to an allow-list would be filtering a value chosen by the party being
// filtered — which is not a filter, and is worse than none because it reads as
// one on a compliance questionnaire.

var yubicoish = []byte{
	0xd8, 0x52, 0x2d, 0x9f, 0x57, 0x5b, 0x48, 0x66,
	0x88, 0xa9, 0xba, 0x99, 0xfa, 0x02, 0xf3, 0x5b,
}

func TestAnEmptyAllowListPermitsAnything(t *testing.T) {
	p := DefaultWebAuthnPolicy()
	if ok, why := p.PermitsAuthenticator(yubicoish, false); !ok {
		t.Fatalf("an organisation with no allow-list refused an authenticator: %s", why)
	}
}

func TestAnAllowListRefusesUnverifiedAttestation(t *testing.T) {
	p := WebAuthnPolicy{
		Conveyance:     "direct",
		AllowedAAGUIDs: []string{"d8522d9f-575b-4866-88a9-ba99fa02f35b"},
	}

	// The AAGUID MATCHES. It must still be refused, because nothing vouched for
	// it: this is precisely the case where a software authenticator claims a
	// hardware vendor's identifier.
	ok, why := p.PermitsAuthenticator(yubicoish, false)
	if ok {
		t.Fatal("an allow-list accepted a matching but SELF-ASSERTED AAGUID. " +
			"The value being filtered was chosen by the party being filtered.")
	}
	if why == "" {
		t.Error("the refusal gave no reason")
	}
}

func TestAnAllowListAcceptsAVerifiedMatch(t *testing.T) {
	p := WebAuthnPolicy{
		Conveyance:     "direct",
		AllowedAAGUIDs: []string{"d8522d9f-575b-4866-88a9-ba99fa02f35b"},
	}
	if ok, why := p.PermitsAuthenticator(yubicoish, true); !ok {
		t.Fatalf("a verified, allow-listed authenticator was refused: %s", why)
	}
}

func TestAnAllowListRefusesAVerifiedNonMatch(t *testing.T) {
	p := WebAuthnPolicy{
		Conveyance:     "direct",
		AllowedAAGUIDs: []string{"00000000-0000-4000-8000-000000000001"},
	}
	if ok, _ := p.PermitsAuthenticator(yubicoish, true); ok {
		t.Fatal("an authenticator not on the list was accepted")
	}
}

// The all-zero AAGUID is "I decline to identify myself", not a value.
//
// Treating it as one would let every such device match a single allow-list entry
// of zeroes — and every privacy-preserving authenticator sends it.
func TestTheAllZeroAAGUIDNeverMatches(t *testing.T) {
	p := WebAuthnPolicy{
		Conveyance:     "direct",
		AllowedAAGUIDs: []string{"00000000-0000-0000-0000-000000000000"},
	}
	if ok, _ := p.PermitsAuthenticator(make([]byte, 16), true); ok {
		t.Fatal("the all-zero AAGUID matched an allow-list entry of zeroes. " +
			"Every authenticator that declines to identify itself would pass.")
	}
}

func TestRequiresAttestationReflectsTheConveyance(t *testing.T) {
	for conveyance, want := range map[string]bool{
		"":         false,
		"none":     false,
		"indirect": true,
		"direct":   true,
	} {
		if got := (WebAuthnPolicy{Conveyance: conveyance}).RequiresAttestation(); got != want {
			t.Errorf("conveyance %q: RequiresAttestation = %v, want %v", conveyance, got, want)
		}
	}
}

// The database refuses an allow-list with no attestation to verify it.
func TestAnAllowListWithoutAttestationIsRefusedByTheSchema(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO core.webauthn_policy (org_id, attestation_conveyance, allowed_aaguids)
		VALUES ($1::uuid, 'none', ARRAY['d8522d9f-575b-4866-88a9-ba99fa02f35b']::uuid[])`,
		orgID)
	if err == nil {
		t.Fatal("an allow-list was accepted alongside conveyance 'none'. The " +
			"AAGUIDs it filters would be self-asserted, so the policy would read " +
			"as a control and be theatre.")
	}
}
