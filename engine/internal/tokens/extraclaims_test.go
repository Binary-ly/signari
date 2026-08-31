package tokens

import (
	"encoding/json"
	"testing"
)

// An operator-defined claim can only ADD.
//
// Three layers enforce this and they are deliberately redundant: the schema
// refuses a protocol claim name at configuration time, provider.MayContribute
// refuses one at merge time, and MarshalJSON refuses one at serialisation. This
// tests the last, because it is the one that cannot be routed around — it
// operates on the bytes that get signed.

func TestAMappedClaimCannotOverwriteAProtocolClaim(t *testing.T) {
	c := IDTokenClaims{
		Issuer: "https://id.example.test", Subject: "real-user",
		Audience: "wiki", Expiry: 200, IssuedAt: 100,
		ACR: "urn:mace:incommon:iap:silver", AMR: []string{"pwd", "otp"},
		Extra: map[string]any{
			"sub":        "somebody-else",
			"iss":        "https://evil.test",
			"acr":        "urn:high",
			"amr":        []string{"mfa"},
			"department": "Engineering",
		},
	}

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	if got["sub"] != "real-user" {
		t.Fatalf("sub = %v; a mapped claim replaced the subject. That would let "+
			"an organisation issue tokens impersonating any user at every "+
			"relying party trusting this issuer.", got["sub"])
	}
	if got["iss"] != "https://id.example.test" {
		t.Errorf("iss = %v, overwritten", got["iss"])
	}
	if got["acr"] != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr = %v; a relying party reads this to decide the "+
			"authentication was strong enough", got["acr"])
	}

	// And the legitimate one survives, or the rule above is refusing everything.
	if got["department"] != "Engineering" {
		t.Errorf("department = %v, want Engineering", got["department"])
	}
}

// A token with no mapped claims serialises exactly as before.
func TestNoExtraClaimsLeavesTheTokenUnchanged(t *testing.T) {
	base := IDTokenClaims{
		Issuer: "https://id.example.test", Subject: "u", Audience: "a",
		Expiry: 200, IssuedAt: 100,
	}
	withEmpty := base
	withEmpty.Extra = map[string]any{}

	a, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(withEmpty)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("an empty Extra changed the token:\n%s\n%s", a, b)
	}
}

// Extra never appears as a claim of its own.
func TestExtraIsNotItselfAClaim(t *testing.T) {
	raw, err := json.Marshal(IDTokenClaims{
		Issuer: "i", Subject: "s", Audience: "a", Expiry: 2, IssuedAt: 1,
		Extra: map[string]any{"x": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, present := got["Extra"]; present {
		t.Error("the Extra map was emitted as a claim")
	}
	if got["x"] != float64(1) {
		t.Errorf("the extra claim was not merged: %v", got)
	}
}
