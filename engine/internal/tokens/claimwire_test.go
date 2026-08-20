package tokens

import (
	"encoding/json"
	"strings"
	"testing"
)

// OIDC Core §5.1 on `email_verified`:
//
//	"True if the End-User's e-mail address has been verified; otherwise false."
//
// Otherwise FALSE — not "otherwise absent". The distinction is the whole value
// of the claim: a relying party deciding whether to trust an address needs
// "asserted, and it is not verified" to look different from "not asserted".
// Several relying parties treat an absent `email_verified` as unknown and a few
// treat it as true, so an unverified address that silently loses its claim is an
// account-linking hazard at the receiving end.
//
// `IDTokenClaims.EmailVerified` is a *bool for exactly this reason, and
// `flow.go` always assigns it when the email scope is granted. Neither fact was
// pinned. Changing the field to a plain `bool` keeps every existing test green —
// it is the same one-word class as AuthZEN's `decision` — and makes every
// unverified address indistinguishable from an unasserted one.
func TestAnUnverifiedEmailSaysSoRatherThanGoingQuiet(t *testing.T) {
	no, yes := false, true

	b, err := json.Marshal(IDTokenClaims{
		Issuer: "https://idp.example", Subject: "u-1", Audience: "c-1",
		Email: "alice@example.com", EmailVerified: &no,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"email_verified":false`) {
		t.Fatalf("an unverified address serialised as %s. OIDC Core §5.1 says "+
			"\"otherwise false\", and a relying party cannot distinguish an "+
			"unverified address from an unasserted one if the claim disappears. "+
			"The usual cause is the field losing its pointer type", b)
	}

	b, err = json.Marshal(IDTokenClaims{
		Issuer: "https://idp.example", Subject: "u-1", Audience: "c-1",
		Email: "alice@example.com", EmailVerified: &yes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"email_verified":true`) {
		t.Fatalf("a verified address serialised as %s", b)
	}

	// And when the email scope was not granted there is nothing to assert, so
	// the claim is genuinely absent rather than false. Omitting it and asserting
	// false are different statements and both are needed.
	b, err = json.Marshal(IDTokenClaims{
		Issuer: "https://idp.example", Subject: "u-1", Audience: "c-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "email_verified") {
		t.Errorf("a token with no email scope still carried an email_verified "+
			"claim: %s", b)
	}
}
