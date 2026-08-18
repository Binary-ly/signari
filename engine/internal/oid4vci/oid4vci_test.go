package oid4vci

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func live(tx bool) *StoredCode {
	return &StoredCode{
		ConfigurationIDs: []string{"UniversityDegree"},
		RequiresTxCode:   tx,
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
}

func req(code, tx string) TokenRequest {
	return TokenRequest{GrantType: GrantType, Code: code, TxCode: tx}
}

// §6.1: tx_code "MUST be present if a tx_code object was present in the
// Credential Offer (including if the object was empty)".
//
// The parenthetical is the whole reason `TxCode` is a pointer and `StoredCode`
// carries an explicit RequiresTxCode. An empty `{}` object in an offer still
// demands a value at the token endpoint — so "no transaction code" and "a
// transaction code with no declared length" are different states, and collapsing
// them turns a required check into an optional one.
func TestAnEmptyTxCodeObjectStillRequiresAValue(t *testing.T) {
	// The offer said `"tx_code": {}` — no length, no input_mode, no description.
	offer, err := BuildOffer("https://issuer.example", []string{"UniversityDegree"},
		"code-1", &TxCode{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(offer)
	if !strings.Contains(string(raw), `"tx_code":{}`) {
		t.Fatalf("an empty tx_code object was not emitted: %s", raw)
	}

	// And a token request with no tx_code is refused.
	if err := ValidateTokenRequest(req("code-1", ""), live(true), time.Now()); err == nil {
		t.Fatal("an offer with an empty tx_code object accepted a token request " +
			"carrying no transaction code")
	}
	// With one, it passes.
	if err := ValidateTokenRequest(req("code-1", "1234"), live(true), time.Now()); err != nil {
		t.Fatalf("a transaction code was refused: %v", err)
	}
}

// An offer with no tx_code object must not accept one.
//
// A transaction code arriving unasked means the wallet and the issuer disagree
// about what this offer is, and proceeding accepts the wallet's version.
func TestATransactionCodeArrivingUnaskedIsRefused(t *testing.T) {
	if err := ValidateTokenRequest(req("code-1", "1234"), live(false), time.Now()); err == nil {
		t.Fatal("a transaction code was accepted for an offer that never asked for one")
	}
	if err := ValidateTokenRequest(req("code-1", ""), live(false), time.Now()); err != nil {
		t.Fatalf("an offer without a transaction code was refused: %v", err)
	}
}

// §3.5: the code "MUST be short lived and single use".
func TestAPreAuthorizedCodeIsSingleUseAndShortLived(t *testing.T) {
	spent := live(false)
	spent.Redeemed = true
	if err := ValidateTokenRequest(req("code-1", ""), spent, time.Now()); err == nil {
		t.Error("a redeemed pre-authorized code was accepted a second time")
	}

	expired := live(false)
	expired.ExpiresAt = time.Now().Add(-time.Second)
	if err := ValidateTokenRequest(req("code-1", ""), expired, time.Now()); err == nil {
		t.Error("an expired pre-authorized code was accepted")
	}

	if err := ValidateTokenRequest(req("code-1", ""), nil, time.Now()); err == nil {
		t.Error("an unknown pre-authorized code was accepted")
	}
}

// The transaction code exists "to prevent replay of this code by an attacker
// that, for example, scanned the QR code while standing behind the legitimate
// End-User" (§3.5). It is a handful of digits, so unbounded guessing removes the
// protection entirely.
func TestGuessingTheTransactionCodeEndsTheOffer(t *testing.T) {
	c := live(true)
	c.Attempts = MaxTxCodeAttempts

	err := ValidateTokenRequest(req("code-1", "9999"), c, time.Now())
	if err == nil {
		t.Fatal("a pre-authorized code accepted an unlimited number of " +
			"transaction code guesses; the code is a few digits, so that is no " +
			"protection at all")
	}
	if !strings.Contains(err.Error(), "attempts") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// One below the limit still works, so the boundary is where it claims to be.
	c.Attempts = MaxTxCodeAttempts - 1
	if err := ValidateTokenRequest(req("code-1", "1234"), c, time.Now()); err != nil {
		t.Errorf("the last permitted attempt was refused: %v", err)
	}
}

// The grant type is fixed, and tx_code belongs only to it.
func TestTheGrantTypeIsSpelledExactly(t *testing.T) {
	if GrantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		t.Fatalf("grant type = %q", GrantType)
	}
	r := req("code-1", "")
	r.GrantType = "authorization_code"
	if err := ValidateTokenRequest(r, live(false), time.Now()); err == nil {
		t.Error("a different grant type was accepted by the pre-authorized path")
	}
	r.GrantType = GrantType
	r.Code = ""
	if err := ValidateTokenRequest(r, live(false), time.Now()); err == nil {
		t.Error("the grant type was accepted with no pre-authorized_code")
	}
}

// §12.2.1 / §12.2.3: the issuer identifier is what the metadata URL is built
// from, and the document must echo it identically.
func TestTheIssuerIdentifierIsConstrained(t *testing.T) {
	for _, bad := range []string{
		"", "http://issuer.example", "issuer.example",
		"https://issuer.example?x=1", "https://issuer.example#f",
	} {
		if err := ValidateIssuer(bad); err == nil {
			t.Errorf("%q was accepted as a credential issuer identifier", bad)
		}
	}
	for _, ok := range []string{
		"https://issuer.example", "https://issuer.example:8443", "https://issuer.example/tenant",
	} {
		if err := ValidateIssuer(ok); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}
}

// An offer of nothing is not an offer.
func TestAnOfferMustNameACredential(t *testing.T) {
	if _, err := BuildOffer("https://issuer.example", nil, "code-1", nil); err == nil {
		t.Fatal("an offer naming no credential configuration was built")
	}
	if _, err := BuildOffer("https://issuer.example", []string{"X"}, "", nil); err == nil {
		t.Fatal("an offer with no pre-authorized code was built")
	}
	// input_mode is constrained to the two values §3.5 defines.
	if _, err := BuildOffer("https://issuer.example", []string{"X"}, "c",
		&TxCode{InputMode: "alphanumeric"}); err == nil {
		t.Fatal("an unrecognised tx_code input_mode was accepted")
	}
}
