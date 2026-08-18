// Package oid4vci implements the authorization server's half of OpenID for
// Verifiable Credential Issuance 1.0 (Final, 16 September 2025).
//
// # Which half
//
// OID4VCI separates two roles. The **Credential Issuer** holds the credential
// endpoint and knows how to mint an SD-JWT VC or an ISO mdoc. The
// **Authorization Server** issues the access token that credential endpoint will
// accept. Signari is the second, so its entire contribution to OID4VCI is the
// Pre-Authorized Code grant and the Credential Offer that carries it.
//
// Nothing here mints a credential, and nothing advertises that it can.
//
// # Why this grant needs more care than it looks
//
// §6.1: "For the Pre-Authorized Code Grant Type, authentication of the Client is
// OPTIONAL". The pre-authorized code IS the credential — whoever presents it
// receives a token. Two things carry the weight a client secret normally would:
//
//   - the code "MUST be short lived and single use" (§3.5), and
//   - the optional Transaction Code, which §3.5 explains exactly: it exists "to
//     bind the Pre-Authorized Code to a certain transaction to prevent replay of
//     this code by an attacker that, for example, scanned the QR code while
//     standing behind the legitimate End-User".
//
// That last sentence is the threat model. A pre-authorized code is usually a QR
// code on a screen, and the attacker is a person with a phone standing behind
// the holder. The transaction code travels by a different channel so that
// photographing the screen is not enough.
package oid4vci

import (
	"fmt"
	"strings"
	"time"
)

// GrantType is the pre-authorized code grant.
const GrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// CredentialOfferURIScheme is the scheme a wallet is invoked with (§G.7.1).
const CredentialOfferURIScheme = "openid-credential-offer"

// WellKnownPath is the Credential Issuer metadata location (§G.5.1).
const WellKnownPath = "/.well-known/openid-credential-issuer"

// MaxTxCodeAttempts bounds guesses against one pre-authorized code.
//
// A transaction code is short and user-entered — §3.5's `length` exists so a
// wallet can render an input box — which makes it guessable in the same way a
// device flow user code is.
//
// Bounded PER CODE rather than per address, and the difference matters. The
// device flow's user code is drawn from one space shared by every device, so an
// attacker guessing there is attacking the space and the limit belongs on the
// guesser. A transaction code belongs to one offer, so an attacker is attacking
// that offer — and a per-address limit would let them move addresses while a
// per-code limit ends the offer.
const MaxTxCodeAttempts = 5

// InputMode values (§3.5).
const (
	InputNumeric = "numeric"
	InputText    = "text"
)

// TxCode describes a required Transaction Code, as it appears in an offer.
//
// A nil *TxCode means the offer carries no `tx_code` object and a token request
// MUST NOT send one. A non-nil but zero-valued TxCode is a present-but-empty
// object, which §3.5 says still REQUIRES a value in the token request:
//
//	"This value MUST be present if a tx_code object was present in the Credential
//	Offer (including if the object was empty)."
//
// So "absent" and "empty" are different states and a pointer is what keeps them
// apart. Collapsing them is how a required transaction code becomes optional.
type TxCode struct {
	InputMode   string `json:"input_mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

// Offer is a Credential Offer (§3.4).
type Offer struct {
	CredentialIssuer string   `json:"credential_issuer"`
	ConfigurationIDs []string `json:"credential_configuration_ids"`
	Grants           Grants   `json:"grants"`
}

// Grants is the offer's `grants` member.
type Grants struct {
	PreAuthorized *PreAuthorizedGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

// PreAuthorizedGrant is the pre-authorized code grant inside an offer.
type PreAuthorizedGrant struct {
	// Code is the pre-authorized code itself. §3.5: REQUIRED.
	Code string `json:"pre-authorized_code"`
	// TxCode is present only when a Transaction Code is required.
	TxCode *TxCode `json:"tx_code,omitempty"`
	// AuthorizationServer names which AS to use, and §3.5 is explicit that it
	// "MUST NOT be used otherwise" than when the issuer metadata lists several.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// BuildOffer assembles a Credential Offer.
func BuildOffer(issuer string, configurationIDs []string, code string, tx *TxCode) (*Offer, error) {
	if err := ValidateIssuer(issuer); err != nil {
		return nil, err
	}
	if len(configurationIDs) == 0 {
		return nil, fmt.Errorf("a credential offer must name at least one " +
			"credential_configuration_id; an offer of nothing is not an offer")
	}
	if code == "" {
		return nil, fmt.Errorf("the pre-authorized code is required (section 3.5)")
	}
	if tx != nil {
		if tx.InputMode != "" && tx.InputMode != InputNumeric && tx.InputMode != InputText {
			return nil, fmt.Errorf("tx_code input_mode %q is not one of %q or %q",
				tx.InputMode, InputNumeric, InputText)
		}
	}
	return &Offer{
		CredentialIssuer: strings.TrimRight(issuer, "/"),
		ConfigurationIDs: configurationIDs,
		Grants:           Grants{PreAuthorized: &PreAuthorizedGrant{Code: code, TxCode: tx}},
	}, nil
}

// ValidateIssuer applies §12.2.1's constraint on a Credential Issuer identifier.
//
// The metadata rule that motivates it (§12.2.3) is the same mix-up defence
// AuthZEN §9.2.3 and OpenID Federation §9 both state: "The value MUST be
// identical to the Credential Issuer's identifier value into which the
// well-known URI string was inserted... If these values are not identical...
// the data contained in the response MUST NOT be used."
func ValidateIssuer(id string) error {
	if id == "" {
		return fmt.Errorf("a credential issuer identifier is required")
	}
	if !strings.HasPrefix(id, "https://") {
		return fmt.Errorf("the credential issuer identifier %q must use the https "+
			"scheme", id)
	}
	if strings.ContainsAny(id, "?#") {
		return fmt.Errorf("the credential issuer identifier %q must not carry a "+
			"query or fragment: the metadata URL is formed by inserting %q into it",
			id, WellKnownPath)
	}
	return nil
}

// TokenRequest is the pre-authorized code half of a token request (§6.1).
type TokenRequest struct {
	GrantType string
	Code      string
	TxCode    string
}

// StoredCode is a pre-authorized code as recorded at issue time.
type StoredCode struct {
	ConfigurationIDs []string
	// RequiresTxCode is true when the offer carried a `tx_code` object, empty or
	// not. See TxCode's documentation for why this is not derived from whether a
	// transaction code value is non-empty.
	RequiresTxCode bool
	Attempts       int
	ExpiresAt      time.Time
	Redeemed       bool
}

// ValidateTokenRequest applies §6.1's rules to a pre-authorized code redemption.
//
// It deliberately does NOT compare the transaction code: that comparison must be
// constant-time against a stored hash, which is the caller's business, and
// putting it here would mean either passing the plaintext around or duplicating
// the hashing. What this decides is whether a comparison should happen at all,
// which is the part the specification governs.
func ValidateTokenRequest(req TokenRequest, stored *StoredCode, now time.Time) error {
	if req.GrantType != GrantType {
		return fmt.Errorf("grant_type must be %s", GrantType)
	}
	if req.Code == "" {
		// §6.1: "This parameter MUST be present if the grant_type is
		// urn:ietf:params:oauth:grant-type:pre-authorized_code".
		return fmt.Errorf("pre-authorized_code is required for this grant type")
	}
	if stored == nil {
		return fmt.Errorf("this pre-authorized code is unknown or has expired")
	}
	if stored.Redeemed {
		// §3.5: the code "MUST be short lived and single use".
		return fmt.Errorf("this pre-authorized code has already been used")
	}
	if !now.Before(stored.ExpiresAt) {
		return fmt.Errorf("this pre-authorized code has expired")
	}
	if stored.Attempts >= MaxTxCodeAttempts {
		// The offer is spent rather than the guesser slowed. A transaction code
		// is a handful of digits; anything that lets an attacker keep trying is
		// a rounding error away from no protection at all.
		return fmt.Errorf("too many incorrect transaction codes for this offer; "+
			"it has been refused after %d attempts", MaxTxCodeAttempts)
	}

	// §6.1: tx_code "MUST be present if a tx_code object was present in the
	// Credential Offer (including if the object was empty)".
	if stored.RequiresTxCode && req.TxCode == "" {
		return fmt.Errorf("this offer requires a transaction code and none was sent")
	}
	// And the converse: "This parameter MUST only be used if the grant_type is
	// urn:ietf:params:oauth:grant-type:pre-authorized_code" -- and, by the same
	// reading, only when the offer asked for one. A transaction code arriving
	// unasked means the wallet and the issuer disagree about what this offer is,
	// and proceeding would silently accept the wallet's version.
	if !stored.RequiresTxCode && req.TxCode != "" {
		return fmt.Errorf("a transaction code was sent but this offer does not " +
			"require one")
	}
	return nil
}
