package oid4vci

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/sdjwt"
)

// The Credential Endpoint, OID4VCI §8.
//
// This is the half migration 0077 deliberately left out: that made Signari the
// authorization server for OID4VCI, issuing the access token a credential
// endpoint would accept. This mints the credential itself.

// FormatSDJWTVC is the only credential format implemented.
const FormatSDJWTVC = "dc+sd-jwt"

// MaxProofsPerRequest bounds how many credentials one request may mint.
//
// §8.3 anticipates an issuer limit outright: the credentials array "matches the
// number of keys that the Wallet has provided via the proofs parameter, unless
// the Issuer decides to issue fewer Credentials."
//
// The bound is not cosmetic. Every proof costs a database round trip to spend
// its c_nonce, a signature verification, a subject read and a signature — so an
// unbounded array turns one HTTP request into thousands of database round trips.
// The request body is capped at a megabyte, which at roughly four hundred bytes
// per proof still leaves room for a couple of thousand.
//
// Thirty-two is generous for the legitimate case. A wallet batches keys for
// unlinkability — a handful per device — and nothing needs hundreds.
const MaxProofsPerRequest = 32

// CredentialRequest is §8.2's request body.
type CredentialRequest struct {
	// ConfigurationID names an entry in credential_configurations_supported.
	ConfigurationID string `json:"credential_configuration_id,omitempty"`
	// CredentialIdentifier is the authorization_details-driven alternative.
	CredentialIdentifier string `json:"credential_identifier,omitempty"`
	// Proofs carries key proofs, keyed by proof type (§8.2).
	Proofs map[string][]json.RawMessage `json:"proofs,omitempty"`
}

// CredentialResponse is §8.3's response body.
type CredentialResponse struct {
	Credentials []IssuedCredential `json:"credentials,omitempty"`
	// NotificationID is optional and only meaningful alongside credentials.
	NotificationID string `json:"notification_id,omitempty"`
}

// IssuedCredential is one element of the `credentials` array.
type IssuedCredential struct {
	Credential string `json:"credential"`
}

// Configuration is one entry of credential_configurations_supported.
type Configuration struct {
	ID     string
	Format string
	VCT    string
	// AlwaysClaims are visible to every verifier the holder presents to.
	AlwaysClaims []string
	// SelectiveClaims are visible only when the holder chooses to reveal them.
	SelectiveClaims []string
	Lifetime        time.Duration
	DisplayName     string
}

// ValidateRequest applies §8.2's parameter rules.
//
// Returns the proofs to validate. The caller validates them, because that needs
// the issuer identity and the nonce, which are not the request's business.
func (r CredentialRequest) Validate() ([]string, error) {
	// §8.2: `credential_identifier` is "REQUIRED when an Authorization Details
	// of type openid_credential was returned from the Token Response. It MUST
	// NOT be used otherwise", and when it is used "the credential_configuration_id
	// MUST NOT be present". We do not issue those authorization details yet, so
	// the identifier form cannot be correct here -- and accepting it would mean
	// resolving an identifier we never handed out.
	if r.CredentialIdentifier != "" {
		return nil, fmt.Errorf("credential_identifier is only usable when the " +
			"token response returned authorization_details of type " +
			"openid_credential, which this issuer does not yet do; send " +
			"credential_configuration_id instead")
	}
	if strings.TrimSpace(r.ConfigurationID) == "" {
		return nil, fmt.Errorf("credential_configuration_id is required")
	}

	// §8.2: "The proofs parameter contains exactly one parameter named as the
	// proof type". More than one would leave which proof type was actually
	// honoured up to map iteration order.
	if len(r.Proofs) == 0 {
		return nil, fmt.Errorf("proofs is required: a credential is bound to a " +
			"key, and without a proof there is no key to bind it to")
	}
	if len(r.Proofs) > 1 {
		names := make([]string, 0, len(r.Proofs))
		for k := range r.Proofs {
			names = append(names, k)
		}
		return nil, fmt.Errorf("proofs carries %d proof types (%s); section 8.2 "+
			"permits exactly one", len(r.Proofs), strings.Join(names, ", "))
	}
	raw, ok := r.Proofs[ProofTypeJWT]
	if !ok {
		for k := range r.Proofs {
			return nil, fmt.Errorf("proof type %q is not supported; this issuer "+
				"accepts %q", k, ProofTypeJWT)
		}
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("the jwt proofs array is empty")
	}
	if len(raw) > MaxProofsPerRequest {
		return nil, fmt.Errorf("this request carries %d key proofs and the limit "+
			"is %d: each one costs a nonce redemption, a signature verification "+
			"and a signature, so an unbounded array is one request that becomes "+
			"thousands of database round trips", len(raw), MaxProofsPerRequest)
	}

	out := make([]string, 0, len(raw))
	for i, m := range raw {
		var s string
		if err := json.Unmarshal(m, &s); err != nil {
			return nil, fmt.Errorf("proofs.jwt[%d] is not a string", i)
		}
		out = append(out, s)
	}
	return out, nil
}

// Issue builds one SD-JWT VC bound to the holder's key.
//
// `subject` are the claim values for this person, keyed by claim name; the
// configuration decides which are always visible and which are disclosable.
type Issuer struct {
	// CredentialIssuer is the identifier that becomes `iss`.
	CredentialIssuer string
	// Sign produces a compact JWS over the payload with the given typ.
	Sign func(payload []byte, typ string) (string, error)
}

// Issue returns the combined SD-JWT VC serialisation.
func (i Issuer) Issue(cfg Configuration, subject map[string]any,
	holderKey *jose.JSONWebKey, now time.Time) (string, error) {

	if cfg.Format != FormatSDJWTVC {
		return "", fmt.Errorf("credential format %q is not implemented", cfg.Format)
	}
	if holderKey == nil {
		return "", fmt.Errorf("no holder key: an unbound credential is a bearer " +
			"token, which is what binding exists to prevent")
	}

	// draft-ietf-oauth-sd-jwt-vc-18 §3.2.2.2: iss, nbf, exp, cnf and vct "MUST
	// NOT be included in the Disclosures, i.e., cannot be selectively disclosed".
	// They are the credential's own frame -- hiding the issuer or the expiry
	// would leave a verifier unable to decide anything at all.
	always := map[string]any{
		"iss": i.CredentialIssuer,
		"vct": cfg.VCT,
		"iat": now.Unix(),
		// §3.2.2.2: cnf is "REQUIRED" when key binding is supported. It is what
		// makes the credential presentable only by whoever holds the private key.
		"cnf": map[string]any{"jwk": holderKey},
	}
	if cfg.Lifetime > 0 {
		always["exp"] = now.Add(cfg.Lifetime).Unix()
	}

	// Claims are split by the configuration, and a claim the subject does not
	// have is omitted rather than emitted empty: an empty `given_name` is a
	// statement that the person has none.
	for _, name := range cfg.AlwaysClaims {
		if v, ok := subject[name]; ok && v != nil && v != "" {
			always[name] = v
		}
	}
	selective := map[string]any{}
	for _, name := range cfg.SelectiveClaims {
		if v, ok := subject[name]; ok && v != nil && v != "" {
			selective[name] = v
		}
	}

	payload, disclosures, err := sdjwt.Payload(always, selective)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	jwt, err := i.Sign(body, sdjwt.TypSDJWTVC)
	if err != nil {
		return "", fmt.Errorf("signing the credential: %w", err)
	}
	return sdjwt.Combine(jwt, disclosures), nil
}
