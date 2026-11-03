package oid4vci

import (
	"encoding/json"
	"errors"
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

// The credential formats implemented: an SD-JWT VC, and a W3C Verifiable Credential
// signed as a JWT (jwtvc.go).
const (
	FormatSDJWTVC = "dc+sd-jwt"
	FormatJWTVC   = "jwt_vc_json"
)

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
	// ResponseEncryption is §8.2's `credential_response_encryption`.
	//
	// Read by the endpoint, which alone knows the request came encrypted, as §8.2 has
	// it. §8.3: "If the Client requested an
	// encrypted response by including the credential_response_encryption object
	// in the request, the Credential Issuer MUST encode the information in the
	// Credential Response as specified by Section 10... Note that this is done
	// regardless of the content."
	//
	// Ignoring it — which is what happens when a field is simply absent from the
	// struct — returns the credential in the clear to a wallet that asked for it
	// encrypted, with a 200 and nothing to indicate otherwise. A wallet asks
	// because it does not trust something about the path the response takes, so
	// answering in plaintext defeats exactly the precaution it was taking.
	ResponseEncryption json.RawMessage `json:"credential_response_encryption,omitempty"`
}

// CredentialResponse is §8.3's response body.
type CredentialResponse struct {
	Credentials []IssuedCredential `json:"credentials,omitempty"`
	// NotificationID is §11's handle for the Notification Endpoint: "The Credential
	// Issuer needs to return one notification_id parameter per Credential Response ...
	// for the Wallet to be able to use this endpoint."
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
	// RequireKeyAttestation issues only on a proof whose key a trusted
	// attester vouches for, and is what the metadata's
	// key_attestations_required describes.
	RequireKeyAttestation bool
	// Deferred holds a request for somebody to decide on (§9).
	Deferred bool
	// WalletInitiated lets anybody signed in ask for this at the authorization
	// endpoint, with no offer naming them.
	WalletInitiated bool
	// Revocable gives each credential a place in a status list.
	Revocable bool
}

// ErrNoProof is a request whose proofs parameter is missing or empty, which
// §8.3.1.2 answers invalid_proof, "(1) if the field is missing"
// (specs/oid4vci.txt:1920), and not as a malformed request.
var ErrNoProof = errors.New("proofs is required: a credential is bound to a " +
	"key, and without a proof there is no key to bind it to")

// ValidateRequest applies §8.2's parameter rules.
//
// Returns the proofs to validate. The caller validates them, because that needs
// the issuer identity and the nonce, which are not the request's business.
func (r CredentialRequest) Validate() ([]string, error) {
	// §8.2: `credential_identifier` is "REQUIRED when an Authorization Details
	// of type openid_credential was returned from the Token Response. It MUST
	// NOT be used otherwise", and when it is used "the credential_configuration_id
	// MUST NOT be present". Which of the two a request owes depends on its token,
	// so that half is the endpoint's. That it sends one is here.
	identifier := strings.TrimSpace(r.CredentialIdentifier) != ""
	configuration := strings.TrimSpace(r.ConfigurationID) != ""
	if identifier && configuration {
		return nil, fmt.Errorf("credential_identifier and credential_configuration_id " +
			"may not be sent together")
	}
	if !identifier && !configuration {
		return nil, fmt.Errorf("credential_configuration_id or credential_identifier is required")
	}

	// §8.2: "The proofs parameter contains exactly one parameter named as the
	// proof type". More than one would leave which proof type was actually
	// honoured up to map iteration order.
	if len(r.Proofs) == 0 {
		return nil, ErrNoProof
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
		return nil, fmt.Errorf("%w: the jwt proofs array is empty", ErrNoProof)
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
	// Status is the credential's place in a status list, for a configuration that can
	// be revoked.
	Status *StatusPlace
}

// Issue returns the credential in the configuration's format: the combined SD-JWT VC
// serialisation, or a JWT.
func (i Issuer) Issue(cfg Configuration, subject map[string]any,
	holderKey *jose.JSONWebKey, now time.Time) (string, error) {

	if cfg.Format != FormatSDJWTVC && cfg.Format != FormatJWTVC {
		return "", fmt.Errorf("credential format %q is not implemented", cfg.Format)
	}
	if holderKey == nil {
		return "", fmt.Errorf("no holder key: an unbound credential is a bearer " +
			"token, which is what binding exists to prevent")
	}
	if cfg.Format == FormatJWTVC {
		return i.issueJWTVC(cfg, subject, holderKey, now)
	}

	// RFC 9901 §10.1: the time claims in a batch MUST be rounded or randomized,
	// or every credential in it carries the same second-precision fingerprint and
	// the fresh salts and holder keys above buy the holder nothing. The caller
	// passes one instant for the whole batch; rounding makes the credentials
	// agree even when a batch straddles a period boundary.
	now = sdjwt.RoundForUnlinkability(now, cfg.Lifetime)

	// draft-ietf-oauth-sd-jwt-vc-18 §2.2.2.3: iss, nbf, exp, cnf and vct "MUST
	// NOT be included in the Disclosures, i.e., cannot be selectively disclosed".
	// They are the credential's own frame -- hiding the issuer or the expiry
	// would leave a verifier unable to decide anything at all.
	always := map[string]any{
		"iss": i.CredentialIssuer,
		"vct": cfg.VCT,
		"iat": now.Unix(),
		// §2.2.2.3: cnf is "REQUIRED" when key binding is supported. It is what
		// makes the credential presentable only by whoever holds the private key.
		"cnf": map[string]any{"jwk": holderKey},
	}
	if cfg.Lifetime > 0 {
		always["exp"] = now.Add(cfg.Lifetime).Unix()
	}
	if i.Status != nil {
		always["status"] = i.Status.claim()
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
