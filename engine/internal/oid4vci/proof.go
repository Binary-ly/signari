package oid4vci

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Key proof of possession, OID4VCI §8.2 and Appendix F.1.
//
// # What the proof is for
//
// A credential is bound to a key the holder controls, so that presenting it
// later means proving possession of that key rather than merely holding a
// bearer string. The proof is how the wallet tells the issuer WHICH key, and
// demonstrates it has the private half.
//
// Without it, a credential issued to whoever redeemed the access token is a
// bearer token with extra steps: anybody who copied it could present it.

// TypProof is the explicit type an issuance proof carries (§F.1).
//
// RFC 8725 §3.11 is the reason: without explicit typing, a JWT minted for one
// purpose can be replayed into a verifier expecting another. A proof and an ID
// token are both signed JSON with `aud` and `iat`.
const TypProof = "openid4vci-proof+jwt"

// ProofTypeJWT is the member name inside the `proofs` object.
const ProofTypeJWT = "jwt"

// MaxProofAge bounds how old a key proof may be.
//
// The specification sets no limit and relies on `nonce` for freshness. A limit
// is kept anyway for the case the nonce cannot carry the weight — an issuer with
// no Nonce Endpoint, where §F.1 makes the claim optional — because an unbounded
// proof is a credential-issuance capability with no expiry.
const MaxProofAge = 5 * time.Minute

// ProofKey is the key a validated proof binds the credential to.
type ProofKey struct {
	// JWK is the public key, when the proof carried one inline.
	JWK *jose.JSONWebKey
	// KeyID is the `kid`, when the proof identified the key by reference.
	KeyID string
	// Nonce is the c_nonce the proof echoed, empty when none was sent.
	Nonce string
}

// proofClaims is the JWT body of a key proof (§F.1).
type proofClaims struct {
	Issuer   string `json:"iss,omitempty"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Nonce    string `json:"nonce,omitempty"`
}

// ProofContext is what the issuer knows and the proof must agree with.
type ProofContext struct {
	// CredentialIssuer is the identifier the proof's `aud` must equal.
	CredentialIssuer string
	// ClientID is the client the access token was issued to, empty when the
	// token came from an anonymous pre-authorized code redemption.
	ClientID string
	// Anonymous records that the access token was obtained without a client_id.
	// See ValidateJWTProof for why this is not simply ClientID == "".
	Anonymous bool
	// ExpectedNonce is the c_nonce this issuer handed out. When set, the proof
	// MUST echo it.
	ExpectedNonce string
	// AllowedAlgs are the signing algorithms the issuer advertises.
	AllowedAlgs []jose.SignatureAlgorithm
}

// ValidateJWTProof checks a `jwt` key proof and returns the key it binds to.
func ValidateJWTProof(raw string, ctx ProofContext, now time.Time) (*ProofKey, error) {
	algs := ctx.AllowedAlgs
	if len(algs) == 0 {
		algs = DefaultProofAlgs()
	}
	// §F.1: alg "MUST NOT be none or an identifier for a symmetric algorithm
	// (MAC)". Enforced by the allow-list rather than by inspecting the header:
	// a symmetric algorithm would let anybody who knows the public key forge a
	// proof, since the "public" key would also be the verification secret.
	tok, err := jose.ParseSigned(raw, algs)
	if err != nil {
		return nil, fmt.Errorf("the key proof did not parse: %w", err)
	}
	// go-jose's Verify also refuses a multi-signature object, so this check is
	// not the only thing standing -- but without it the refusal reads "the
	// signature does not verify", which is false and sends an integrator looking
	// at their key. The check is here to make the error tell the truth, and the
	// test asserts the reason rather than merely the refusal.
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("a key proof must carry exactly one signature")
	}
	h := tok.Signatures[0].Header

	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !strings.EqualFold(typ, TypProof) {
		return nil, fmt.Errorf("the key proof has typ %q, want %q; without explicit "+
			"typing an ID token could be replayed here", typ, TypProof)
	}

	// §F.1: kid, jwk and x5c are mutually exclusive -- "It MUST NOT be present
	// if jwk or x5c is present", stated for each. Two key sources in one proof
	// means the key that was VERIFIED and the key the credential is BOUND to can
	// differ, which is the whole attack.
	hasJWK := h.JSONWebKey != nil
	hasKID := h.KeyID != ""
	// x5c is read from the raw header: go-jose exposes Certificates as a
	// verification helper rather than as the header value.
	_, hasX5C := h.ExtraHeaders[jose.HeaderKey("x5c")]
	switch {
	case hasJWK && hasKID, hasJWK && hasX5C, hasKID && hasX5C:
		return nil, fmt.Errorf("the key proof carries more than one of kid, jwk " +
			"and x5c; they are mutually exclusive, and two key sources mean the " +
			"key verified and the key bound could differ")
	case !hasJWK && !hasKID && !hasX5C:
		return nil, fmt.Errorf("the key proof identifies no key: one of kid, jwk " +
			"or x5c is required")
	}

	// §F.1: "The Credential Issuer MUST validate that the JWT used as a proof is
	// actually signed by a key identified in the JOSE Header."
	//
	// Only the inline `jwk` form is supported here, and that is a deliberate
	// limit rather than an oversight: `kid` refers to a key the issuer is
	// expected to already know (typically a DID URL), and `x5c` requires a trust
	// decision about a certificate chain. Accepting either without performing
	// that resolution would be accepting a proof we did not verify.
	if !hasJWK {
		which := "kid"
		if hasX5C {
			which = "x5c"
		}
		return nil, fmt.Errorf("this issuer accepts key proofs that carry the key "+
			"inline as `jwk`; %s identifies a key it would have to resolve and "+
			"trust separately, which it does not do", which)
	}
	// Defence in depth, and honestly labelled: go-jose refuses an embedded
	// private JWK inside ParseSigned ("invalid embedded jwk, must be public
	// key"), so this line does not fire today and removing it fails no test.
	//
	// It is kept because the property matters more than which layer enforces it
	// — a wallet that sent its private key would have handed the issuer a secret
	// it must never hold — and because a JOSE library change would otherwise make
	// this the only thing standing, with nothing to say it had stopped working.
	if !h.JSONWebKey.IsPublic() {
		return nil, fmt.Errorf("the key proof's jwk contains private key material")
	}

	payload, err := tok.Verify(h.JSONWebKey)
	if err != nil {
		return nil, fmt.Errorf("the key proof's signature does not verify against " +
			"the key it carries")
	}

	var c proofClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("the key proof's claims did not parse: %w", err)
	}

	// §F.1: aud REQUIRED, "MUST be the Credential Issuer Identifier".
	if c.Audience != ctx.CredentialIssuer {
		return nil, fmt.Errorf("the key proof's aud is %q, want the credential "+
			"issuer %q", c.Audience, ctx.CredentialIssuer)
	}
	if c.IssuedAt == 0 {
		return nil, fmt.Errorf("the key proof has no iat")
	}
	issued := time.Unix(c.IssuedAt, 0)
	if issued.After(now.Add(time.Minute)) {
		return nil, fmt.Errorf("the key proof is dated in the future")
	}
	if now.Sub(issued) > MaxProofAge {
		return nil, fmt.Errorf("the key proof is older than %s", MaxProofAge)
	}

	// §F.1 on `iss`: "The value of this claim MUST be the client_id of the Client
	// making the Credential request. This claim MUST be omitted if the access
	// token authorizing the issuance call was obtained from a Pre-Authorized Code
	// Flow through anonymous access to the token endpoint."
	//
	// Both halves are enforced, and the second is why ProofContext carries
	// Anonymous separately from an empty ClientID: "we do not know the client"
	// and "there was deliberately no client" are different states, and only the
	// second forbids the claim.
	switch {
	case ctx.Anonymous && c.Issuer != "":
		return nil, fmt.Errorf("the key proof carries iss=%q, but the access token "+
			"was obtained anonymously through the pre-authorized code flow, where "+
			"section F.1 requires the claim to be omitted", c.Issuer)
	case !ctx.Anonymous && ctx.ClientID != "" && c.Issuer != "" && c.Issuer != ctx.ClientID:
		return nil, fmt.Errorf("the key proof's iss is %q, but the access token was "+
			"issued to %q", c.Issuer, ctx.ClientID)
	}

	// §8.2: the proof MUST incorporate a c_nonce when the issuer has a Nonce
	// Endpoint. We have one, so a proof without the nonce we issued is refused --
	// otherwise a proof captured once could be replayed indefinitely.
	if ctx.ExpectedNonce != "" && c.Nonce != ctx.ExpectedNonce {
		return nil, fmt.Errorf("the key proof does not carry the c_nonce this " +
			"issuer provided, so its freshness cannot be established")
	}

	return &ProofKey{JWK: h.JSONWebKey, Nonce: c.Nonce}, nil
}

// DefaultProofAlgs are the signing algorithms accepted for key proofs.
//
// Asymmetric only. §F.1 forbids `none` and any MAC, and the list is the defence:
// a symmetric algorithm here would make the verification key and the forgery key
// the same value.
func DefaultProofAlgs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	}
}

// ProofAlgNames renders the accepted algorithms for issuer metadata.
func ProofAlgNames() []string {
	algs := DefaultProofAlgs()
	out := make([]string, 0, len(algs))
	for _, a := range algs {
		out = append(out, string(a))
	}
	return out
}

// NonceFromProof reads the `nonce` claim WITHOUT verifying the proof.
//
// Used only to look up which c_nonce the wallet is claiming, so the expected
// value can be supplied to ValidateJWTProof — which then compares it against the
// verified payload. Nothing is trusted on the strength of this read: the nonce
// is spent by a database statement that only succeeds for a nonce this issuer
// actually minted, and the proof's signature is checked separately.
//
// Returns "" for anything unparseable, so a malformed proof fails the nonce
// lookup rather than reaching the verifier with a half-read value.
func NonceFromProof(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return ""
	}
	return c.Nonce
}
