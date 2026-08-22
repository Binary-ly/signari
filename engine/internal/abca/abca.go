// Package abca implements OAuth 2.0 Attestation-Based Client Authentication,
// draft-ietf-oauth-attestation-based-client-auth-10 (6 July 2026).
//
// # The problem it solves
//
// A public client has no secret. Anything that knows the `client_id` -- a
// repackaged app, a script, a modified build -- is indistinguishable from the
// real one, because there is nothing to prove otherwise. PKCE binds the code to
// a one-time secret and DPoP binds the token to a key, but neither says anything
// about WHAT is holding that key.
//
// ABCA adds a third party: a Client Attester, which vouches that a particular
// key belongs to a genuine instance of a known application. The client then
// proves possession of that key. So the token endpoint learns two things it
// could not learn before: this is the app we think it is, and this is the
// instance the attester saw.
//
// # Two artefacts
//
//	OAuth-Client-Attestation:     signed by the ATTESTER, carries cnf.jwk
//	OAuth-Client-Attestation-PoP: signed by the INSTANCE key named in that cnf
//
// The first is long-lived and reusable; the second is per-request. Splitting
// them is what lets an attester issue an attestation once, offline, while the
// instance proves liveness on every call.
package abca

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Header field names, §4 and §5.1. Case-insensitive per RFC 9110, which is what
// http.Header.Get already does.
const (
	HeaderAttestation = "OAuth-Client-Attestation"
	HeaderPoP         = "OAuth-Client-Attestation-PoP"
	// HeaderChallenge carries a fresh challenge back to the client, §6.2.
	HeaderChallenge = "OAuth-Client-Attestation-Challenge"
)

// JWT types, §4 and §5.1. Both are REQUIRED and exact.
const (
	TypAttestation = "oauth-client-attestation+jwt"
	TypPoP         = "oauth-client-attestation-pop+jwt"
)

// Client authentication method names, §8.
const (
	MethodPoP  = "attest_jwt_client_auth"
	MethodDPoP = "attest_jwt_client_auth_dpop"
)

// Error codes, §7.4.
const (
	// ErrUseChallenge MUST be accompanied by the OAuth-Client-Attestation-Challenge
	// header, per §7.4 -- the error is an instruction to retry with the enclosed
	// value, and without it the client has been told to do something it cannot do.
	ErrUseChallenge  = "use_attestation_challenge"
	ErrUseFresh      = "use_fresh_attestation"
	ErrInvalidClient = "invalid_client_attestation"
)

// MaxPoPAge bounds §7.2 rule 6, "within an acceptable window per local policy".
//
// The specification sets no number, so this is ours. Sixty seconds is the same
// bound internal/dpop uses for its proofs, and for the same reason: the window
// is how long a captured proof stays useful to whoever captured it. Replay
// detection on `jti` covers reuse within the window; this covers the case where
// the replay store is unavailable or the capture is older than its retention.
const MaxPoPAge = 60 * time.Second

// MaxSkew tolerates disagreeing clocks in both directions.
const MaxSkew = 30 * time.Second

// allowedAlgs is §7.1 rule 3 and §7.2 rule 3: "contains a registered algorithm,
// is not none, is supported by the application".
//
// Asymmetric only, and for the PoP that is the specification's own rule (§5.1:
// "MUST be digitally signed using an asymmetric cryptographic algorithm").
//
// For the ATTESTATION §4 additionally permits a MAC, and we decline it
// deliberately. A symmetric attester key is a key this server holds, so this
// server could mint attestations indistinguishable from the attester's own. The
// whole value of ABCA is that a third party vouched for the client; an
// attestation we could have forged ourselves vouches for nothing, and would be
// worth exactly as much as trusting the client_id we already had. Passing
// go-jose an explicit list also forecloses `none` at the parser rather than
// after it.
var allowedAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Attestation is a verified Client Attestation JWT.
type Attestation struct {
	// ClientID is the `sub` claim, which §4 defines as the client_id.
	ClientID string
	Expiry   time.Time
	IssuedAt time.Time
	// Key is cnf.jwk: the instance key that must sign the PoP.
	Key *jose.JSONWebKey
}

type attestationClaims struct {
	Subject  string `json:"sub"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	Cnf      struct {
		JWK json.RawMessage `json:"jwk"`
	} `json:"cnf"`
}

// VerifyAttestation applies §7.1's seven rules.
//
// `trusted` is the key set of the Client Attesters this deployment accepts.
// Rule 4 is "verifies with the public key of a known and trusted Client
// Attester", so an attestation signed by a perfectly valid key nobody registered
// is refused -- that check is the entire trust model, and without it any party
// able to sign a JWT could vouch for any client.
func VerifyAttestation(raw string, trusted *jose.JSONWebKeySet, now time.Time) (*Attestation, error) {
	if trusted == nil || len(trusted.Keys) == 0 {
		return nil, fmt.Errorf("no client attesters are trusted by this deployment, " +
			"so no attestation can be verified; register an attester's key first")
	}

	tok, err := jose.ParseSigned(raw, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("the client attestation is not a JWS signed with a "+
			"supported asymmetric algorithm: %w", err)
	}

	// §7.1 rule 2, the `typ` half. Checked before the signature so a token meant
	// for another purpose is rejected as the wrong KIND of thing rather than as a
	// bad signature -- and so an attestation can never be confused with a PoP,
	// which is the cross-protocol substitution `typ` exists to prevent.
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("the client attestation carries %d signatures; exactly "+
			"one is expected", len(tok.Signatures))
	}
	if typ, _ := tok.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string); typ != TypAttestation {
		return nil, fmt.Errorf("the client attestation has typ %q; §4 requires %q",
			typ, TypAttestation)
	}

	var payload []byte
	var verifyErr error
	for _, k := range trusted.Keys {
		if p, e := tok.Verify(k); e == nil {
			payload = p
			verifyErr = nil
			break
		} else {
			verifyErr = e
		}
	}
	if payload == nil {
		return nil, fmt.Errorf("the client attestation is not signed by any trusted "+
			"client attester: %w", verifyErr)
	}

	var c attestationClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("the client attestation payload is not JSON: %w", err)
	}

	// §4: sub, exp and cnf are REQUIRED. Absence is not "unset", it is a document
	// that does not meet the definition.
	if strings.TrimSpace(c.Subject) == "" {
		return nil, fmt.Errorf("the client attestation has no sub claim; §4 requires " +
			"it and defines it as the client_id being attested")
	}
	if c.Expiry == 0 {
		return nil, fmt.Errorf("the client attestation has no exp claim; §4 makes it " +
			"REQUIRED, and an attestation that never expires is a permanent licence " +
			"to impersonate the client instance it names")
	}
	if len(c.Cnf.JWK) == 0 {
		return nil, fmt.Errorf("the client attestation has no cnf.jwk; §4 requires the " +
			"key \"expressed using the jwk representation\", and without it there is " +
			"nothing for the proof of possession to be checked against")
	}

	// §7.1 rule 6, via exp. Expiry is checked here rather than left to a caller,
	// because §4 states the rejection as a MUST on the receiving server.
	exp := time.Unix(c.Expiry, 0)
	if now.Add(-MaxSkew).After(exp) {
		return nil, fmt.Errorf("the client attestation expired at %s", exp.UTC().Format(time.RFC3339))
	}
	var iat time.Time
	if c.IssuedAt != 0 {
		iat = time.Unix(c.IssuedAt, 0)
		if iat.After(now.Add(MaxSkew)) {
			return nil, fmt.Errorf("the client attestation is issued in the future")
		}
	}

	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(c.Cnf.JWK); err != nil {
		return nil, fmt.Errorf("cnf.jwk is not a JWK: %w", err)
	}
	// §7.1 rule 5: "The key contained in the cnf claim ... is not a private key."
	//
	// An attestation carrying a private key would hand this server -- and every
	// log and proxy the header passed through -- the very key the PoP is supposed
	// to prove exclusive possession of.
	if !key.IsPublic() {
		return nil, fmt.Errorf("cnf.jwk contains a PRIVATE key; §7.1 rule 5 refuses " +
			"this, and an attestation that leaks the instance key proves nothing " +
			"about who holds it")
	}
	if !key.Valid() {
		return nil, fmt.Errorf("cnf.jwk is not a usable key")
	}

	return &Attestation{
		ClientID: c.Subject,
		Expiry:   exp,
		IssuedAt: iat,
		Key:      &key,
	}, nil
}

// PoP is a verified Client Attestation PoP JWT.
type PoP struct {
	Audience  string
	JTI       string
	IssuedAt  time.Time
	Challenge string
}

type popClaims struct {
	Audience  string `json:"aud"`
	JTI       string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	Challenge string `json:"challenge"`
}

// VerifyPoP applies §7.2's rules 1-8. Rule 9, replay detection, needs storage
// and is the caller's -- it is stated as conditional on "the security
// requirements of the deployment", and ours does apply it.
//
// `expectedChallenge` implements rules 5 and 8 together: when this server issued
// a challenge, the PoP MUST carry it and it MUST match. Empty means no challenge
// was issued for this exchange, and the claim is then not required -- §5.1 makes
// `challenge` OPTIONAL precisely because a deployment may not offer one.
func VerifyPoP(raw string, key *jose.JSONWebKey, audience, expectedChallenge string,
	now time.Time) (*PoP, error) {

	tok, err := jose.ParseSigned(raw, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("the client attestation PoP is not a JWS signed with a "+
			"supported asymmetric algorithm: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("the client attestation PoP carries %d signatures; "+
			"exactly one is expected", len(tok.Signatures))
	}
	if typ, _ := tok.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string); typ != TypPoP {
		return nil, fmt.Errorf("the client attestation PoP has typ %q; §5.1 requires %q",
			typ, TypPoP)
	}

	// §7.2 rule 4: verified with the cnf key from the ATTESTATION, and with
	// nothing else. This is the join between the two artefacts -- the attester
	// says which key, and this proves the sender holds it.
	payload, err := tok.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("the client attestation PoP is not signed by the key "+
			"the attestation names in cnf: %w", err)
	}

	var c popClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("the client attestation PoP payload is not JSON: %w", err)
	}

	// §5.1: aud, jti and iat are all REQUIRED.
	if c.Audience == "" {
		return nil, fmt.Errorf("the client attestation PoP has no aud claim")
	}
	if c.JTI == "" {
		return nil, fmt.Errorf("the client attestation PoP has no jti claim; §5.1 " +
			"requires it and replay detection has nothing to key on without it")
	}
	if c.IssuedAt == 0 {
		return nil, fmt.Errorf("the client attestation PoP has no iat claim")
	}

	// §7.2 rule 7: for an authorization server the audience MUST be the RFC 8414
	// issuer identifier. Constant time because a mismatch is an authentication
	// failure and the comparison is against a fixed, known value.
	if subtle.ConstantTimeCompare([]byte(c.Audience), []byte(audience)) != 1 {
		return nil, fmt.Errorf("the client attestation PoP is addressed to %q, not to "+
			"this authorization server (%q); §7.2 rule 7 requires the issuer "+
			"identifier, so a proof captured at one deployment cannot be replayed at "+
			"another", c.Audience, audience)
	}

	// §7.2 rule 6.
	iat := time.Unix(c.IssuedAt, 0)
	if iat.After(now.Add(MaxSkew)) {
		return nil, fmt.Errorf("the client attestation PoP is issued in the future")
	}
	if now.Sub(iat) > MaxPoPAge+MaxSkew {
		return nil, fmt.Errorf("the client attestation PoP was issued %s ago, beyond "+
			"the %s this server accepts", now.Sub(iat).Truncate(time.Second), MaxPoPAge)
	}

	// §7.2 rules 5 and 8.
	if expectedChallenge != "" {
		if c.Challenge == "" {
			return nil, &ChallengeError{Reason: "this server issued a challenge and the " +
				"client attestation PoP carries none"}
		}
		if subtle.ConstantTimeCompare([]byte(c.Challenge), []byte(expectedChallenge)) != 1 {
			return nil, &ChallengeError{Reason: "the challenge in the client attestation " +
				"PoP is not the one this server issued"}
		}
	}

	return &PoP{
		Audience:  c.Audience,
		JTI:       c.JTI,
		IssuedAt:  iat,
		Challenge: c.Challenge,
	}, nil
}

// ChallengeError marks the one failure §7.4 gives its own error code AND an
// instruction: `use_attestation_challenge` MUST be accompanied by a fresh
// challenge in the OAuth-Client-Attestation-Challenge header. Distinguished from
// an ordinary error so the caller knows to attach one -- telling a client to
// retry with a challenge, without giving it a challenge, is a loop.
type ChallengeError struct{ Reason string }

func (e *ChallengeError) Error() string { return e.Reason }

// SigningAlgs names the algorithms §8 requires this server to publish in
// `client_attestation_signing_alg_values_supported` and
// `client_attestation_pop_signing_alg_values_supported`.
//
// Derived from the same list the verifier enforces, rather than written out
// again beside it. Two copies of an algorithm list drift, and the direction they
// drift is always the same: metadata claims an algorithm the verifier refuses,
// so a client builds something correct by the published rules and is rejected.
func SigningAlgs() []string {
	out := make([]string, 0, len(allowedAlgs))
	for _, a := range allowedAlgs {
		out = append(out, string(a))
	}
	return out
}

// Proof-of-Possession method identifiers from the "OAuth Client Attestation
// Proof-of-Possession Methods" registry created by draft -10 §7.6.
//
// Only the first is implemented here. `PoPMethodDPoPCombined` is named so the
// gap has a name rather than being an absence -- and so that anything advertising
// it has to reference a constant that does not appear in the accepted list.
const (
	// PoPMethodAttestationJWT is the dedicated Client Attestation PoP JWT.
	PoPMethodAttestationJWT = "attestation_pop_jwt"
	// PoPMethodDPoPCombined uses one DPoP proof as both the sender-constraint and
	// the Client Attestation PoP (§5.2, §7.3).
	//
	// §5.2 also notes that when authorization code binding is used, "this mode
	// only works with the DPoP Proof header containing a proof of possession and
	// not `dpop_jkt`". That holds structurally here rather than by a check:
	// combined mode is selected by the presence of a DPoP proof header at the
	// token endpoint, and `dpop_jkt` is an authorization-request parameter that
	// is not a proof and cannot be presented as one.
	PoPMethodDPoPCombined = "dpop_combined"
	// PoPMethodNone means no Client Attestation is required.
	PoPMethodNone = "none"
)

// SameKey reports whether two JWKs are the same public key.
//
// # Why thumbprints rather than field comparison
//
// §7.3 rule 4 of the combined mode requires that "the public key in the `jwk`
// header parameter of the DPoP proof MUST be identical to the public key in the
// `cnf` claim of the Client Attestation JWT". The two arrive from different
// places, serialised by different parties, so "identical" cannot mean byte
// equality of the JSON: member order, whitespace, an omitted `alg`, an added
// `kid` or a `use` on one and not the other are all the same key written
// differently, and every one of them would make a conformant client fail.
//
// RFC 7638 exists for exactly this. The thumbprint is computed over a canonical
// subset — the required members only, lexicographically ordered — so two
// spellings of one key produce one digest, and two different keys cannot.
//
// Constant time is not required and is not used: both values are public keys, and
// which one differs is not a secret.
func SameKey(a, b *jose.JSONWebKey) (bool, error) {
	if a == nil || b == nil {
		return false, fmt.Errorf("a key is missing")
	}
	ta, err := a.Thumbprint(crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("thumbprinting the attested key: %w", err)
	}
	tb, err := b.Thumbprint(crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("thumbprinting the presented key: %w", err)
	}
	return bytes.Equal(ta, tb), nil
}
