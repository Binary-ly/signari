package oid4vci

import (
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Key attestation, OID4VCI 1.0 Appendix D.
//
// A key proof says "I hold this key". A key attestation says "and a party you
// trust vouches that this key lives in hardware, behind a user gesture". They
// answer different questions, and only the second is worth anything against a
// wallet that has been rooted -- a software key can sign a perfectly valid
// proof.
//
// # The attester's signature is the whole point, so it is required
//
// An attestation is a JWT issued by a device manufacturer or wallet provider.
// Accepting one without checking who signed it would be accepting the wallet's
// own word about its own security, which is what the mechanism exists to stop.
//
// So TrustedAttesters must be configured for `key_attestation` to be accepted at
// all. With none configured the header is REFUSED rather than ignored: a wallet
// that sends an attestation and receives a credential concludes the attestation
// was weighed, and silently dropping it would leave the issuer believing it has
// hardware-backed keys when it has whatever the wallet chose to claim.
//
// This is the same rule this package already applies to `kid` and `x5c`: a key
// source we cannot verify is refused, not honoured.

const (
	TypKeyAttestation       = "key-attestation+jwt"
	TypKeyAttestationLegacy = "keyattestation+jwt"
)

// HeaderKeyAttestation is the JOSE header parameter carrying the attestation.
const HeaderKeyAttestation = "key_attestation"

// KeyAttestation is Appendix D's payload.
type KeyAttestation struct {
	AttestedKeys []json.RawMessage `json:"attested_keys"`
	IssuedAt     int64             `json:"iat"`
	Expiry       int64             `json:"exp"`
	Nonce        string            `json:"nonce,omitempty"`
	KeyStorage   []string          `json:"key_storage,omitempty"`
	UserAuth     []string          `json:"user_authentication,omitempty"`
}

// AttestedKeySet is the verified result.
type AttestedKeySet struct {
	Keys       []*jose.JSONWebKey
	KeyStorage []string
	UserAuth   []string
}

// Contains reports whether a key is among the attested ones, compared by
// thumbprint rather than by object identity.
//
// By thumbprint because the wallet's inline `jwk` and the attester's copy of the
// same key are separately encoded documents: same key, different bytes, and
// different `kid` values are permitted. Comparing the marshalled JSON would
// refuse a conformant wallet for whitespace.
func (s *AttestedKeySet) Contains(k *jose.JSONWebKey) bool {
	if k == nil {
		return false
	}
	want, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return false
	}
	for _, a := range s.Keys {
		got, err := a.Thumbprint(crypto.SHA256)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(got, want) == 1 {
			return true
		}
	}
	return false
}

// ByKeyID returns the attested key with this `kid`.
//
// Appendix D lets a proof name one of the attested keys by reference instead of
// inlining it. The lookup is over the ATTESTED set only -- never over anything
// the wallet supplied separately -- so the key that gets verified is by
// construction a key the attester vouched for.
func (s *AttestedKeySet) ByKeyID(kid string) *jose.JSONWebKey {
	if kid == "" {
		return nil
	}
	for _, a := range s.Keys {
		if a.KeyID == kid {
			return a
		}
	}
	return nil
}

// VerifyKeyAttestation checks an Appendix D attestation and returns its keys.
//
// requireExpiry is D.1: "exp MUST be present when the attestation is used with
// the jwt proof type". It is a parameter rather than a constant because the
// attestation proof type has a different rule, and hard-coding the stricter one
// here would refuse a conformant attestation in the other position.
func VerifyKeyAttestation(raw string, attesters []*jose.JSONWebKey, algs []jose.SignatureAlgorithm,
	requireExpiry bool, expectedNonce string, now time.Time) (*AttestedKeySet, error) {

	if len(attesters) == 0 {
		return nil, fmt.Errorf("this issuer has no trusted key attesters configured, so a " +
			"key_attestation cannot be verified; it is refused rather than ignored, because " +
			"a wallet that sends one and receives a credential concludes it was checked")
	}
	if len(algs) == 0 {
		algs = DefaultProofAlgs()
	}

	tok, err := jose.ParseSigned(raw, algs)
	if err != nil {
		return nil, fmt.Errorf("the key attestation did not parse: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("a key attestation must carry exactly one signature")
	}
	h := tok.Signatures[0].Header

	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, TypKeyAttestation) && !strings.EqualFold(typ, TypKeyAttestationLegacy) {
		return nil, fmt.Errorf("the key attestation has typ %q, want %q; without explicit "+
			"typing another JWT this attester signed could be replayed here",
			typ, TypKeyAttestation)
	}

	// Verified against the CONFIGURED attesters, one at a time. Nothing in the
	// attestation itself selects the key: an attestation that named its own
	// verification key would be vouching for itself.
	var payload []byte
	var verr error
	for _, a := range attesters {
		if payload, verr = tok.Verify(a); verr == nil {
			break
		}
	}
	if verr != nil || payload == nil {
		return nil, fmt.Errorf("the key attestation does not verify against any trusted attester")
	}

	var c KeyAttestation
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("the key attestation's payload is not JSON: %w", err)
	}
	if len(c.AttestedKeys) == 0 {
		return nil, fmt.Errorf("the key attestation carries no attested_keys, so it vouches for nothing")
	}
	if c.IssuedAt == 0 {
		return nil, fmt.Errorf("the key attestation has no iat")
	}
	// The same one-minute future tolerance the key proof beside it uses; a
	// second, different allowance for the same kind of clock would be a second
	// number to keep in step.
	if time.Unix(c.IssuedAt, 0).After(now.Add(time.Minute)) {
		return nil, fmt.Errorf("the key attestation is issued in the future")
	}
	if requireExpiry && c.Expiry == 0 {
		return nil, fmt.Errorf("the key attestation has no exp; Appendix D.1 requires one " +
			"when the attestation is carried in a jwt proof")
	}
	if c.Expiry != 0 && !now.Before(time.Unix(c.Expiry, 0)) {
		return nil, fmt.Errorf("the key attestation expired at %s",
			time.Unix(c.Expiry, 0).UTC().Format(time.RFC3339))
	}
	if expectedNonce != "" && c.Nonce != expectedNonce {
		return nil, fmt.Errorf("the key attestation does not echo the expected nonce, so it " +
			"could be one issued earlier for a different request")
	}

	out := &AttestedKeySet{KeyStorage: c.KeyStorage, UserAuth: c.UserAuth}
	for i, rawKey := range c.AttestedKeys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(rawKey); err != nil {
			return nil, fmt.Errorf("attested_keys[%d] is not a JWK: %w", i, err)
		}
		if !k.IsPublic() {
			return nil, fmt.Errorf("attested_keys[%d] contains private key material", i)
		}
		out.Keys = append(out.Keys, &k)
	}
	return out, nil
}
