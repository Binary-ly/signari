// Package sdjwt implements Selective Disclosure for JWTs
// (draft-ietf-oauth-selective-disclosure-jwt) and the SD-JWT VC credential
// format (draft-ietf-oauth-sd-jwt-vc-18, 10 August 2026).
//
// # What selective disclosure buys
//
// An ordinary credential is all-or-nothing: to prove you are over 18 to a bar,
// you hand over a document carrying your name, address and exact date of birth.
// The bar learns everything because the signature covers everything, and
// removing a field breaks it.
//
// SD-JWT signs DIGESTS of individual claims instead of the claims themselves.
// The holder receives the signed JWT plus one "disclosure" per claim, and
// presents only the disclosures they choose. The signature still verifies,
// because it was never over the values.
//
// # The detail implementations get wrong
//
// §4.2.3, emphatically:
//
//	"The digest MUST be taken over the US-ASCII bytes of the base64url-encoded
//	value that is the Disclosure... The input to the hash function MUST be the
//	base64url-encoded Disclosure, NOT the bytes encoded by the base64url string."
//
// Hashing the decoded JSON is the obvious reading and produces a credential that
// verifies against nothing. The specification publishes a test vector precisely
// because of this, and `TestTheSpecificationsOwnDigestVector` uses it.
package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
)

// Separator joins the issuer-signed JWT and its disclosures.
//
// The combined serialisation ends with a trailing separator when there is no
// key binding JWT, which is what distinguishes "no key binding" from a truncated
// credential.
const Separator = "~"

// TypSDJWTVC is the `typ` header an SD-JWT VC carries.
//
// draft-18 §3.2.1: the value MUST be `dc+sd-jwt`. Earlier drafts used
// `vc+sd-jwt`, "changed to avoid conflict with the vc media type name", and a
// transitional period is permitted for accepting the old one. We ISSUE only the
// current value: emitting a deprecated type keeps it alive in verifiers.
const TypSDJWTVC = "dc+sd-jwt"

// AlgSHA256 is the only `_sd_alg` this implementation produces.
//
// §4.1.1 makes sha-256 the default when the claim is absent and requires every
// implementation to support it. It is written explicitly rather than omitted,
// because a verifier that defaults correctly and a verifier that assumes are
// indistinguishable until somebody changes the algorithm.
const AlgSHA256 = "sha-256"

var RedList = map[string]bool{
	"iss": true, "iat": true, "nbf": true, "exp": true,
	"cnf": true, "vct": true, "status": true,
}

// Disclosure is one selectively disclosable claim.
type Disclosure struct {
	// Salt is base64url of 128 bits of random data, unique per claim (§4.2.1).
	Salt string
	Name string
	// Value is the claim value as it would have appeared in the payload.
	Value any
	// Encoded is the base64url serialisation the digest is taken over.
	Encoded string
}

// Digest returns the base64url SHA-256 of the ENCODED disclosure string.
//
// Delegates to DigestOf rather than repeating the two lines. They were separate
// implementations of one rule, and a mutation proved the cost: changing this one
// to hash the decoded bytes — the exact mistake §4.2.3 warns about twice — broke
// nothing, because the specification's test vector exercises DigestOf and this
// is what issuance actually calls.
//
// One rule, one implementation, one test that reaches it.
func (d Disclosure) Digest() string { return DigestOf(d.Encoded) }

// NewDisclosure builds a disclosure for one object property.
func NewDisclosure(name string, value any) (Disclosure, error) {
	if RedList[name] {
		return Disclosure{}, fmt.Errorf("%q cannot be selectively disclosed: "+
			"section 3.2.2.2 requires it in the SD-JWT itself, because a verifier "+
			"that cannot see it cannot evaluate the credential at all", name)
	}
	if name == "_sd" || name == "..." {
		// §4.2.1: the claim name "MUST NOT be _sd, ..., or a claim name existing
		// in the object as a permanently disclosed claim". The first two are
		// structural: a disclosure named `_sd` would, once revealed, collide with
		// the digest array itself.
		return Disclosure{}, fmt.Errorf("%q cannot be a selectively disclosable "+
			"claim name: it is structural in an SD-JWT payload", name)
	}
	salt, err := newSalt()
	if err != nil {
		return Disclosure{}, err
	}
	return newDisclosureWithSalt(salt, name, value)
}

func newDisclosureWithSalt(salt, name string, value any) (Disclosure, error) {
	// A JSON array of exactly three elements, in order. Encoded WITHOUT HTML
	// escaping, because Go's default encoder rewrites <, > and & into < and
	// friends -- which changes the bytes, and the bytes are what is hashed.
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode([]any{salt, name, value}); err != nil {
		return Disclosure{}, err
	}
	// Encoder appends a newline; the disclosure is the JSON text alone.
	raw := strings.TrimRight(buf.String(), "\n")
	return Disclosure{
		Salt: salt, Name: name, Value: value,
		Encoded: base64.RawURLEncoding.EncodeToString([]byte(raw)),
	}, nil
}

// newSalt returns 128 bits of randomness, base64url encoded (§4.2.1).
func newSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating a disclosure salt: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Payload builds an SD-JWT payload from claims that are always visible and
// claims that are selectively disclosable.
//
// Returns the payload to sign and the disclosures to hand the holder.
func Payload(always map[string]any, selective map[string]any) (map[string]any, []Disclosure, error) {
	out := make(map[string]any, len(always)+2)
	for k, v := range always {
		// §4.1: "The payload MUST NOT contain the claims _sd or ... except for
		// the purpose of conveying digests." An always-visible claim by either
		// name would be silently overwritten by the digest array below, so the
		// credential would quietly not say what the configuration asked for.
		if k == "_sd" || k == "..." {
			return nil, nil, fmt.Errorf("%q cannot be an always-visible claim: the "+
				"name is reserved for conveying digests", k)
		}
		out[k] = v
	}

	// Sorted, so the disclosures are built in a deterministic order and a test
	// can predict them. The DIGEST array is sorted separately below, which is
	// what actually matters for privacy.
	names := make([]string, 0, len(selective))
	for k := range selective {
		names = append(names, k)
	}
	sort.Strings(names)

	var ds []Disclosure
	var digests []string
	for _, name := range names {
		if _, clash := always[name]; clash {
			// §4.2.1 again: a disclosure must not name a claim that is already
			// permanently present. Revealing it would put the name in the object
			// twice with two values.
			return nil, nil, fmt.Errorf("claim %q is both always-visible and "+
				"selectively disclosable; revealing it would put the name in the "+
				"payload twice", name)
		}
		d, err := NewDisclosure(name, selective[name])
		if err != nil {
			return nil, nil, err
		}
		ds = append(ds, d)
		digests = append(digests, d.Digest())
	}

	// §4.2.5: decoy digests, "to make it more difficult for an adversarial
	// Verifier to see the original number of claims". Without them, len(_sd) is
	// exactly how many claims the holder is withholding — so a verifier presented
	// with two disclosures out of five learns that three were held back, and can
	// press for them.
	//
	// "It is RECOMMENDED to create the decoy digests by hashing over a
	// cryptographically secure random number", which is what newDecoy does. No
	// disclosure is sent for them, so the holder simply sees digests they cannot
	// open — as the specification says they will.
	// §4.1: "The same digest value MUST NOT appear more than once in the SD-JWT."
	//
	// Real digests cannot collide in practice — the salts are unique and the
	// hash is SHA-256 — so this guards the decoys, which are random and checked
	// against nothing. The probability is negligible and the requirement is
	// unconditional; a set costs nothing and removes the question.
	seen := make(map[string]bool, len(digests))
	for _, d := range digests {
		seen[d] = true
	}
	for i := 0; i < decoyCount(len(digests)); i++ {
		d, err := decoySource()
		if err != nil {
			return nil, nil, err
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		digests = append(digests, d)
	}

	if len(digests) > 0 {
		// §4.2.4.1: "The Issuer MUST hide the original order of the claims in the
		// array." Sorting the DIGESTS does that -- they are hashes, so their order
		// carries no information about the claim names that produced them.
		sort.Strings(digests)
		out["_sd"] = digests
		out["_sd_alg"] = AlgSHA256
	}
	return out, ds, nil
}

// decoyCount decides how many decoys to add for a given number of real claims.
//
// A random count in a band that scales with the real one. A FIXED number would
// be worse than none: a verifier who knows the issuer always adds three simply
// subtracts three. The count varying per credential is what makes the total
// uninformative.
func decoyCount(real int) int {
	if real == 0 {
		return 0
	}
	max := real/2 + 2
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max+1)))
	if err != nil {
		// Falling back to a fixed count rather than failing issuance: a
		// credential with predictable padding is still better than no credential,
		// and this only happens if the system entropy source is broken.
		return 1
	}
	return int(n.Int64())
}

// decoySource produces decoy digests. A package variable so a test can force
// the collision §4.1 forbids — SHA-256 will not produce one by chance, so a
// guard against it is otherwise unprovable, and an unprovable guard is one
// nobody can tell has stopped working.
var decoySource = newDecoy

// newDecoy returns a digest that opens to nothing.
func newDecoy() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating a decoy digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Combine assembles the issuance serialisation: JWT ~ disclosure ~ ... ~
//
// The trailing separator is required. §4: the combined format ends with `~`
// when no key binding JWT follows, and a verifier splitting on `~` uses the
// empty final element to tell "no key binding" from a credential that was cut
// short in transit.
func Combine(jwt string, ds []Disclosure) string {
	var b strings.Builder
	b.WriteString(jwt)
	for _, d := range ds {
		b.WriteString(Separator)
		b.WriteString(d.Encoded)
	}
	b.WriteString(Separator)
	return b.String()
}

// Split parses an issuance or presentation serialisation.
//
// Returns the JWT, the disclosures present, and the key binding JWT if one was
// appended.
func Split(s string) (jwt string, disclosures []string, keyBinding string, err error) {
	if s == "" {
		return "", nil, "", fmt.Errorf("empty SD-JWT")
	}
	parts := strings.Split(s, Separator)
	if len(parts) < 2 {
		return "", nil, "", fmt.Errorf("an SD-JWT must contain at least one %q, "+
			"even with no disclosures", Separator)
	}
	jwt = parts[0]
	last := parts[len(parts)-1]
	middle := parts[1 : len(parts)-1]
	// A non-empty final element is a key binding JWT; an empty one means the
	// serialisation ended with the required trailing separator.
	if last != "" {
		keyBinding = last
	}
	for _, d := range middle {
		if d == "" {
			return "", nil, "", fmt.Errorf("an SD-JWT contains an empty disclosure, " +
				"which means two separators in a row")
		}
		disclosures = append(disclosures, d)
	}
	return jwt, disclosures, keyBinding, nil
}

// DigestOf returns the digest a verifier would compute for a disclosure string.
//
// Exported because verification is somebody else's job -- a wallet or a relying
// party -- and this is the one operation they cannot get wrong by guessing.
func DigestOf(encodedDisclosure string) string {
	sum := sha256.Sum256([]byte(encodedDisclosure))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Parse decodes an encoded disclosure back to its three elements.
func Parse(encoded string) (Disclosure, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Disclosure{}, fmt.Errorf("a disclosure is not base64url: %w", err)
	}
	var parts []any
	if err := json.Unmarshal(raw, &parts); err != nil {
		return Disclosure{}, fmt.Errorf("a disclosure is not a JSON array: %w", err)
	}
	if len(parts) != 3 {
		return Disclosure{}, fmt.Errorf("a disclosure for an object property has "+
			"three elements (salt, name, value), got %d", len(parts))
	}
	salt, ok := parts[0].(string)
	if !ok {
		return Disclosure{}, fmt.Errorf("a disclosure salt must be a string")
	}
	name, ok := parts[1].(string)
	if !ok {
		return Disclosure{}, fmt.Errorf("a disclosure claim name must be a string")
	}
	return Disclosure{Salt: salt, Name: name, Value: parts[2], Encoded: encoded}, nil
}
