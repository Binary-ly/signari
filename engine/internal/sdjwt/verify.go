package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Verification, RFC 9901 §7.1.
//
// # Why this is the mirror of issuance and not a second implementation of it
//
// Everything here reuses the primitives issuance uses: Split for the
// serialisation, DigestOf for the hash, Parse for an object disclosure. A
// verifier that computed digests its own way would be the one place a mistake
// could not be caught -- issuance would agree with itself and only a third party
// would ever notice.
//
// # The shape of the algorithm
//
// The issuer-signed payload contains digests, never values. `_sd` is an array of
// digests standing in for object properties; an array element of the form
// `{"...": "<digest>"}` stands in for one array item. Verification walks the
// payload, replaces every digest it holds a matching disclosure for, and removes
// the machinery. Disclosed values can themselves contain digests, so it recurses.

// keyDigests is the claim holding digests of object properties.
const keyDigests = "_sd"

// keyArrayDigest is the single member of an array element standing in for a
// selectively disclosable item.
const keyArrayDigest = "..."

// keyAlg names the hash function. Removed from the reconstructed output: it is
// machinery, not a claim about the subject.
const keyAlg = "_sd_alg"

// Reconstruct applies the disclosures to an issuer-signed payload.
//
// The payload must already have had its SIGNATURE verified: this function is the
// claim-processing half and says nothing about whether the issuer really signed
// what it is given. Separated that way because the two need different things --
// this needs no keys and no clock, and is therefore testable against the
// specification's own vectors without a deployment.
//
// Every rejection below is a MUST in §7.1.4.
func Reconstruct(payload map[string]any, disclosures []string) (map[string]any, error) {
	if payload == nil {
		return nil, fmt.Errorf("no issuer-signed payload")
	}
	// §4.1.1: sha-256 is the default when _sd_alg is absent, and the only value
	// this implementation produces or accepts. An unknown one is refused rather
	// than assumed, because assuming means computing digests that match nothing
	// and reporting every disclosure as unreferenced.
	if alg, present := payload[keyAlg]; present {
		s, ok := alg.(string)
		if !ok || s != AlgSHA256 {
			return nil, fmt.Errorf("_sd_alg is %v; this implementation supports only %q",
				alg, AlgSHA256)
		}
	}

	// Index the disclosures by digest, and refuse a duplicate presentation.
	//
	// Two identical disclosures are not merely redundant: the same digest would
	// be consumed twice, and §7.1.4.5's "not referenced" check would then pass
	// for a disclosure that was never independently referenced.
	byDigest := make(map[string]string, len(disclosures))
	for _, d := range disclosures {
		dig := DigestOf(d)
		if _, seen := byDigest[dig]; seen {
			return nil, fmt.Errorf("the same disclosure was presented twice")
		}
		byDigest[dig] = d
	}

	used := make(map[string]bool, len(disclosures))
	seenDigest := make(map[string]bool, len(disclosures))
	out, err := walk(payload, byDigest, used, seenDigest)
	if err != nil {
		return nil, err
	}

	// §7.1.4.5: "any Disclosure not referenced by digest value in the
	// Issuer-signed JWT" is a rejection.
	//
	// Not merely unused. A presentation carrying a disclosure the credential does
	// not reference is either a different credential's disclosure or a forgery
	// attempt, and silently ignoring it would let a holder append anything.
	if len(used) != len(byDigest) {
		var orphans []string
		for dig, enc := range byDigest {
			if !used[dig] {
				if p, perr := Parse(enc); perr == nil {
					orphans = append(orphans, p.Name)
				} else {
					orphans = append(orphans, dig[:8])
				}
			}
		}
		sort.Strings(orphans)
		return nil, fmt.Errorf("%d disclosure(s) are not referenced by the "+
			"issuer-signed JWT: %s", len(orphans), strings.Join(orphans, ", "))
	}
	return out, nil
}

// walk reconstructs one object.
func walk(obj map[string]any, byDigest map[string]string,
	used, seenDigest map[string]bool) (map[string]any, error) {

	out := make(map[string]any, len(obj))
	for k, v := range obj {
		if k == keyDigests || k == keyAlg {
			continue // machinery, removed from the result
		}
		nv, err := walkValue(v, byDigest, used, seenDigest)
		if err != nil {
			return nil, err
		}
		out[k] = nv
	}

	raw, present := obj[keyDigests]
	if !present {
		return out, nil
	}
	// Both spellings of the same array.
	//
	// A verifier reading a credential off the wire unmarshals JSON and gets
	// `[]any`. A caller handing this the output of Payload -- the issuance side of
	// this very package, which is what the round-trip test does and what an
	// issuer checking its own work would do -- gets `[]string`.
	//
	// Accepting only the first is strictly correct for the wire and produces a
	// baffling "must be an array of digests" for a payload that plainly is one.
	var list []string
	switch t := raw.(type) {
	case []string:
		list = t
	case []any:
		for _, entry := range t {
			dig, ok := entry.(string)
			if !ok {
				// §4.2.4 makes these strings. A non-string here is a malformed
				// credential, and treating it as "no match" would let an issuer
				// hide a claim behind something a verifier silently skips.
				return nil, fmt.Errorf("_sd contains a non-string entry")
			}
			list = append(list, dig)
		}
	default:
		return nil, fmt.Errorf("_sd must be an array of digests, got %T", raw)
	}
	for _, dig := range list {
		// §7.1.4.4: a digest appearing more than once anywhere in the payload.
		if seenDigest[dig] {
			return nil, fmt.Errorf("a digest appears more than once in the " +
				"issuer-signed JWT")
		}
		seenDigest[dig] = true

		enc, held := byDigest[dig]
		if !held {
			continue // not disclosed; that is the point of the format
		}
		d, err := Parse(enc)
		if err != nil {
			return nil, err
		}
		// §7.1.4.3.2.2.2.2: the claim name must not be _sd or "...".
		if d.Name == keyDigests || d.Name == keyArrayDigest {
			return nil, fmt.Errorf("a disclosure claims the name %q, which is "+
				"reserved and would rewrite the machinery of the credential", d.Name)
		}
		// §7.1.4.3.2.2.2.3: the name must not already exist at this level.
		if _, clash := out[d.Name]; clash {
			return nil, fmt.Errorf("a disclosure for %q collides with a claim "+
				"already present at that level", d.Name)
		}
		used[dig] = true

		// A disclosed value may itself contain digests.
		nv, err := walkValue(d.Value, byDigest, used, seenDigest)
		if err != nil {
			return nil, err
		}
		out[d.Name] = nv
	}
	return out, nil
}

// walkValue reconstructs any value, recursing into objects and arrays.
func walkValue(v any, byDigest map[string]string, used, seenDigest map[string]bool) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		return walk(t, byDigest, used, seenDigest)
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			obj, isObj := item.(map[string]any)
			if !isObj || len(obj) != 1 {
				nv, err := walkValue(item, byDigest, used, seenDigest)
				if err != nil {
					return nil, err
				}
				out = append(out, nv)
				continue
			}
			raw, isDigest := obj[keyArrayDigest]
			if !isDigest {
				nv, err := walkValue(item, byDigest, used, seenDigest)
				if err != nil {
					return nil, err
				}
				out = append(out, nv)
				continue
			}
			dig, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("an array digest is not a string")
			}
			if seenDigest[dig] {
				return nil, fmt.Errorf("a digest appears more than once in the " +
					"issuer-signed JWT")
			}
			seenDigest[dig] = true

			enc, held := byDigest[dig]
			if !held {
				// Undisclosed array items are OMITTED, not left as placeholders.
				// Leaving the object in would tell the verifier how many items
				// were withheld and where, which is exactly the linkability the
				// format exists to remove.
				continue
			}
			val, err := parseArrayDisclosure(enc)
			if err != nil {
				return nil, err
			}
			used[dig] = true
			nv, err := walkValue(val, byDigest, used, seenDigest)
			if err != nil {
				return nil, err
			}
			out = append(out, nv)
		}
		return out, nil
	default:
		return v, nil
	}
}

// parseArrayDisclosure decodes the two-element form, §7.1.4.3.2.3.2.1.
//
// Separate from Parse because the shapes differ and conflating them is how a
// three-element object disclosure gets accepted where an array item belongs --
// which would put a claim NAME into an array as if it were a value.
func parseArrayDisclosure(encoded string) (any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("an array disclosure is not base64url: %w", err)
	}
	var parts []any
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("an array disclosure is not a JSON array: %w", err)
	}
	if len(parts) != 2 {
		return nil, fmt.Errorf("a disclosure for an array element has two elements "+
			"(salt, value), got %d", len(parts))
	}
	if _, ok := parts[0].(string); !ok {
		return nil, fmt.Errorf("an array disclosure salt must be a string")
	}
	return parts[1], nil
}
