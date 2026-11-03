package oid4vp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/sdjwt"
)

// Expect is what a presentation has to match: this verifier, this request, and
// the issuers it believes.
type Expect struct {
	// ClientID is the whole client identifier, prefix included, which a Key
	// Binding JWT's aud must be (specs/oid4vp.txt:3631, and :2083 on using the
	// whole of it).
	ClientID string
	// Nonce is the request's, which its nonce must be (:3629).
	Nonce string
	Ask   Ask
	// Issuers are the issuers believed, each with the keys its credentials are
	// checked with. An issuer not here is not believed, whatever it signed with.
	Issuers map[string]*jose.JSONWebKeySet
	Now     time.Time
}

// Presented is a credential that passed every check, and what it said.
type Presented struct {
	Issuer, VCT string
	// Claims is the processed SD-JWT payload (specs/rfc9901.txt:1754-1758).
	Claims map[string]any
}

// How far a Key Binding JWT's iat may be from now. RFC 9901 leaves the window
// to the verifier (specs/rfc9901.txt:1860-1861). The key binding is made for
// this request, which lives five minutes, so a binding older than that was made
// for something else.
const (
	KeyBindingMaxAge = RequestLifetime
	clockSkew        = time.Minute
)

// The types a credential's header may carry. dc+sd-jwt is the type, and
// vc+sd-jwt the one it replaced, which "should be accepted ... for a reasonable
// transitional period" (specs/sdjwtvc.txt:327-331, 350-356).
var credentialTypes = []string{"dc+sd-jwt", "vc+sd-jwt"}

// TypKeyBinding is the Key Binding JWT's typ (specs/rfc9901.txt:914-915).
const TypKeyBinding = "kb+jwt"

// Verify checks a vp_token against e, section 8.6, and returns the one
// credential it answers with.
//
// Any failure refuses the whole token. Section 8.6 discards a failed
// presentation and keeps the rest, but the query asks for exactly one, so with
// it discarded there is nothing left to sign anybody in with.
func Verify(vpToken string, e Expect) (*Presented, error) {
	// "a JSON-encoded object containing entries where the key is the id value
	// used for a Credential Query in the DCQL query and the value is an array of
	// one or more Presentations"; with multiple left false "the array MUST
	// contain only one Presentation" (specs/oid4vp.txt:1302).
	var token map[string]json.RawMessage
	if err := json.Unmarshal([]byte(vpToken), &token); err != nil {
		return nil, fmt.Errorf("the vp_token is not a JSON object: %w", err)
	}
	if len(token) != 1 {
		return nil, fmt.Errorf("the vp_token answers %d credential queries, and one was asked", len(token))
	}
	raw, ok := token[e.Ask.ID]
	if !ok {
		return nil, fmt.Errorf("the vp_token does not answer credential query %q", e.Ask.ID)
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("the answer to %q is not an array of presentations: %w", e.Ask.ID, err)
	}
	if len(list) != 1 {
		return nil, fmt.Errorf("the answer to %q holds %d presentations, and one was asked", e.Ask.ID, len(list))
	}
	return verifyPresentation(list[0], e)
}

func verifyPresentation(presentation string, e Expect) (*Presented, error) {
	jwt, disclosures, kb, err := sdjwt.Split(presentation)
	if err != nil {
		return nil, err
	}
	// Key binding is required by this verifier's policy, and RFC 9901 says that
	// decision "MUST NOT be based on whether or not a Key Binding JWT is
	// provided" (specs/rfc9901.txt:1830-1836).
	if kb == "" {
		return nil, fmt.Errorf("the presentation has no Key Binding JWT, and one is required")
	}

	payload, issuer, err := verifyIssuerSigned(jwt, e)
	if err != nil {
		return nil, err
	}

	// cnf, before the disclosures, so a credential that cannot be bound is
	// refused for that and not for whatever its disclosures do.
	holder, err := holderKey(payload)
	if err != nil {
		return nil, err
	}

	claims, err := sdjwt.Reconstruct(payload, disclosures)
	if err != nil {
		return nil, err
	}

	vct, _ := claims["vct"].(string)
	if !slices.Contains(e.Ask.VCTValues, vct) {
		return nil, fmt.Errorf("the credential's type is %q, and %v were asked for", vct, e.Ask.VCTValues)
	}
	if err := validity(claims, e.Now); err != nil {
		return nil, err
	}

	// sd_hash is over everything before the Key Binding JWT: the Issuer-signed
	// JWT and each Disclosure, each followed by a tilde (specs/rfc9901.txt:948-956).
	if err := verifyKeyBinding(kb, presentation[:len(presentation)-len(kb)], holder, e); err != nil {
		return nil, err
	}

	// "it MUST NOT rely on the Wallet to enforce these constraints"
	// (specs/oid4vp.txt:2087-2091): every claim asked for has to be there.
	for _, p := range e.Ask.Claims {
		if _, err := Select(claims, p); err != nil {
			return nil, fmt.Errorf("the credential does not carry a claim that was asked for: %w", err)
		}
	}
	return &Presented{Issuer: issuer, VCT: vct, Claims: claims}, nil
}

// verifyIssuerSigned checks the Issuer-signed JWT, RFC 9901 §7.1 step 2
// (specs/rfc9901.txt:1661-1675), with the key found as SD-JWT VC §2.5 has it
// found: by a mechanism "permitted for the given Issuer according to policy"
// (specs/sdjwtvc.txt:1080-1083). Here that is keys the operator has pinned for
// the issuer, and nothing else.
func verifyIssuerSigned(jwt string, e Expect) (map[string]any, string, error) {
	tok, err := jose.ParseSigned(jwt, Algorithms())
	if err != nil {
		return nil, "", fmt.Errorf("the credential did not parse: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return nil, "", fmt.Errorf("a credential carries exactly one signature")
	}
	h := tok.Signatures[0].Protected
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	if !slices.Contains(credentialTypes, typ) {
		return nil, "", fmt.Errorf("the credential's typ is %q, not dc+sd-jwt", typ)
	}

	// The issuer is read before the signature is checked, to find whose keys to
	// check it with, and nothing else is: an issuer named and not believed stops
	// here, and one believed is held to its own keys alone.
	var named struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(tok.UnsafePayloadWithoutVerification(), &named); err != nil {
		return nil, "", fmt.Errorf("the credential's payload is not JSON: %w", err)
	}
	keys := e.Issuers[named.Issuer]
	if named.Issuer == "" || keys == nil {
		return nil, "", fmt.Errorf("the credential is from %q, which is not an issuer this verifier believes", named.Issuer)
	}
	verified, err := verifyWith(tok, keys)
	if err != nil {
		return nil, "", fmt.Errorf("the credential's signature does not verify with %s's keys: %w", named.Issuer, err)
	}

	payload := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(verified))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil, "", fmt.Errorf("the credential's payload is not a JSON object: %w", err)
	}
	return payload, named.Issuer, nil
}

// verifyWith checks tok against the pinned keys: the one its kid names, or with
// no kid each key in turn.
func verifyWith(tok *jose.JSONWebSignature, set *jose.JSONWebKeySet) ([]byte, error) {
	candidates := set.Keys
	if kid := tok.Signatures[0].Protected.KeyID; kid != "" {
		candidates = set.Key(kid)
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no key %q", kid)
		}
	}
	var last error = errors.New("no key")
	for _, k := range candidates {
		if !k.IsPublic() || !asymmetric(k.Key) {
			continue
		}
		out, err := tok.Verify(k.Key)
		if err == nil {
			return out, nil
		}
		last = err
	}
	return nil, last
}

func asymmetric(k any) bool {
	switch k.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return true
	}
	return false
}

// holderKey is the key the Key Binding JWT must be signed with: cnf's jwk,
// which SD-JWT VC says "MUST be used" (specs/sdjwtvc.txt:1043-1046).
func holderKey(payload map[string]any) (*jose.JSONWebKey, error) {
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the credential has no cnf, so nobody can prove they hold it")
	}
	raw, ok := cnf["jwk"]
	if !ok {
		return nil, fmt.Errorf("the credential's cnf names no jwk")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("the credential's cnf jwk does not parse: %w", err)
	}
	if !k.IsPublic() || !asymmetric(k.Key) {
		return nil, fmt.Errorf("the credential's cnf jwk is not a public signing key")
	}
	return &k, nil
}

// validity is RFC 9901 §7.1 step 6, nbf and exp (specs/rfc9901.txt:1749-1752).
func validity(claims map[string]any, now time.Time) error {
	if exp, ok, err := numericDate(claims, "exp"); err != nil {
		return err
	} else if ok && !now.Before(exp.Add(clockSkew)) {
		return fmt.Errorf("the credential expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if nbf, ok, err := numericDate(claims, "nbf"); err != nil {
		return err
	} else if ok && now.Add(clockSkew).Before(nbf) {
		return fmt.Errorf("the credential is not valid until %s", nbf.UTC().Format(time.RFC3339))
	}
	return nil
}

func numericDate(claims map[string]any, name string) (time.Time, bool, error) {
	v, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false, fmt.Errorf("the credential's %s is not a number", name)
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false, fmt.Errorf("the credential's %s is not a number", name)
	}
	return time.Unix(int64(f), 0), true, nil
}

// verifyKeyBinding is RFC 9901 §7.3 step 5 (specs/rfc9901.txt:1844-1873), with
// OID4VP's rule for aud and nonce (specs/oid4vp.txt:3627-3631).
func verifyKeyBinding(kb, sdJWT string, holder *jose.JSONWebKey, e Expect) error {
	tok, err := jose.ParseSigned(kb, Algorithms())
	if err != nil {
		return fmt.Errorf("the Key Binding JWT did not parse: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return fmt.Errorf("a Key Binding JWT carries exactly one signature")
	}
	if typ, _ := tok.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string); typ != TypKeyBinding {
		return fmt.Errorf("the Key Binding JWT's typ is %q, not %s", typ, TypKeyBinding)
	}
	verified, err := tok.Verify(holder.Key)
	if err != nil {
		return fmt.Errorf("the Key Binding JWT is not signed by the credential's holder key: %w", err)
	}
	var c struct {
		IssuedAt json.Number     `json:"iat"`
		Audience json.RawMessage `json:"aud"`
		Nonce    *string         `json:"nonce"`
		SDHash   string          `json:"sd_hash"`
	}
	dec := json.NewDecoder(bytes.NewReader(verified))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("the Key Binding JWT's claims did not parse: %w", err)
	}

	iat, err := c.IssuedAt.Float64()
	if c.IssuedAt == "" || err != nil {
		return fmt.Errorf("the Key Binding JWT has no iat")
	}
	issued := time.Unix(int64(iat), 0)
	if issued.After(e.Now.Add(clockSkew)) {
		return fmt.Errorf("the Key Binding JWT is dated %s, in the future", issued.UTC().Format(time.RFC3339))
	}
	if e.Now.Sub(issued) > KeyBindingMaxAge+clockSkew {
		return fmt.Errorf("the Key Binding JWT is from %s, older than this request", issued.UTC().Format(time.RFC3339))
	}

	// "aud: REQUIRED. The value MUST be a single string" (specs/rfc9901.txt:927-928).
	var aud string
	if err := json.Unmarshal(c.Audience, &aud); err != nil {
		return fmt.Errorf("the Key Binding JWT's aud is not a single string")
	}
	if aud != e.ClientID {
		return fmt.Errorf("the Key Binding JWT was made for %q, not for this verifier, %q", aud, e.ClientID)
	}
	if c.Nonce == nil || *c.Nonce != e.Nonce {
		return fmt.Errorf("the Key Binding JWT does not carry this request's nonce")
	}

	// The same hash as the disclosures, which Reconstruct has already held to
	// sha-256 (specs/rfc9901.txt:958-960).
	if want := sdjwt.DigestOf(sdJWT); c.SDHash != want {
		return fmt.Errorf("the Key Binding JWT's sd_hash is not over this presentation")
	}
	return nil
}
