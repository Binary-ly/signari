package federation

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// assertionAlgorithms is the allow-list for RFC 7523 assertions.
//
// # This list IS the defence
//
// It is passed to the parser, so the token's own `alg` header never selects the
// verification method. That single fact is the whole of the algorithm-confusion
// class: given a free choice, an attacker picks `none` and signs nothing, or
// picks HS256 and uses the issuer's PUBLIC key as the HMAC secret -- which is
// public, so anybody can forge with it.
//
// Production identity software has shipped exactly that in this grant
// (a published advisory, CVSS 8.1, CWE-347), where it let anyone holding client
// credentials "impersonate any federated user linked to the affected Identity
// Provider".
//
// No HMAC family appears here and none ever should. An assertion is signed by a
// party we do not share a secret with; if verification ever succeeds with a
// symmetric algorithm, something has gone very wrong.
var assertionAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// VerifyAssertion checks an RFC 7523 assertion's signature against a provider's
// published keys and returns the raw claim payload.
//
// The claims are NOT interpreted here -- that is oauth.ValidateAssertionClaims,
// which needs no network and no database. This half owns exactly one question:
// did the party we trust actually sign this?
func VerifyAssertion(ctx context.Context, hc *http.Client, cache *JWKSCache,
	c Config, raw string) ([]byte, error) {

	sig, err := jose.ParseSigned(raw, assertionAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("the assertion did not parse: %w", err)
	}
	if len(sig.Signatures) != 1 {
		// A multi-signature JWS is legal JOSE and is not a JWT. Accepting one
		// means choosing which signature counted, and every choice is somebody
		// else's confusion bug.
		return nil, fmt.Errorf("the assertion must carry exactly one signature")
	}
	h := sig.Signatures[0].Header

	// Key material carried by the token is refused outright.
	//
	// Verification below only ever uses keys fetched from the provider, so an
	// embedded key is already inert -- this is belt and braces, and it is here
	// because "already inert" is a property of the code underneath, which is
	// exactly the kind of thing a later refactor changes without noticing.
	if h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil ||
		h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return nil, fmt.Errorf("the assertion carries its own key material")
	}

	set, err := cache.Get(ctx, hc, c.JWKSURL(), h.KeyID)
	if err != nil {
		return nil, fmt.Errorf("fetching the issuer's keys: %w", err)
	}

	// By `kid` when the assertion names one. Every serious issuer does, and it is
	// what lets the cache tell "I have never seen this key" from "this signature
	// is wrong" -- the first is a rotation to pick up, the second is an attack.
	if h.KeyID != "" {
		for _, k := range set.Keys {
			if k.KeyID != h.KeyID {
				continue
			}
			payload, verr := sig.Verify(k)
			if verr != nil {
				return nil, fmt.Errorf("the assertion's signature does not verify")
			}
			return payload, nil
		}
		return nil, fmt.Errorf("the issuer publishes no key with id %q", h.KeyID)
	}

	// No `kid`: try each published key. Safe because every candidate came from the
	// issuer's own key set and the algorithm was pinned above -- the attacker
	// chooses neither.
	for _, k := range set.Keys {
		if payload, verr := sig.Verify(k); verr == nil {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("the assertion's signature does not verify against any of " +
		"the issuer's published keys")
}
