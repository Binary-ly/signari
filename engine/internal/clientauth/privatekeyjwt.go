// Package clientauth verifies how a client proves who it is at the token
// endpoint.
//
// # private_key_jwt
//
// The client signs a short-lived assertion with a key we hold only the public
// half of. The private half never crosses the network, so our database leaking
// discloses nothing that authenticates as that client -- unlike a secret hash,
// which can be attacked offline, or the plaintext some products still store.
//
// # What the assertion must prove, and what goes wrong without each check
//
//	iss == sub == client_id   otherwise a client asserts on behalf of another
//	aud is US                 otherwise an assertion made for a DIFFERENT
//	                          authorization server can be replayed here --
//	                          the audience is the ONLY thing stopping a
//	                          client's assertion to one AS being reused at
//	                          another, and it is the check most often skipped
//	exp present and short     otherwise the assertion is a bearer credential
//	                          with no expiry, which is a client secret again
//	jti unique                otherwise a captured assertion is replayable
//	                          within its lifetime
//	signature by a registered key   otherwise anybody may sign one
//	asymmetric alg            otherwise the client's own secret verifies it,
//	                          which is client_secret_jwt wearing this name
package clientauth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// AssertionType is the fixed value RFC 7523 requires.
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// MaxAssertionLifetime bounds how long an assertion may claim to be valid.
//
// The client mints one per request and holds the key, so there is no legitimate
// reason for a long one. An assertion valid for a day is a bearer credential
// valid for a day -- which is the shared secret this mechanism exists to remove.
const MaxAssertionLifetime = 5 * time.Minute

const MaxClockSkew = 10 * time.Second

// maxAssertionBytes bounds the parameter before any parsing.
const maxAssertionBytes = 16 << 10

// allowedAlgs is asymmetric only.
//
// A symmetric algorithm here would be verified with a key both sides hold --
// which is client_secret_jwt, a different mechanism with different properties.
// Accepting it under this name means a client configured for private_key_jwt
// could be authenticated by something an attacker who read our database can
// forge.
var allowedAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Assertion is a verified client assertion.
type Assertion struct {
	ClientID string
	JTI      string
	Expiry   time.Time
}

type assertionClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	Expiry    int64           `json:"exp"`
	IssuedAt  int64           `json:"iat"`
	NotBefore int64           `json:"nbf"`
	JTI       string          `json:"jti"`
}

// VerifyPrivateKeyJWT checks a client assertion.
//
// clientID is what the request claims; jwksJSON is the client's registered
// public key set. audiences is every value we accept in `aud` -- the issuer and
// the token endpoint URL, because implementations legitimately differ about
// which to use and rejecting one breaks real clients.
func VerifyPrivateKeyJWT(assertion, clientID, jwksJSON string, audiences []string, now time.Time) (*Assertion, error) {
	if assertion == "" {
		return nil, fmt.Errorf("no client assertion")
	}
	if len(assertion) > maxAssertionBytes {
		return nil, fmt.Errorf("the client assertion is %d bytes, over the limit", len(assertion))
	}
	if strings.TrimSpace(jwksJSON) == "" {
		return nil, fmt.Errorf("this client has no registered keys, so a signed " +
			"assertion cannot be verified")
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		return nil, fmt.Errorf("the client's registered key set did not parse: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("the client's registered key set is empty")
	}

	tok, err := jose.ParseSigned(assertion, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("the client assertion did not parse: %w", err)
	}

	// Verified against the REGISTERED keys, never against a key carried in the
	// assertion's own header. A `jwk` header here would let the assertion name
	// the key that verifies it, which authenticates nobody.
	var payload []byte
	var lastErr error
	for _, k := range jwks.Keys {
		if !k.IsPublic() {
			// A private key in a client's registered set is a configuration
			// error serious enough to refuse: it means somebody pasted the wrong
			// half, and it is now in our database.
			return nil, fmt.Errorf("the client's registered key set contains private " +
				"key material; register the PUBLIC keys only")
		}
		if p, verr := tok.Verify(k); verr == nil {
			payload = p
			break
		} else {
			lastErr = verr
		}
	}
	if payload == nil {
		return nil, fmt.Errorf("the client assertion was not signed by any registered key: %w", lastErr)
	}

	var c assertionClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("the client assertion claims did not parse: %w", err)
	}

	// iss and sub must both be the client. RFC 7523 §3: for client
	// authentication they are the client id, and accepting a mismatch lets one
	// client present an assertion asserting another's identity.
	if c.Issuer != clientID || c.Subject != clientID {
		return nil, fmt.Errorf("the assertion's iss/sub (%q/%q) do not both match the "+
			"client id %q", c.Issuer, c.Subject, clientID)
	}

	// THE audience check. Without it, an assertion this client made for a
	// different authorization server can be replayed here -- and clients
	// legitimately talk to several. It is the check most often skipped, because
	// everything works without it right up until it matters.
	if !audienceMatches(c.Audience, audiences) {
		return nil, fmt.Errorf("the assertion's audience is not this server; it was "+
			"made for somebody else (accepted: %s)", strings.Join(audiences, ", "))
	}

	if c.JTI == "" {
		return nil, fmt.Errorf("the assertion has no jti, so a replay could not be detected")
	}
	if c.Expiry == 0 {
		return nil, fmt.Errorf("the assertion has no exp, so it would never expire")
	}
	exp := time.Unix(c.Expiry, 0)
	if now.After(exp) {
		return nil, fmt.Errorf("the assertion expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if exp.Sub(now) > MaxAssertionLifetime {
		// A long-lived assertion is a bearer credential, which is the thing this
		// mechanism replaces. Refused rather than trimmed, because trimming would
		// accept a credential the client believes is still valid.
		return nil, fmt.Errorf("the assertion is valid for %s, over the %s limit",
			exp.Sub(now).Round(time.Second), MaxAssertionLifetime)
	}
	if c.NotBefore != 0 && time.Unix(c.NotBefore, 0).After(now.Add(MaxClockSkew)) {
		return nil, fmt.Errorf("the assertion is not valid until %s, more than %s from now",
			time.Unix(c.NotBefore, 0).UTC().Format(time.RFC3339), MaxClockSkew)
	}

	// iat was parsed into the claims and never read -- a field that looked
	// validated and was not. An assertion issued an hour in the future was
	// accepted, because the only bound on time was MaxAssertionLifetime, which
	// measures `exp` against now and says nothing about where the window sits.
	//
	// Future-dating does not lengthen the window; it MOVES it. Combined with a
	// replay cache that forgets a jti once its assertion has expired, an
	// assertion whose window has not opened yet is a credential the server has
	// agreed to honour later, which is not what anybody reviewing this thought
	// they were agreeing to.
	if c.IssuedAt != 0 {
		iat := time.Unix(c.IssuedAt, 0)
		if iat.After(now.Add(MaxClockSkew)) {
			return nil, fmt.Errorf("the assertion says it was issued at %s, which is in "+
				"the future by more than %s", iat.UTC().Format(time.RFC3339), MaxClockSkew)
		}
		// And the other end. MaxAssertionLifetime is meant to stop an assertion
		// being a long-lived bearer credential, and it only measures forwards --
		// so one minted an hour ago with `exp` two minutes out slipped past it,
		// having been usable for that whole hour.
		if now.Sub(iat) > MaxAssertionLifetime {
			return nil, fmt.Errorf("the assertion was issued %s ago, over the %s limit; "+
				"a client mints one per request and holds the key, so there is no "+
				"reason for an old one",
				now.Sub(iat).Round(time.Second), MaxAssertionLifetime)
		}
	}

	return &Assertion{ClientID: clientID, JTI: c.JTI, Expiry: exp}, nil
}

// audienceMatches accepts a string or an array, and requires an exact match.
func audienceMatches(raw json.RawMessage, accepted []string) bool {
	if len(raw) == 0 {
		return false
	}
	ok := func(v string) bool {
		for _, a := range accepted {
			if v == a {
				return true
			}
		}
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return ok(one)
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, v := range many {
			if ok(v) {
				return true
			}
		}
	}
	return false
}
