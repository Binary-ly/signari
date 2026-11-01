// Package extfactor is the wire contract of the external_factor sign-in stage
// (10.03): a service of the operator's own proves something about a person, and
// this engine believes it because of who signed the answer.
//
// The browser carries both directions, so nothing here is confidential and
// everything is signed. The engine sends a challenge it signed with its own
// keys, which the service checks against this issuer's JWKS. The service answers
// with a JWS signed by a key it registered, naming the challenge's nonce, the
// person the challenge named, and what it proved. The nonce is spent once.
//
// # Why the keys are asymmetric
//
// A shared secret is a key this server holds, so this server could have written
// any answer it accepts, and so could anybody who reads it out of the database.
// The explicit list below refuses HS256 at the parser, and `none` with it, and
// CheckKeys refuses a key set holding anything but public keys.
//
// # Why amr is a declared set
//
// amr reaches relying parties in the ID token, and acr is derived from it. A
// service's answer can only narrow what the operator said it may claim, so a
// compromised service cannot promote itself to a stronger factor than it was
// registered as, and an undeclared value refuses the answer rather than being
// dropped: dropping it would sign somebody in on a claim nobody agreed to read.
package extfactor

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// TypChallenge and TypResponse keep the two directions, and every other
	// token either party signs, from being taken for each other. An ID token the
	// service signed with the same key, carrying a nonce, is not an answer.
	TypChallenge = "factor-challenge+jwt"
	TypResponse  = "factor-response+jwt"

	// ChallengeLifetime bounds how long a person may take. A push times out well
	// inside it.
	ChallengeLifetime = 5 * time.Minute

	// clockLeeway forgives a service's clock, the same minute a federation's
	// statements are given.
	clockLeeway = time.Minute
)

// algorithms are what an answer may be signed with. Symmetric algorithms are
// left out on purpose; see the package comment.
var algorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Challenge is what the engine signs and sends the person to the service with.
type Challenge struct {
	Issuer string `json:"iss"`
	// Audience is the service's registered issuer.
	Audience string `json:"aud"`
	// Subject is the person, and the answer must name the same one.
	Subject string `json:"sub"`
	// LoginHint is how the person signs in, for a service that keys people on
	// that rather than on sub. Empty when they have neither name.
	LoginHint string `json:"login_hint,omitempty"`
	Nonce     string `json:"nonce"`
	// ReturnTo is where the service sends the browser, with `response` added.
	ReturnTo string `json:"return_to"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
}

// Expected is what an answer is checked against. All of it comes from the
// engine's own records, none from the request.
type Expected struct {
	// Issuer is the service's registered issuer.
	Issuer string
	// Audience is this server's issuer.
	Audience string
	Subject  string
	// JWKS is the service's registered key set.
	JWKS []byte
	// Declared is the amr the service was registered as able to claim.
	Declared []string
}

// Answer is a verified response. The nonce is still to be spent.
type Answer struct {
	Nonce string
	AMR   []string
}

type responseClaims struct {
	Issuer   string       `json:"iss"`
	Audience jwt.Audience `json:"aud"`
	Subject  string       `json:"sub"`
	Nonce    string       `json:"nonce"`
	AMR      []string     `json:"amr"`
	IssuedAt int64        `json:"iat"`
	Expiry   int64        `json:"exp"`
}

// Verify checks a response. It says why it refused, for the log; the person is
// told nothing that distinguishes one reason from another.
func Verify(raw string, want Expected, now time.Time) (*Answer, error) {
	tok, err := jose.ParseSigned(raw, algorithms)
	if err != nil {
		return nil, fmt.Errorf("not a JWS signed with an asymmetric algorithm: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("it carries %d signatures, and one is expected", len(tok.Signatures))
	}
	if typ, _ := tok.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string); typ != TypResponse {
		return nil, fmt.Errorf("its typ is %q, and %q is expected", typ, TypResponse)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(want.JWKS, &set); err != nil {
		return nil, fmt.Errorf("the registered key set does not parse: %w", err)
	}
	var payload []byte
	for _, k := range set.Keys {
		if p, verr := tok.Verify(k); verr == nil {
			payload = p
			break
		}
	}
	if payload == nil {
		return nil, errors.New("it is not signed by a key the service registered")
	}

	var c responseClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("its payload does not parse: %w", err)
	}
	switch {
	case c.Issuer != want.Issuer:
		return nil, fmt.Errorf("its iss is %q, and %q is registered", c.Issuer, want.Issuer)
	case !c.Audience.Contains(want.Audience):
		return nil, fmt.Errorf("it is not addressed to %q", want.Audience)
	case c.Subject != want.Subject:
		return nil, errors.New("it names somebody other than the person challenged")
	case c.Nonce == "":
		return nil, errors.New("it has no nonce")
	case c.Expiry == 0 || c.IssuedAt == 0:
		return nil, errors.New("it needs both exp and iat")
	case now.After(time.Unix(c.Expiry, 0).Add(clockLeeway)):
		return nil, errors.New("it has expired")
	case time.Unix(c.IssuedAt, 0).After(now.Add(clockLeeway)):
		return nil, errors.New("it was issued in the future")
	case len(c.AMR) == 0:
		return nil, errors.New("it claims to have proved nothing")
	}
	for _, v := range c.AMR {
		if !slices.Contains(want.Declared, v) {
			return nil, fmt.Errorf("it claims amr %q, which the service was not registered with", v)
		}
	}
	return &Answer{Nonce: c.Nonce, AMR: c.AMR}, nil
}

// routeValues are the amr values that say how somebody arrived rather than what
// else they proved. A flow reads them (primaryProof) to tell which route a
// sign-in took, so a service claiming one could turn a password sign-in into a
// federated one in a flow that branches on the difference.
var routeValues = []string{"pwd", "fed", "krb", "user"}

// amrValue admits no colon, so no service can write a walk's own marks
// (flow.Mark).
var amrValue = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// CheckDeclared is what registering a service refuses of its amr: none at all,
// a value that could not be one, or one that says how somebody arrived.
func CheckDeclared(amr []string) error {
	if len(amr) == 0 {
		return errors.New("it needs at least one amr value, the most it may claim to have proved")
	}
	for _, v := range amr {
		if !amrValue.MatchString(v) {
			return fmt.Errorf("%q is not an amr value: lower-case letters, digits, - and _", v)
		}
		if slices.Contains(routeValues, v) {
			return fmt.Errorf("%q says how somebody arrived, which a sign-in's route decides "+
				"and a service does not", v)
		}
	}
	return nil
}

// CheckKeys is what registering a service refuses of its key set: one that does
// not parse, holds no keys, or holds anything but public keys. It answers how
// many keys it holds.
func CheckKeys(jwks []byte) (int, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwks, &set); err != nil {
		return 0, fmt.Errorf("the key set is not a JSON Web Key Set: %w", err)
	}
	if len(set.Keys) == 0 {
		return 0, errors.New("the key set holds no keys")
	}
	for i, k := range set.Keys {
		// Valid goes first: IsPublic is false of a symmetric key as of a private
		// one, and the message has to fit both.
		if !k.Valid() {
			return 0, fmt.Errorf("key %d is not usable", i)
		}
		if !k.IsPublic() {
			return 0, fmt.Errorf("key %d is not a public key; register only the service's public "+
				"keys, or this server could write the answers it is meant to be checking", i)
		}
	}
	return len(set.Keys), nil
}
