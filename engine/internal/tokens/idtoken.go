// Package tokens mints ID tokens and JWT access tokens.
package tokens

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/sulimanbenhalim/idp/engine/internal/keys"
)

// Type values for the JWT `typ` header.
//
// Asserting `typ` on every inbound token is what stops one token class being
// accepted where another is expected -- a logout token presented as an access
// token, for instance. RFC 9068 mandates at+jwt for JWT access tokens, and the
// back-channel logout spec mandates logout+jwt.
const (
	TypIDToken     = "JWT"
	TypAccessToken = "at+jwt"
	TypLogoutToken = "logout+jwt"
)

// IDTokenClaims is the OIDC ID token payload.
type IDTokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	AuthTime int64  `json:"auth_time,omitempty"`

	// Echoed verbatim from the authorization request. Binding the ID token to the
	// nonce the client generated is what stops a token being replayed into a
	// different session.
	Nonce string `json:"nonce,omitempty"`

	// Authentication context. These are properties of the SESSION and must be
	// re-evaluated per authorization request, not frozen at first login --
	// otherwise an acr_values step-up requirement can be satisfied by a stale
	// session that never did the extra factor.
	ACR string   `json:"acr,omitempty"`
	AMR []string `json:"amr,omitempty"`

	// sid ties this token to a session so back-channel logout can address it.
	// Always emitted: a BFF cannot map a logout token to its own session without it.
	SessionID string `json:"sid,omitempty"`

	// azp is required when the audience has more than one value, and harmless
	// otherwise; emitting it always avoids a conditional that is easy to get wrong.
	AuthorizedParty string `json:"azp,omitempty"`

	// at_hash binds the ID token to the access token issued alongside it.
	AccessTokenHash string `json:"at_hash,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Username      string `json:"preferred_username,omitempty"`
}

// Signer mints tokens with a specific key.
type Signer struct {
	key keys.Key
}

// NewSigner binds a signer to one key. Algorithm comes from the key, never from
// a caller-supplied string and never from an inbound token's header -- that is
// the algorithm-confusion defence, applied at the point of construction.
func NewSigner(k keys.Key) *Signer { return &Signer{key: k} }

// KID is the key id this signer stamps into token headers.
func (s *Signer) KID() string { return s.key.KID() }

func (s *Signer) joseAlg() (jose.SignatureAlgorithm, error) {
	switch s.key.Algorithm() {
	case keys.RS256:
		return jose.RS256, nil
	case keys.ES256:
		return jose.ES256, nil
	case keys.EdDSA:
		return jose.EdDSA, nil
	case keys.PS256:
		return jose.PS256, nil
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q", s.key.Algorithm())
	}
}

// SignIDToken mints a signed ID token.
func (s *Signer) SignIDToken(c IDTokenClaims) (string, error) {
	if c.Issuer == "" || c.Subject == "" || c.Audience == "" {
		return "", fmt.Errorf("iss, sub and aud are all required")
	}
	if c.Expiry == 0 || c.IssuedAt == 0 {
		return "", fmt.Errorf("exp and iat are required")
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return s.sign(payload, TypIDToken)
}

// SignJSON mints an arbitrary signed payload with an explicit `typ`. Used for
// access tokens and logout tokens, which share the signing path but must never
// share a type.
func (s *Signer) SignJSON(payload any, typ string) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return s.sign(b, typ)
}

func (s *Signer) sign(payload []byte, typ string) (string, error) {
	alg, err := s.joseAlg()
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(typ)).
		WithHeader(jose.HeaderKey("kid"), s.key.KID())

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: s.key.Signer()}, opts)
	if err != nil {
		return "", fmt.Errorf("building signer: %w", err)
	}
	obj, err := sig.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return obj.CompactSerialize()
}

// AtHash computes the at_hash claim: the base64url of the left-most half of the
// hash of the ASCII access token, using the hash paired with the signing
// algorithm (SHA-256 for ES256, RS256 and PS256).
//
// Getting the "left-most half" wrong is the classic at_hash bug: it is half the
// HASH, not half the token, and it is the raw bytes that are halved, not the
// base64 text.
func AtHash(alg keys.Algorithm, accessToken string) (string, error) {
	var h crypto.Hash
	switch alg {
	case keys.RS256, keys.ES256, keys.PS256:
		h = crypto.SHA256
	case keys.EdDSA:
		// Ed25519 has no paired hash in the JOSE registry, so at_hash is omitted
		// rather than guessed.
		return "", nil
	default:
		return "", fmt.Errorf("no at_hash defined for %s", alg)
	}
	if h != crypto.SHA256 {
		return "", fmt.Errorf("unsupported hash")
	}
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

// AccessTokenClaims is the RFC 9068 JWT access token payload.
type AccessTokenClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience []string `json:"aud"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	// jti is required by RFC 9068 and is what makes replay detection possible.
	JTI       string `json:"jti"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope,omitempty"`
	SessionID string `json:"sid,omitempty"`
}

// Lifetime bounds. Short access tokens are how revocation stays bounded without
// forcing introspection on every request -- see ADR-007.
const (
	DefaultAccessTokenTTL = 5 * time.Minute
	DefaultIDTokenTTL     = 5 * time.Minute
	MaxAccessTokenTTL     = 1 * time.Hour
)
