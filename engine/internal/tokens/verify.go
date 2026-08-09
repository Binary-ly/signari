package tokens

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/sulimanbenhalim/idp/engine/internal/keys"
)

// ErrInvalidToken is the only failure a caller can distinguish. The reason is
// logged, never returned: telling a bearer *why* their token failed is a probing
// oracle.
var ErrInvalidToken = errors.New("token is invalid")

// Leeway absorbs clock skew between us and whoever minted the token. Small on
// purpose -- generous leeway extends the life of a revoked token.
const Leeway = 60 * time.Second

// VerifyAccessToken parses and validates one of our own JWT access tokens.
//
// The defences, each of which is a shipped CVE somewhere:
//
//   - The permitted algorithms are passed to the parser explicitly, so the
//     token's own `alg` header can never select the verification method. That is
//     the algorithm-confusion class (RS256 verified as HS256 using the public key
//     as an HMAC secret).
//   - `jku`, `x5u` and an embedded `jwk` are rejected. Each is an SSRF and
//     key-injection primitive: an attacker who can point key resolution at a URL
//     they control has forged a token.
//   - The key is resolved by `kid` against OUR key set only.
//   - `typ` must be at+jwt. Without this a logout token or an ID token can be
//     presented as an access token, since they share a signer.
func VerifyAccessToken(set *keys.Set, issuer, raw string) (*AccessTokenClaims, error) {
	// Only the algorithms we actually sign with. jose requires this list up
	// front, which is exactly the right shape: it is impossible to "forget" to
	// pin the algorithm.
	permitted := []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256, jose.EdDSA}

	tok, err := jose.ParseSigned(raw, permitted)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(tok.Signatures) != 1 {
		// Multiple signatures means ambiguity about which one was checked.
		return nil, fmt.Errorf("%w: expected exactly one signature", ErrInvalidToken)
	}
	h := tok.Signatures[0].Header

	if h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil ||
		h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return nil, fmt.Errorf("%w: token carries its own key material", ErrInvalidToken)
	}
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != TypAccessToken {
		return nil, fmt.Errorf("%w: typ is %q, want %q", ErrInvalidToken, typ, TypAccessToken)
	}
	if h.KeyID == "" {
		return nil, fmt.Errorf("%w: no kid", ErrInvalidToken)
	}

	key, ok := set.ByKID(h.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrInvalidToken, h.KeyID)
	}
	// The key's declared algorithm must match the header. Resolving a key by kid
	// and then trusting the header's alg would reopen algorithm confusion through
	// the back door.
	if string(key.Algorithm()) != h.Algorithm {
		return nil, fmt.Errorf("%w: kid %q is %s, token claims %s",
			ErrInvalidToken, h.KeyID, key.Algorithm(), h.Algorithm)
	}

	payload, err := tok.Verify(key.Signer().Public())
	if err != nil {
		return nil, fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
	}

	var c AccessTokenClaims
	if err := jsonUnmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}

	now := time.Now()
	switch {
	case c.Issuer != issuer:
		return nil, fmt.Errorf("%w: wrong issuer", ErrInvalidToken)
	case c.Subject == "":
		return nil, fmt.Errorf("%w: no subject", ErrInvalidToken)
	case c.Expiry == 0 || now.After(time.Unix(c.Expiry, 0).Add(Leeway)):
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	case c.IssuedAt == 0 || now.Add(Leeway).Before(time.Unix(c.IssuedAt, 0)):
		return nil, fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	case c.JTI == "":
		// RFC 9068 requires jti; without it replay detection is impossible.
		return nil, fmt.Errorf("%w: no jti", ErrInvalidToken)
	}
	return &c, nil
}

// HasScope reports whether a space-delimited scope string contains one scope.
func HasScope(scope, want string) bool {
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if scope[start:i] == want {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
