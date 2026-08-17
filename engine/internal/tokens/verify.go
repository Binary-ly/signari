package tokens

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
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
//
// VerifyAccessToken accepts a token minted under the deployment's own issuer.
func VerifyAccessToken(set *keys.Set, issuer, raw string) (*AccessTokenClaims, error) {
	return VerifyAccessTokenAny(set, []string{issuer}, raw)
}

// VerifyAccessTokenAny accepts any of several issuers.
//
// Needed because a client mid-migration has its tokens minted under a REGISTERED
// legacy issuer (migration 0015), and would otherwise be unable to call our own
// userinfo or introspection with the tokens we just gave it -- the migration
// feature would break the very applications it exists to keep working.
//
// The list is the deployment's issuer plus its registered aliases, and nothing
// else. It is emphatically not "skip the issuer check": an unregistered issuer
// is still refused, which is what keeps this from being a mix-up attack.
func VerifyAccessTokenAny(set *keys.Set, issuers []string, raw string) (*AccessTokenClaims, error) {
	// The header and signature checks live in verifiedPayload, shared with
	// VerifyTypedJSON. Two copies of this is one copy that eventually forgets
	// the jku check, which is alg confusion through the back door.
	payload, err := verifiedPayload(set, raw, TypAccessToken)
	if err != nil {
		return nil, err
	}

	var c AccessTokenClaims
	if err := jsonUnmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}

	accepted := false
	for _, i := range issuers {
		if i != "" && c.Issuer == i {
			accepted = true
			break
		}
	}

	now := time.Now()
	switch {
	case !accepted:
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

// VerifyIDTokenAudience verifies an ID token and returns its audience.
//
// Used for `id_token_hint` at the end-session endpoint, where the only question is
// which client is asking. Expiry is deliberately NOT enforced: a user signing out
// after their ID token expired is the normal case, and refusing the hint would
// make logout harder precisely when it matters. The signature and issuer still
// must check out, so the hint cannot be forged.
func VerifyIDTokenAudience(set *keys.Set, issuer, raw string) (string, error) {
	permitted := []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256, jose.EdDSA}
	tok, err := jose.ParseSigned(raw, permitted)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(tok.Signatures) != 1 {
		return "", fmt.Errorf("%w: expected exactly one signature", ErrInvalidToken)
	}
	h := tok.Signatures[0].Header
	if h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil ||
		h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return "", fmt.Errorf("%w: token carries its own key material", ErrInvalidToken)
	}
	key, ok := set.ByKID(h.KeyID)
	if !ok {
		return "", fmt.Errorf("%w: unknown kid", ErrInvalidToken)
	}
	if string(key.Algorithm()) != h.Algorithm {
		return "", fmt.Errorf("%w: kid/alg mismatch", ErrInvalidToken)
	}
	payload, err := tok.Verify(key.Signer().Public())
	if err != nil {
		return "", fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
	}
	var c IDTokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}
	if c.Issuer != issuer {
		return "", fmt.Errorf("%w: wrong issuer", ErrInvalidToken)
	}
	return c.Audience, nil
}

// VerifyTyped verifies a token this server issued for its own internal use and
// returns the raw payload.
//
// The `typ` is checked against an expected value, which is what keeps
// single-purpose tokens single-purpose: a pending-authentication token must not
// be accepted where an access token is expected, and vice versa. Enforcing that
// structurally beats relying on every call site to remember.
//
// Deliberately NOT exported for general token verification -- it does not
// enforce subject, jti or audience, because internal tokens carry their own
// shape. Callers must validate their own claims after unmarshalling.
func VerifyTyped(set *keys.Set, issuer, raw, wantTyp string) ([]byte, error) {
	permitted := []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256, jose.EdDSA}
	tok, err := jose.ParseSigned(raw, permitted)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one signature", ErrInvalidToken)
	}
	h := tok.Signatures[0].Header
	if h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil ||
		h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return nil, fmt.Errorf("%w: token carries its own key material", ErrInvalidToken)
	}
	if typ, _ := h.ExtraHeaders[jose.HeaderKey("typ")].(string); typ != wantTyp {
		return nil, fmt.Errorf("%w: typ is %q, want %q", ErrInvalidToken, typ, wantTyp)
	}
	key, ok := set.ByKID(h.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid", ErrInvalidToken)
	}
	if string(key.Algorithm()) != h.Algorithm {
		return nil, fmt.Errorf("%w: kid/alg mismatch", ErrInvalidToken)
	}
	payload, err := tok.Verify(key.PublicJWK().Key)
	if err != nil {
		return nil, fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
	}
	var probe struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}
	if probe.Issuer != issuer {
		return nil, fmt.Errorf("%w: wrong issuer", ErrInvalidToken)
	}
	return payload, nil
}

// VerifyTypedJSON verifies any JWT we issued and decodes it into `into`.
//
// # Why this shares its checks with VerifyAccessTokenAny
//
// The hardening below -- no embedded key material, kid required, the algorithm
// pinned to the KEY's declared one rather than the header's, exactly one
// signature -- is the part that is easy to write twice and get right once. A
// second verifier that forgot the jku check would accept a token carrying its
// own key, which is the whole of CVE-class "alg confusion" in one line.
//
// So the shared part lives in verifiedPayload and both callers use it. The only
// thing this adds is that `typ` must be the one the caller named, which is what
// stops a token minted for one purpose being presented for another.
func VerifyTypedJSON(set *keys.Set, issuers []string, raw, wantTyp string, into any) error {
	payload, err := verifiedPayload(set, raw, wantTyp)
	if err != nil {
		return err
	}
	if err := jsonUnmarshal(payload, into); err != nil {
		return fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}
	// The issuer is checked against the decoded form, so a caller passing a
	// struct without an `iss` field cannot skip the check by omission.
	var envelope struct {
		Issuer string `json:"iss"`
	}
	if err := jsonUnmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}
	for _, i := range issuers {
		if i != "" && envelope.Issuer == i {
			return nil
		}
	}
	return fmt.Errorf("%w: wrong issuer", ErrInvalidToken)
}

// verifiedPayload does the signature and header checks common to every token we
// verify, and returns the raw payload.
func verifiedPayload(set *keys.Set, raw, wantTyp string) ([]byte, error) {
	permitted := []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256, jose.EdDSA}

	tok, err := jose.ParseSigned(raw, permitted)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one signature", ErrInvalidToken)
	}
	h := tok.Signatures[0].Header

	if h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil ||
		h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return nil, fmt.Errorf("%w: token carries its own key material", ErrInvalidToken)
	}
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != wantTyp {
		return nil, fmt.Errorf("%w: typ is %q, want %q", ErrInvalidToken, typ, wantTyp)
	}
	if h.KeyID == "" {
		return nil, fmt.Errorf("%w: no kid", ErrInvalidToken)
	}
	key, ok := set.ByKID(h.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrInvalidToken, h.KeyID)
	}
	if string(key.Algorithm()) != h.Algorithm {
		return nil, fmt.Errorf("%w: kid %q is %s, token claims %s",
			ErrInvalidToken, h.KeyID, key.Algorithm(), h.Algorithm)
	}
	payload, err := tok.Verify(key.Signer().Public())
	if err != nil {
		return nil, fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
	}
	return payload, nil
}
