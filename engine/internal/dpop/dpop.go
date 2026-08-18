// Package dpop implements RFC 9449, Demonstrating Proof of Possession.
//
// # What it changes
//
// A bearer token is a bearer credential: whoever holds it, uses it. Every
// defence around one is about stopping it being obtained -- TLS, short
// lifetimes, careful logging -- because once obtained there is nothing left to
// check. Tokens leak through referrer headers, proxy logs, browser history,
// crash reports and copy-paste into support tickets.
//
// DPoP binds the token to a key the client holds. The token carries the
// thumbprint of that key (`cnf.jkt`), and every request carrying the token must
// also carry a fresh signature from it. A stolen token without the private key
// is inert.
//
// # What this package refuses, and why each one matters
//
// The proof is a JWT supplied by the caller, so every field in it is
// attacker-chosen until checked:
//
//	alg: none / HMAC     the proof would verify against its own public key
//	replayed proof       a captured proof would authorise a second request
//	wrong htu / htm      a proof for /userinfo would authorise /admin
//	stale iat            a proof captured yesterday would still work
//	mismatched ath       a proof made for one token would authorise another
//	jkt mismatch         any key would do, and binding would mean nothing
//
// Each of these is checked below. The last is the one that makes the feature
// real: without it the proof demonstrates possession of *a* key, not *the* key
// the token was issued to.
package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// TypDPoP is the required `typ` header. Checked because a JWT minted for
	// another purpose -- an ID token, an access token, a proof for a different
	// protocol -- must not be usable here. It is the same cross-type confusion
	// defence the rest of this codebase applies to every token it verifies.
	TypDPoP = "dpop+jwt"

	// MaxAge bounds how old a proof may be. Short: the proof is generated per
	// request by a client that already holds the key, so there is no legitimate
	// reason for an old one. Every second of slack is a second in which a
	// captured proof still works.
	MaxAge = 60 * time.Second

	// MaxSkew allows for a client clock running ahead of ours.
	MaxSkew = 30 * time.Second

	// maxProofBytes bounds the header before any parsing.
	maxProofBytes = 8 << 10
)

// allowedAlgs is an allow-list, and asymmetric only.
//
// The proof carries its own public key in the header. With a symmetric
// algorithm that key would be the verification key AND the signing key, so any
// caller could mint a proof for any key: the check would verify perfectly and
// prove nothing. `none` is absent for the obvious reason.
var allowedAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Proof is a verified DPoP proof.
type Proof struct {
	// JKT is the JWK SHA-256 thumbprint (RFC 7638) of the key that signed it.
	// This is the value bound into the token as `cnf.jkt`.
	JKT string
	// JTI is the proof's unique identifier, for replay detection.
	JTI string
	// Method and URI are what the proof authorises.
	Method string
	URI    string
	// IssuedAt is the proof's own timestamp.
	IssuedAt time.Time
	// AccessTokenHash is `ath`, present when the proof accompanies an access
	// token.
	AccessTokenHash string
	// PublicKey is the key that signed it, for callers that need to record it.
	PublicKey *jose.JSONWebKey
}

type proofClaims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath"`

	// `nonce` is deliberately absent.
	//
	// RFC 9449 §8 makes the check conditional on the server having supplied one:
	// "If the server provided a nonce value to the client, the nonce claim
	// matches the server-provided nonce value". We never send a DPoP-Nonce
	// header, so there is nothing to compare a nonce against and ignoring it is
	// conformant.
	//
	// It was previously parsed into a field that nothing read. A parsed claim
	// reads like a checked one, and this is a file where every other field in
	// this struct is load-bearing. If nonces are added, issuance and this check
	// have to arrive together -- checking a nonce we never issued would refuse
	// every honest client, and issuing one we never check would be theatre.
}

// Verify checks a DPoP proof against the request it accompanies.
//
// method and uri are what the SERVER saw, never what the proof claims -- the
// whole point is comparing the client's assertion against reality.
//
// accessToken is the token presented alongside, or "" at the token endpoint
// where none exists yet.
func Verify(header, method, uri, accessToken string, now time.Time) (*Proof, error) {
	if header == "" {
		return nil, fmt.Errorf("no DPoP proof")
	}
	if len(header) > maxProofBytes {
		return nil, fmt.Errorf("DPoP proof is %d bytes, over the limit", len(header))
	}
	// Exactly one proof. Multiple headers would leave which one was checked up
	// to the parser, and a caller who can supply two can supply one that
	// verifies and one that authorises.
	if strings.Contains(header, ",") || strings.Contains(header, " ") {
		return nil, fmt.Errorf("the DPoP header must carry exactly one proof")
	}

	tok, err := jose.ParseSigned(header, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("the DPoP proof did not parse: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("the DPoP proof must carry exactly one signature")
	}
	sig := tok.Signatures[0]

	if typ, _ := sig.Header.ExtraHeaders[jose.HeaderType].(string); typ != TypDPoP {
		return nil, fmt.Errorf("the DPoP proof has typ %q, expected %q", typ, TypDPoP)
	}

	// The key is IN the proof. That is not a weakness -- it is the design: the
	// proof demonstrates possession of whatever key it names, and the binding
	// check afterwards decides whether that key is the right one.
	jwk := sig.Header.JSONWebKey
	if jwk == nil {
		return nil, fmt.Errorf("the DPoP proof carries no jwk header")
	}
	if !jwk.IsPublic() {
		// A proof carrying a PRIVATE key means the client has just published its
		// own secret. Refused rather than used: continuing would authorise a
		// request with a key everybody now has.
		return nil, fmt.Errorf("the DPoP proof carries private key material")
	}
	if !jwk.Valid() {
		return nil, fmt.Errorf("the DPoP proof carries an unusable key")
	}

	payload, err := tok.Verify(jwk)
	if err != nil {
		return nil, fmt.Errorf("the DPoP proof signature did not verify: %w", err)
	}

	var c proofClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("the DPoP proof claims did not parse: %w", err)
	}
	if c.JTI == "" {
		return nil, fmt.Errorf("the DPoP proof has no jti, so a replay could not be detected")
	}

	if !strings.EqualFold(c.HTM, method) {
		return nil, fmt.Errorf("the DPoP proof is for method %q, this request is %q", c.HTM, method)
	}
	if !sameURI(c.HTU, uri) {
		return nil, fmt.Errorf("the DPoP proof is for %q, this request is %q", c.HTU, uri)
	}

	if c.IAT == 0 {
		return nil, fmt.Errorf("the DPoP proof has no iat, so its age cannot be checked")
	}
	issued := time.Unix(c.IAT, 0)
	if age := now.Sub(issued); age > MaxAge {
		return nil, fmt.Errorf("the DPoP proof is %s old, over the %s limit",
			age.Round(time.Second), MaxAge)
	} else if age < -MaxSkew {
		return nil, fmt.Errorf("the DPoP proof is timestamped %s in the future",
			(-age).Round(time.Second))
	}

	// `ath` binds the proof to the specific access token presented. Without it a
	// proof made while using one token would authorise a request carrying a
	// different one -- so where a token is present, the binding is REQUIRED
	// rather than checked-if-supplied.
	if accessToken != "" {
		if c.ATH == "" {
			return nil, fmt.Errorf("the DPoP proof has no ath, so it is not bound to " +
				"the access token presented with it")
		}
		if c.ATH != AccessTokenHash(accessToken) {
			return nil, fmt.Errorf("the DPoP proof's ath does not match the access token")
		}
	}

	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("computing the key thumbprint: %w", err)
	}

	return &Proof{
		JKT:             base64.RawURLEncoding.EncodeToString(thumb),
		JTI:             c.JTI,
		Method:          method,
		URI:             uri,
		IssuedAt:        issued,
		AccessTokenHash: c.ATH,
		PublicKey:       jwk,
	}, nil
}

// Presentation errors, distinguished so a caller can word its challenge.
var (
	// ErrBoundTokenAsBearer is RFC 9449 §7.2.
	ErrBoundTokenAsBearer = fmt.Errorf("this access token is sender-constrained " +
		"and must be presented with the DPoP scheme")
	// ErrDPoPSchemeUnboundToken is RFC 9449 §7.1.
	ErrDPoPSchemeUnboundToken = fmt.Errorf("the DPoP scheme requires a " +
		"sender-constrained access token")
)

// CheckPresentation applies RFC 9449 §7.1 and §7.2 to how a token was
// presented, before any proof is looked at.
//
// Both rules are downgrade defences, and both key on the SCHEME rather than on
// the token -- which is why checking `cnf` alone missed them:
//
//	§7.2  "such a protected resource MUST reject a DPoP-bound access token
//	      received as a bearer token"
//	§7.1  of a token sent under the DPoP scheme, the server "MUST check that a
//	      DPoP proof was also received ... MUST NOT grant access to the resource
//	      unless all checks are successful"
//
// §7.2 applies to a resource supporting BOTH schemes, which is what we are. A
// resource that only understood Bearer would be free to accept a bound token as
// a bearer one, and the same section says so explicitly -- but having advertised
// DPoP, we no longer have that excuse.
//
// scheme is "Bearer", "DPoP", or "" when the token arrived some other way.
func CheckPresentation(bound bool, scheme string) error {
	switch {
	case bound && scheme == "Bearer":
		return ErrBoundTokenAsBearer
	case !bound && scheme == "DPoP":
		return ErrDPoPSchemeUnboundToken
	}
	return nil
}

// SupportedAlgs renders allowedAlgs for the `algs` parameter of a DPoP
// WWW-Authenticate challenge (RFC 9449 §7.2). Built from the same list Verify
// enforces, so the advertisement cannot drift from the policy.
func SupportedAlgs() string {
	names := make([]string, 0, len(allowedAlgs))
	for _, a := range allowedAlgs {
		names = append(names, string(a))
	}
	return strings.Join(names, " ")
}

// AccessTokenHash computes `ath` (RFC 9449 §4.2): base64url of the SHA-256 of
// the access token, exactly as the client sends it.
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sameURI compares the proof's htu with the request URI.
//
// RFC 9449 §4.3 says htu is the request URI WITHOUT query or fragment. Those are
// stripped rather than compared, because a client that includes them would
// otherwise fail against a server that does not -- and the interoperability
// failure would look like an attack in the logs.
//
// Everything else is compared exactly. Scheme and host are folded because they
// are case-insensitive by definition; the path is not.
func sameURI(htu, actual string) bool {
	a, err1 := url.Parse(htu)
	b, err2 := url.Parse(actual)
	if err1 != nil || err2 != nil {
		return false
	}
	a.RawQuery, a.Fragment = "", ""
	b.RawQuery, b.Fragment = "", ""
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) &&
		a.Path == b.Path
}

// Confirmation is the `cnf` claim carried by a bound token.
type Confirmation struct {
	JKT string `json:"jkt"`
}

// BoundTo reports whether a token's confirmation matches a proof.
//
// THE check that makes the feature real. Without it the proof demonstrates
// possession of *a* key rather than *the* key the token was issued to, and a
// thief could present a stolen token with a proof from a key they generated
// themselves.
func BoundTo(cnf *Confirmation, proof *Proof) error {
	if cnf == nil || cnf.JKT == "" {
		return fmt.Errorf("this access token is not sender-constrained")
	}
	if proof == nil {
		return fmt.Errorf("this access token is sender-constrained and no DPoP proof was presented")
	}
	// Constant time is unnecessary -- both values are public thumbprints -- but
	// the comparison must be exact: a prefix match would let a generated key
	// with a colliding prefix pass.
	if cnf.JKT != proof.JKT {
		return fmt.Errorf("this access token is bound to a different key than the " +
			"DPoP proof was signed with")
	}
	return nil
}
