package oid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Prefix is how a wallet is told to identify this verifier, section 5.9.3.
type Prefix string

// The prefixes this verifier can be known by. Both x509 ones sign the request
// with the key of a certificate the wallet validates; redirect_uri cannot sign
// at all (specs/oid4vp.txt:615), and is for a wallet that already trusts the
// address it posts to.
const (
	PrefixX509SANDNS  Prefix = "x509_san_dns"
	PrefixX509Hash    Prefix = "x509_hash"
	PrefixRedirectURI Prefix = "redirect_uri"
)

// Signed reports whether requests under p are signed request objects.
func (p Prefix) Signed() bool { return p == PrefixX509SANDNS || p == PrefixX509Hash }

// ParsePrefix reads one of the three.
func ParsePrefix(s string) (Prefix, error) {
	switch p := Prefix(s); p {
	case PrefixX509SANDNS, PrefixX509Hash, PrefixRedirectURI:
		return p, nil
	}
	return "", fmt.Errorf("client identifier prefix %q: want x509_san_dns, x509_hash or redirect_uri", s)
}

// Response modes. direct_post sends the answer to the response URI in clear
// (section 8.2); direct_post.jwt encrypts it to a key the request names
// (section 8.3.1).
const (
	ModeDirectPost    = "direct_post"
	ModeDirectPostJWT = "direct_post.jwt"
)

// RequestLifetime is how long a signed request object is good for.
const RequestLifetime = 5 * time.Minute

// staticAudience is a request object's aud when the wallet's metadata is not
// discovered (specs/oid4vp.txt:570).
const staticAudience = "https://self-issued.me/v2"

// ClientID is the whole client identifier, prefix and all, for a verifier whose
// responses arrive at responseURI. leaf is the certificate a signed request
// carries, and nil for redirect_uri.
//
//   - x509_san_dns: the response URI's host, which "MUST be a DNS name and match
//     a dNSName Subject Alternative Name" of the leaf, and which the wallet holds
//     the response URI's host to (specs/oid4vp.txt:670).
//   - x509_hash: "the base64url-encoded value of the SHA-256 hash of the
//     DER-encoded X.509 certificate" (:672).
//   - redirect_uri: the response URI itself (:615, with :1361's note that the
//     response URI stands in for the redirect URI under direct_post).
func ClientID(p Prefix, responseURI string, leaf *x509.Certificate) (string, error) {
	u, err := url.Parse(responseURI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("the response URI %q is not an https URL", responseURI)
	}
	switch p {
	case PrefixX509SANDNS:
		if leaf == nil {
			return "", fmt.Errorf("x509_san_dns needs a certificate")
		}
		host := u.Hostname()
		if !slices.Contains(leaf.DNSNames, host) {
			return "", fmt.Errorf("the certificate names %v and not %s, the host the wallet posts to",
				leaf.DNSNames, host)
		}
		return string(p) + ":" + host, nil
	case PrefixX509Hash:
		if leaf == nil {
			return "", fmt.Errorf("x509_hash needs a certificate")
		}
		sum := sha256.Sum256(leaf.Raw)
		return string(p) + ":" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case PrefixRedirectURI:
		return string(p) + ":" + responseURI, nil
	}
	return "", fmt.Errorf("client identifier prefix %q", p)
}

// Request is one authorization request to a wallet.
type Request struct {
	ClientID, ResponseURI, ResponseMode string
	// Nonce binds the presentation to this request (specs/oid4vp.txt:379), and
	// State finds the request again when the answer arrives.
	Nonce, State string
	// WalletNonce is the wallet's own, when it fetched the request by POST, and
	// is echoed in the request object (:692-694).
	WalletNonce string
	Ask         Ask
	// EncryptTo is the public key a direct_post.jwt answer is encrypted to: one
	// for this request alone, so a key never decrypts two people's answers.
	EncryptTo *jose.JSONWebKey
}

// Parameters are the authorization request's parameters: the claims of a signed
// request object, or the query of an unsigned one.
func (r Request) Parameters(now time.Time) map[string]any {
	p := map[string]any{
		"client_id":       r.ClientID,
		"response_type":   "vp_token",
		"response_mode":   r.ResponseMode,
		"response_uri":    r.ResponseURI,
		"nonce":           r.Nonce,
		"state":           r.State,
		"dcql_query":      r.Ask.Query(),
		"client_metadata": r.metadata(),
	}
	if r.WalletNonce != "" {
		p["wallet_nonce"] = r.WalletNonce
	}
	if !now.IsZero() {
		p["aud"] = staticAudience
		p["iat"] = now.Unix()
		p["exp"] = now.Add(RequestLifetime).Unix()
	}
	return p
}

// metadata is client_metadata (specs/oid4vp.txt:310-322): the algorithms this
// verifier checks, and for an encrypted answer the key to encrypt it to. The enc
// is A128GCM, the default, so encrypted_response_enc_values_supported is left
// out, as :316 says it SHOULD be.
func (r Request) metadata() map[string]any {
	algs := AlgorithmNames()
	m := map[string]any{"vp_formats_supported": map[string]any{
		Format: map[string]any{"sd-jwt_alg_values": algs, "kb-jwt_alg_values": algs},
	}}
	if r.EncryptTo != nil {
		m["jwks"] = map[string]any{"keys": []any{r.EncryptTo}}
	}
	return m
}

// URL is the request as a wallet is sent it: by reference, as a client_id and
// a request_uri, when it is signed (:243-247, :500-505), and otherwise with
// every parameter in the query, as :615-629 shows for redirect_uri.
func (r Request) URL(wallet, requestURI string, post bool) (string, error) {
	u, err := url.Parse(wallet)
	if err != nil || u.Scheme == "" {
		return "", fmt.Errorf("the wallet URL %q is not a URL", wallet)
	}
	q := u.Query()
	q.Set("client_id", r.ClientID)
	if requestURI != "" {
		q.Set("request_uri", requestURI)
		if post {
			q.Set("request_uri_method", "post")
			// With nothing else to say what this verifier can do, the wallet is
			// told here what to say in its POST (:328-329).
			b, err := json.Marshal(r.metadata())
			if err != nil {
				return "", err
			}
			q.Set("client_metadata", string(b))
		}
	} else {
		for k, v := range r.Parameters(time.Time{}) {
			switch t := v.(type) {
			case string:
				q.Set(k, t)
			default:
				// "parameters containing objects are transferred as
				// JSON-serialized strings" (:308).
				b, err := json.Marshal(t)
				if err != nil {
					return "", err
				}
				q.Set(k, string(b))
			}
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TypRequest is the request object's typ, which a wallet "MUST NOT process"
// without (specs/oid4vp.txt:277).
const TypRequest = "oauth-authz-req+jwt"

// Sign makes the signed request object: the parameters signed with key, whose
// certificate chain, leaf first, goes in x5c (:670, :672).
func Sign(params map[string]any, key crypto.Signer, chain []*x509.Certificate) (string, error) {
	alg, err := Algorithm(key.Public())
	if err != nil {
		return "", err
	}
	if len(chain) == 0 {
		return "", fmt.Errorf("a signed request carries its certificate chain, and there is none")
	}
	if !samePublic(chain[0].PublicKey, key.Public()) {
		return "", fmt.Errorf("the certificate is not for the request-signing key")
	}
	x5c := make([]string, 0, len(chain))
	for _, c := range chain {
		// RFC 7515's x5c is base64 of the DER, not base64url.
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	opts := (&jose.SignerOptions{}).WithType(TypRequest).WithHeader("x5c", x5c)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// Algorithm is the JWS algorithm for a public key: ES256, ES384 or ES512 by
// curve, EdDSA, or PS256 for RSA.
func Algorithm(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
		return "", fmt.Errorf("an ECDSA key on %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	case *rsa.PublicKey:
		return jose.PS256, nil
	}
	return "", fmt.Errorf("a %T key cannot sign a request", pub)
}

func samePublic(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// Algorithms are the signature algorithms a credential and its key binding may
// use. Asymmetric only: with a MAC the key that checks a signature would be the
// key that makes one, and "none" is refused by RFC 9901 itself
// (specs/rfc9901.txt:1663-1665, 1849-1852).
func Algorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.EdDSA,
	}
}

// AlgorithmNames are Algorithms as the metadata spells them.
func AlgorithmNames() []string {
	var out []string
	for _, a := range Algorithms() {
		out = append(out, string(a))
	}
	return out
}

// ParseChain reads a PEM certificate chain, leaf first.
func ParseChain(pemText string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate in the chain")
	}
	return out, nil
}
