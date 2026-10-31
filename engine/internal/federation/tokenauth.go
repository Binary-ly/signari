package federation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the x5t header is defined over SHA-1; it names a certificate and protects nothing
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// How this engine proves itself at the provider's token endpoint.
const (
	AuthSecretPost    = "client_secret_post"
	AuthSecretBasic   = "client_secret_basic"
	AuthPrivateKeyJWT = "private_key_jwt"
	AuthTLS           = "tls_client_auth"

	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// assertionLifetime is short because it is made for one request.
	assertionLifetime = time.Minute
)

// TokenAuth is how a provider is told who is asking. Key and Certificate are
// for the two methods that use them.
type TokenAuth struct {
	Method      string
	Key         crypto.Signer
	Certificate *x509.Certificate
}

// ParseClientKey reads a private key, and a certificate when there is one, and
// refuses a pair that does not belong together: it would fail at the provider, on
// somebody's first sign-in, as a refusal saying nothing about why.
func ParseClientKey(keyPEM, certPEM []byte) (crypto.Signer, *x509.Certificate, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, errors.New("the client key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if rsaKey, rerr := x509.ParsePKCS1PrivateKey(block.Bytes); rerr == nil {
			parsed = rsaKey
		} else if ecKey, eerr := x509.ParseECPrivateKey(block.Bytes); eerr == nil {
			parsed = ecKey
		} else {
			return nil, nil, fmt.Errorf("the client key does not parse: %w", err)
		}
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("the client key cannot sign")
	}
	if _, err := assertionAlgorithm(key); err != nil {
		return nil, nil, err
	}
	if len(certPEM) == 0 {
		return key, nil, nil
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, errors.New("the client certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("the client certificate does not parse: %w", err)
	}
	type publicKey interface{ Equal(crypto.PublicKey) bool }
	if pub, ok := key.Public().(publicKey); !ok || !pub.Equal(cert.PublicKey) {
		return nil, nil, errors.New("the client certificate is not for this key")
	}
	return key, cert, nil
}

func assertionAlgorithm(key crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return jose.ES256, nil
		}
		return "", fmt.Errorf("the client key is on %s; P-256 is the curve a provider will accept", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	}
	return "", errors.New("the client key is of a kind no assertion can be signed with")
}

// clientAssertion is the signed statement private_key_jwt sends: this client,
// about itself, to this token endpoint and for this request alone. A certificate
// is named in the header because a provider that holds certificates, and not raw
// keys, finds the one to check by its thumbprint.
func (c Config) clientAssertion(now time.Time) (string, error) {
	alg, err := assertionAlgorithm(c.TokenAuth.Key)
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if cert := c.TokenAuth.Certificate; cert != nil {
		s256 := sha256.Sum256(cert.Raw)
		opts = opts.WithHeader("x5t#S256", base64.RawURLEncoding.EncodeToString(s256[:]))
		// SHA-1 panics under fips140=only, and a provider that can read the
		// stronger thumbprint needs nothing more.
		if !fips140.Enforced() {
			s1 := sha1.Sum(cert.Raw) //nolint:gosec // see the import
			opts = opts.WithHeader("x5t", base64.RawURLEncoding.EncodeToString(s1[:]))
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: c.TokenAuth.Key}, opts)
	if err != nil {
		return "", err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{"iss": c.ClientID, "sub": c.ClientID, "aud": c.tokenURL(),
		"jti": hex.EncodeToString(id[:]), "iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix()})
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

// authenticate puts this client's proof on a token request, in the form or, for
// basic, on the request once there is one.
func (c Config) authenticate(form url.Values, now time.Time) (func(*http.Request), error) {
	switch c.TokenAuth.Method {
	case "", AuthSecretPost:
		if c.ClientSecret != "" {
			form.Set("client_secret", c.ClientSecret)
		}
	case AuthSecretBasic:
		return func(r *http.Request) {
			// RFC 6749 §2.3.1 has both parts form-encoded before they are joined.
			r.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
		}, nil
	case AuthPrivateKeyJWT:
		assertion, err := c.clientAssertion(now)
		if err != nil {
			return nil, fmt.Errorf("signing the client assertion: %w", err)
		}
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	case AuthTLS:
		// The proof is the connection's: tokenClient.
	default:
		return nil, fmt.Errorf("unknown token authentication method %q", c.TokenAuth.Method)
	}
	return func(*http.Request) {}, nil
}

// tokenClient is hc presenting this client's certificate when the method asks. A
// clone, so the certificate goes to the token endpoint alone, and on the same
// guarded dialer.
func (c Config) tokenClient(hc *http.Client) (*http.Client, error) {
	if c.TokenAuth.Method != AuthTLS {
		return hc, nil
	}
	transport, ok := hc.Transport.(*http.Transport)
	if !ok || c.TokenAuth.Key == nil || c.TokenAuth.Certificate == nil {
		return nil, errors.New("tls_client_auth needs a client key and certificate")
	}
	clone := transport.Clone()
	if clone.TLSClientConfig == nil {
		clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	clone.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{c.TokenAuth.Certificate.Raw},
		PrivateKey: c.TokenAuth.Key, Leaf: c.TokenAuth.Certificate}}
	out := *hc
	out.Transport = clone
	return &out, nil
}
