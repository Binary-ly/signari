package oid4vci

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)


// ParseX5CChain decodes an `x5c` header value into certificates.
//
// RFC 7515 §4.1.6: each entry is the **base64** (not base64url) DER of a
// certificate, leaf first. Getting that encoding wrong is the usual bug here,
// because every other value in a JOSE header is base64url.
func ParseX5CChain(raw any) ([]*x509.Certificate, error) {
	var entries []string
	switch v := raw.(type) {
	case []string:
		entries = v
	case []any:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("the x5c header contains a non-string entry")
			}
			entries = append(entries, s)
		}
	case json.RawMessage:
		if err := json.Unmarshal(v, &entries); err != nil {
			return nil, fmt.Errorf("the x5c header is not an array of strings: %w", err)
		}
	default:
		return nil, fmt.Errorf("the x5c header is not an array of strings")
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("the x5c header is empty, so it names no key")
	}
	if len(entries) > MaxX5CChainLength {
		return nil, fmt.Errorf("the x5c chain has %d certificates, over the limit of %d; "+
			"a chain that long is a parsing cost chosen by the caller",
			len(entries), MaxX5CChainLength)
	}

	out := make([]*x509.Certificate, 0, len(entries))
	for i, e := range entries {
		der, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d] is not base64 (RFC 7515 §4.1.6 uses "+
				"base64, not base64url, unlike every other JOSE value): %w", i, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d] is not a certificate: %w", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// MaxX5CChainLength bounds a chain before any parsing work is done.
const MaxX5CChainLength = 8

// ResolveX5CKey verifies a chain to a configured root and returns the leaf's key.
func ResolveX5CKey(chain []*x509.Certificate, roots *x509.CertPool,
	alg string, now time.Time) (*jose.JSONWebKey, error) {

	if roots == nil {
		return nil, fmt.Errorf("this issuer has no trusted x5c roots configured, so a " +
			"certificate chain cannot be checked; it is refused rather than accepted " +
			"on its own signature, which a self-signed certificate would satisfy")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("the x5c chain is empty")
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	// Verify checks the leaf's validity window and every signature up to a root.
	// KeyUsage is left ANY deliberately: a wallet attestation certificate is not
	// a TLS certificate, and demanding ExtKeyUsageClientAuth would refuse
	// conformant chains for a reason the specification does not state.
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("the x5c chain does not verify to a trusted root: %w", err)
	}

	return &jose.JSONWebKey{
		Key:          chain[0].PublicKey,
		Algorithm:    alg,
		Certificates: chain,
	}, nil
}
