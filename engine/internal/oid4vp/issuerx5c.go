package oid4vp

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// An issuer believed by certificate: its credentials carry their signing key's X.509
// chain in x5c, and the chain has to lead to a root the operator holds for that issuer.
// This is the second mechanism SD-JWT VC section 2.5 defines (specs/sdjwtvc.txt:1091-1098):
// "the recipient uses the public key from the end-entity certificate ... and validates the
// X.509 certificate chain accordingly. In this case, the Issuer of the Verifiable Digital
// Credential is the subject of the end-entity certificate."
//
// The issuer is still found by its iss, and only an issuer the operator named this way is
// checked this way, so for any iss the mechanism is the operator's choice and never the
// credential's (:2141-2145): a pinned issuer's credential that carries an x5c is checked
// with the pinned keys and nothing else.

// ParseRoots reads the PEM root certificates an issuer's chain must lead to. Each has to
// be a certificate authority's: a leaf named as a root would vouch for nothing but itself.
func ParseRoots(pemText string) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the roots hold a %q block, and only certificates belong there", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a root does not parse: %w", err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("the certificate for %q is not a certificate authority's, so it cannot be a root",
				cert.Subject.String())
		}
		roots = append(roots, cert)
	}
	// A block cut short is skipped by the decoder, which would hold one root fewer than the
	// file names without saying so.
	if len(bytes.TrimSpace(rest)) > 0 || strings.Count(pemText, "-----BEGIN") != len(roots) {
		return nil, errors.New("the roots carry text that is not a whole PEM certificate")
	}
	if len(roots) == 0 {
		return nil, errors.New("no root certificate was given")
	}
	return roots, nil
}

// RootPool is ParseRoots as a pool to verify with.
func RootPool(pemText string) (*x509.CertPool, error) {
	roots, err := ParseRoots(pemText)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	return pool, nil
}

// CanBeNamedByCertificate says whether iss is something a certificate can name: an
// absolute URI, carried as a uniformResourceIdentifier subject alternative name.
func CanBeNamedByCertificate(iss string) error {
	u, err := url.Parse(iss)
	if err != nil || u.Scheme == "" || (u.Host == "" && u.Opaque == "") {
		return fmt.Errorf("the issuer %q is not an absolute URI, so no certificate can name it", iss)
	}
	return nil
}

// issuerKeysFromChain validates the credential's x5c to roots and returns the leaf's key,
// with the chain it was validated along.
func issuerKeysFromChain(h jose.Header, iss string, roots *x509.CertPool, now time.Time) (*jose.JSONWebKeySet,
	[]*x509.Certificate, error) {
	// The chain is read from the protected header, where SD-JWT VC looks for it
	// (specs/sdjwtvc.txt:1093-1094); in a compact JWS there is no other.
	chains, err := h.Certificates(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		// SD-JWT VC names no extended key usage for an issuer, and with none given the
		// library would demand serverAuth, which an issuer's certificate need not carry.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if errors.Is(err, jose.ErrMissingX5cHeader) {
		return nil, nil, fmt.Errorf("the credential from %s carries no x5c, and that issuer is believed by its certificate", iss)
	}
	if err != nil {
		// "consider the certificate or certificate chain to be invalid if any validation
		// failure occurs" (specs/rfc7515.txt:629-632).
		return nil, nil, fmt.Errorf("the credential's certificate chain does not lead to a root held for %s: %w", iss, err)
	}
	chain := chains[0]
	leaf := chain[0]
	if !asymmetric(leaf.PublicKey) {
		return nil, nil, fmt.Errorf("the credential's certificate holds no public signing key")
	}
	// A key usage that leaves out digitalSignature is a key not for signing anything but
	// certificates and CRLs (specs/rfc5280.txt:1652-1656).
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, fmt.Errorf("the credential's certificate is not for digital signatures")
	}
	if !certificateNames(leaf, iss) {
		return nil, nil, fmt.Errorf("the credential's certificate does not name its issuer %s", iss)
	}
	// The key keeps the credential's kid, if it named one, so a status list that names the
	// same key by the same kid finds it (specs/token-status-list.txt:949-951).
	kid := h.KeyID
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: leaf.PublicKey, KeyID: kid, Use: "sig"}}}, chain, nil
}

// certificateNames says whether leaf names iss. The issuer is the certificate's subject
// (specs/sdjwtvc.txt:1096-1098), and an identity is bound to a subject by a subject
// alternative name (specs/rfc5280.txt:1955-1956, :1970-1972): a uniformResourceIdentifier
// that is iss exactly, or, for an iss that is a host and nothing more, a dNSName that is
// that host. A host with a path is not named by the host alone, since one host may keep
// many issuers, each at its own path. A wildcard names nobody: an issuer is one party.
func certificateNames(leaf *x509.Certificate, iss string) bool {
	for _, u := range leaf.URIs {
		if u.String() == iss {
			return true
		}
	}
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() != "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(iss, "#") {
		return false
	}
	for _, name := range leaf.DNSNames {
		if !strings.Contains(name, "*") && strings.EqualFold(name, u.Hostname()) {
			return true
		}
	}
	return false
}

// CRLMedia is the type a CRL is served as (specs/rfc5280.txt:2558-2560).
const CRLMedia = "application/pkix-crl"

// checkChainRevocation is RFC 5280's "the certificate is not revoked"
// (specs/rfc5280.txt:4454-4456) for each certificate of the chain below its root, which
// the operator holds and answers for. A certificate that names CRLs over HTTP is checked
// against one, fetched for each presentation and kept for none (ADR-007: a kept "not
// revoked" outlives the revocation). One that names none leaves its revocation to the
// operator, out of band, by removing the issuer or the root. Every failure to decide
// refuses.
func checkChainRevocation(chain []*x509.Certificate, fetch Fetcher, now time.Time) error {
	for i := 0; i+1 < len(chain); i++ {
		if err := checkRevocation(chain[i], chain[i+1], fetch, now); err != nil {
			return err
		}
	}
	return nil
}

func checkRevocation(cert, issuer *x509.Certificate, fetch Fetcher, now time.Time) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil
	}
	if fetch == nil {
		return fmt.Errorf("the certificate for %q names a CRL and this verifier has no way to read it", cert.Subject)
	}
	var reasons []string
	for _, where := range cert.CRLDistributionPoints {
		u, err := url.Parse(where)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			reasons = append(reasons, fmt.Sprintf("%s is not an HTTP address", where))
			continue
		}
		revoked, err := readCRL(where, cert, issuer, fetch, now)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		if revoked {
			return fmt.Errorf("the certificate for %q was revoked by %q", cert.Subject, issuer.Subject)
		}
		return nil
	}
	return fmt.Errorf("whether the certificate for %q is revoked could not be told: %s", cert.Subject,
		strings.Join(reasons, "; "))
}

// readCRL fetches the CRL at where and says whether it lists cert. Only a complete CRL
// from cert's own issuer is read: an indirect CRL, a delta, or one scoped by an issuing
// distribution point carries a critical extension this does not process, and such a CRL
// "MUST NOT" be used (specs/rfc5280.txt:3323-3326, :3822-3825).
func readCRL(where string, cert, issuer *x509.Certificate, fetch Fetcher, now time.Time) (bool, error) {
	body, _, err := fetch(where, CRLMedia)
	if err != nil {
		return false, fmt.Errorf("the CRL at %s could not be read: %w", where, err)
	}
	// "the URI MUST point to a single DER encoded CRL" (specs/rfc5280.txt:2557-2558).
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return false, fmt.Errorf("the CRL at %s does not parse: %w", where, err)
	}
	// "verify that the CRL issuer matches the certificate issuer" (:5165-5166), and signed
	// by it.
	if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) {
		return false, fmt.Errorf("the CRL at %s is not from the certificate's issuer", where)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return false, fmt.Errorf("the CRL at %s is not signed by the certificate's issuer: %w", where, err)
	}
	for _, ext := range crl.Extensions {
		if ext.Critical {
			return false, fmt.Errorf("the CRL at %s carries a critical extension %v that is not read here", where, ext.Id)
		}
	}
	// "Conforming CRL issuers MUST include the nextUpdate field" (:3272), and the current
	// time has to be "before the next update value in the new CRL" (:5135-5136).
	if crl.ThisUpdate.After(now.Add(clockSkew)) {
		return false, fmt.Errorf("the CRL at %s is dated %s, in the future", where, crl.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if crl.NextUpdate.IsZero() || !now.Before(crl.NextUpdate.Add(clockSkew)) {
		return false, fmt.Errorf("the CRL at %s is not current", where)
	}
	listed := false
	for _, entry := range crl.RevokedCertificateEntries {
		for _, ext := range entry.Extensions {
			if ext.Critical {
				return false, fmt.Errorf("the CRL at %s carries a critical entry extension %v that is not read here", where, ext.Id)
			}
		}
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			listed = true
		}
	}
	return listed, nil
}
