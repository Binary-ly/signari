package saml

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// certLifetime is deliberately long.
//
// This is not a TLS certificate. Nothing validates a chain, nothing checks
// revocation, and no browser is involved -- the service provider compares the
// certificate in the assertion against the copy it took from our metadata. Its
// expiry is therefore not a security boundary; it is a scheduled outage, and
// every SAML deployment in the world has been broken at least once by one.
//
// The key's own rotation schedule is the real control, and it already exists.
const certLifetime = 10 * 365 * 24 * time.Hour

// EnsureCertificate returns the stored certificate for a key, creating it once
// if there is none.
//
// The certificate is created ONCE and reused forever after. Regenerating it
// would change its fingerprint, and every service provider pinning that
// fingerprint would begin rejecting assertions -- which is the failure that
// looks like "SAML randomly stopped working for some users".
func EnsureCertificate(ctx context.Context, tx pgx.Tx, kid, issuer string, signer crypto.Signer) ([]byte, error) {
	var der []byte
	err := tx.QueryRow(ctx,
		`SELECT certificate FROM core.signing_keys WHERE kid = $1`, kid).Scan(&der)
	if err != nil {
		return nil, fmt.Errorf("reading the certificate for key %s: %w", kid, err)
	}
	if len(der) > 0 {
		return der, nil
	}

	der, notAfter, err := selfSign(issuer, signer)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)

	// Written back under the same transaction the caller holds. Two nodes racing
	// to create the first certificate would otherwise each generate one, and the
	// loser's assertions would be signed by a certificate no SP has.
	if _, err := tx.Exec(ctx, `
		UPDATE core.signing_keys
		SET certificate = $2, certificate_sha256 = $3, certificate_not_after = $4
		WHERE kid = $1 AND certificate IS NULL`,
		kid, der, hex.EncodeToString(sum[:]), notAfter); err != nil {
		return nil, fmt.Errorf("storing the certificate for key %s: %w", kid, err)
	}

	// Re-read: if another transaction won the race, theirs is the one every SP
	// will be given, so it must be the one we sign with.
	var stored []byte
	if err := tx.QueryRow(ctx,
		`SELECT certificate FROM core.signing_keys WHERE kid = $1`, kid).Scan(&stored); err != nil {
		return nil, err
	}
	return stored, nil
}

// selfSign builds the certificate.
//
// Self-signed, and that is correct rather than a shortcut: SAML trust is
// established by the service provider holding a copy of this exact certificate,
// not by a chain to a public root. A CA-issued certificate here would cost money
// and add an expiry cliff without changing what is actually verified.
func selfSign(issuer string, signer crypto.Signer) ([]byte, time.Time, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generating a serial number: %w", err)
	}

	// The subject is the issuer URL, which is what an operator sees in their SP's
	// configuration screen. A certificate labelled "signari" tells them nothing
	// when they run two of these.
	cn := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	if i := strings.IndexByte(cn, '/'); i > 0 {
		cn = cn[:i]
	}

	now := time.Now().UTC()
	notAfter := now.Add(certLifetime)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Signari"}},
		// Backdated by an hour so a service provider whose clock is behind ours
		// does not reject a certificate that is technically not yet valid.
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  notAfter,
		// Signing only. Not a TLS certificate, and marking it as one would invite
		// somebody to reuse it as one.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("creating the certificate: %w", err)
	}
	return der, notAfter, nil
}

// CertificateB64 renders a certificate for XML, which carries base64 of DER with
// no PEM header.
func CertificateB64(der []byte) string {
	return base64.StdEncoding.EncodeToString(der)
}

// SignatureMethod picks the XML signature algorithm for a key.
//
// RSA-SHA256 is what SAML deployments interoperate on. ECDSA is specified and
// is refused by a great deal of real service-provider software, so a deployment
// choosing an EC key for SAML would produce assertions that verify correctly and
// are rejected anyway -- which is a much worse failure to debug than being told
// up front.
func SignatureMethod(signer crypto.Signer) (string, error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", nil
	case *ecdsa.PublicKey:
		return "", fmt.Errorf("this instance's active key is ECDSA, which most SAML " +
			"service providers cannot verify. Rotate in an RS256 key before enabling " +
			"SAML: `signari keys rotate -alg RS256`")
	default:
		return "", fmt.Errorf("key type %T cannot sign SAML assertions", signer.Public())
	}
}
