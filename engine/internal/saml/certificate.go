package saml

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	dsig "github.com/russellhaering/goxmldsig"
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

	der, notAfter, err := selfSign(issuer, kid, signer)
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
func selfSign(issuer, kid string, signer crypto.Signer) ([]byte, time.Time, error) {
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
		// The key id as well, so each key's certificate has a name of its own.
		// Metadata publishes the active, next and passive keys together, and a
		// provider that trusts all three and looks the signer up by name took
		// whichever it had loaded last when the names were the same: xmlsec1
		// verified in one order and found no key in another.
		Subject: pkix.Name{CommonName: cn, Organization: []string{"Signari"},
			OrganizationalUnit: []string{"key " + kid}},
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

// The signature algorithms a service provider can be signed for, as
// core.saml_providers.signature_alg names them.
//
// RSA-SHA256 is the default because it is what SAML deployments interoperate
// on. ECDSA is specified and refused by a great deal of real service-provider
// software, so signing with it for a provider that cannot verify it produces
// assertions that are correct and rejected anyway. It is therefore chosen per
// provider, by whoever knows the far end, and never by which key happens to be
// active.
const (
	SignatureAlgRSASHA256   = "rsa-sha256"
	SignatureAlgECDSASHA256 = "ecdsa-sha256"
)

// SignatureMethod names the XML signature algorithm for a key: RSA-SHA256 for
// an RSA key, ECDSA-SHA256 for a P-256 one. It goes by the public half alone,
// so a key whose private half never leaves a KMS or HSM is named the same way.
func SignatureMethod(signer crypto.Signer) (string, error) {
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		return dsig.RSASHA256SignatureMethod, nil
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return "", fmt.Errorf("an ECDSA key on %s cannot sign SAML here; ecdsa-sha256 "+
				"is used with P-256 keys", pub.Curve.Params().Name)
		}
		return dsig.ECDSASHA256SignatureMethod, nil
	default:
		return "", fmt.Errorf("key type %T cannot sign SAML assertions", signer.Public())
	}
}
