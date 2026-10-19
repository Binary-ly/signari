package store

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The roots an OID4VCI key proof's `x5c` chain must verify to (0150).

// ErrInvalidProofRoot is a certificate that cannot serve as a proof root.
var ErrInvalidProofRoot = errors.New("not a usable root certificate")

// CredentialProofRoots returns an organisation's roots as a pool, or nil when
// it has registered none. Nil is what oid4vci.ResolveX5CKey reads as "no roots
// configured", which refuses every chain.
func CredentialProofRoots(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) (*x509.CertPool, error) {
	rows, err := q.Query(ctx,
		`SELECT certificate FROM core.credential_proof_roots WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("reading credential proof roots: %w", err)
	}
	defer rows.Close()
	var pool *x509.CertPool
	for rows.Next() {
		var der []byte
		if err := rows.Scan(&der); err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			// Refused at write, so a stored one that does not parse was put
			// there by hand. Failing the request rather than skipping it: a
			// shrunken trust set fails open for whoever that root vouched
			// against.
			return nil, fmt.Errorf("a registered credential proof root does not parse: %w", err)
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AddCert(cert)
	}
	return pool, rows.Err()
}

// CheckProofRoot refuses a certificate that cannot anchor a chain: one that
// does not parse, is not a CA, or has expired.
func CheckProofRoot(der []byte, now time.Time) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProofRoot, err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("%w: %s is not a CA certificate, so no chain can verify to it",
			ErrInvalidProofRoot, cert.Subject)
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: %s expired on %s", ErrInvalidProofRoot, cert.Subject,
			cert.NotAfter.Format(time.DateOnly))
	}
	return cert, nil
}

// SetCredentialProofRoot registers a root under a name, replacing one of the
// same name.
func SetCredentialProofRoot(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID, name string, der []byte) error {
	if _, err := CheckProofRoot(der, time.Now()); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO core.credential_proof_roots (org_id, name, certificate)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (org_id, name) DO UPDATE SET certificate = EXCLUDED.certificate`,
		orgID, name, der); err != nil {
		return fmt.Errorf("registering the credential proof root: %w", err)
	}
	return nil
}
