package store

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
)

// A deployment's own keys toward one upstream SAML identity provider (8.04).

const sealContextSAMLSourceKey = "saml_source_key"

// ErrSAMLSourceKey is a change to an upstream's keys or what is asked of them
// that cannot be made, in words an operator can act on.
var ErrSAMLSourceKey = errors.New("that cannot be done to this upstream")

// SAMLSourceKey is one such key, without the part that matters.
type SAMLSourceKey struct {
	ID          string     `json:"id"`
	Purpose     string     `json:"purpose"`
	Certificate string     `json:"certificate"` // PEM
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at"`
}

// samlSourceKeysDB is a connection or a transaction.
type samlSourceKeysDB interface {
	claimReader
	Execer
}

// AddSAMLSourceKey makes a key for the upstream named by slug. An older key of
// the same purpose stays until it is retired: the upstream has to be given the
// new certificate first, and until it has, it goes on using the old one.
func AddSAMLSourceKey(ctx context.Context, q samlSourceKeysDB, root *keys.RootKey, orgID, slug, purpose string) (SAMLSourceKey, error) {
	if root == nil {
		return SAMLSourceKey{}, errors.New("a key is sealed under the root key, and none is configured")
	}
	var providerID, issuer string
	err := q.QueryRow(ctx, `
		SELECT p.id::text, i.issuer
		  FROM core.identity_providers p
		  JOIN core.saml_sources x ON x.provider_id = p.id
		  JOIN core.organizations o ON o.id = p.org_id
		  JOIN core.instances i ON i.id = o.instance_id
		 WHERE p.org_id = $1::uuid AND p.slug = $2`, orgID, slug).Scan(&providerID, &issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return SAMLSourceKey{}, ErrProviderUnknown
	}
	if err != nil {
		return SAMLSourceKey{}, err
	}
	pkcs8, certPEM, err := saml.NewSPKey(issuer, purpose)
	if err != nil {
		return SAMLSourceKey{}, fmt.Errorf("%w: %w", ErrSAMLSourceKey, err)
	}
	sealed, err := root.Seal(pkcs8, sealContextSAMLSourceKey)
	if err != nil {
		return SAMLSourceKey{}, fmt.Errorf("sealing the key: %w", err)
	}
	k := SAMLSourceKey{Purpose: purpose, Certificate: certPEM}
	err = q.QueryRow(ctx, `
		INSERT INTO core.saml_source_keys (provider_id, org_id, purpose, key_sealed, certificate)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5) RETURNING id::text, created_at`,
		providerID, orgID, purpose, sealed, certPEM).Scan(&k.ID, &k.CreatedAt)
	return k, err
}

// SAMLSourceKeys lists an upstream's keys, newest first.
func SAMLSourceKeys(ctx context.Context, q claimReader, orgID, slug string) ([]SAMLSourceKey, error) {
	rows, err := q.Query(ctx, `
		SELECT k.id::text, k.purpose, k.certificate, k.created_at, k.retired_at
		  FROM core.saml_source_keys k
		  JOIN core.identity_providers p ON p.id = k.provider_id
		 WHERE p.org_id = $1::uuid AND p.slug = $2
		 ORDER BY k.created_at DESC, k.id`, orgID, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SAMLSourceKey{}
	for rows.Next() {
		var k SAMLSourceKey
		if err := rows.Scan(&k.ID, &k.Purpose, &k.Certificate, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RetireSAMLSourceKey takes a key out of use. Refused for the last key of a
// purpose the upstream is held to: every sign-in through it would then fail, and
// an operator retiring a key does not mean that.
func RetireSAMLSourceKey(ctx context.Context, q samlSourceKeysDB, orgID, slug, id string) error {
	var purpose string
	var needed bool
	err := q.QueryRow(ctx, `
		SELECT k.purpose,
		       CASE k.purpose WHEN 'signing' THEN x.sign_requests ELSE x.require_encryption END
		       AND NOT EXISTS (SELECT 1 FROM core.saml_source_keys o
		                        WHERE o.provider_id = k.provider_id AND o.purpose = k.purpose
		                          AND o.retired_at IS NULL AND o.id <> k.id)
		  FROM core.saml_source_keys k
		  JOIN core.identity_providers p ON p.id = k.provider_id
		  JOIN core.saml_sources x ON x.provider_id = p.id
		 WHERE p.org_id = $1::uuid AND p.slug = $2 AND k.id::text = $3 AND k.retired_at IS NULL`,
		orgID, slug, id).Scan(&purpose, &needed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrProviderUnknown
	}
	if err != nil {
		return err
	}
	if needed {
		return fmt.Errorf("%w: this is the last %s key, and %q is held to using one; turn that off first",
			ErrSAMLSourceKey, purpose, slug)
	}
	_, err = q.Exec(ctx, `UPDATE core.saml_source_keys SET retired_at = now() WHERE id::text = $1`, id)
	return err
}

// SetSAMLSourceKeyUse says what an upstream is held to, nil leaving a setting as
// it is. Neither can be turned on with no key to do it with: the first sign-in
// afterwards would be how anybody found out.
func SetSAMLSourceKeyUse(ctx context.Context, q samlSourceKeysDB, orgID, slug string, signRequests, requireEncryption *bool) error {
	var signing, encryption bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.saml_source_keys k
		                WHERE k.provider_id = p.id AND k.purpose = 'signing' AND k.retired_at IS NULL),
		       EXISTS (SELECT 1 FROM core.saml_source_keys k
		                WHERE k.provider_id = p.id AND k.purpose = 'encryption' AND k.retired_at IS NULL)
		  FROM core.identity_providers p
		  JOIN core.saml_sources x ON x.provider_id = p.id
		 WHERE p.org_id = $1::uuid AND p.slug = $2`, orgID, slug).Scan(&signing, &encryption)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrProviderUnknown
	}
	if err != nil {
		return err
	}
	if signRequests != nil && *signRequests && !signing {
		return fmt.Errorf("%w: %q has no signing key; make one first", ErrSAMLSourceKey, slug)
	}
	if requireEncryption != nil && *requireEncryption && !encryption {
		return fmt.Errorf("%w: %q has no encryption key; make one first", ErrSAMLSourceKey, slug)
	}
	_, err = q.Exec(ctx, `
		UPDATE core.saml_sources x
		   SET sign_requests = COALESCE($3, x.sign_requests),
		       require_encryption = COALESCE($4, x.require_encryption)
		  FROM core.identity_providers p
		 WHERE p.id = x.provider_id AND p.org_id = $1::uuid AND p.slug = $2`,
		orgID, slug, signRequests, requireEncryption)
	return err
}

// SAMLSourceSigner is the key an upstream's requests are signed with: the newest
// that is live.
func SAMLSourceSigner(ctx context.Context, q claimReader, root *keys.RootKey, providerID string) (crypto.Signer, error) {
	live, err := liveSAMLSourceKeys(ctx, q, root, providerID, saml.SPKeySigning, 1)
	if err != nil {
		return nil, err
	}
	if len(live) == 0 {
		return nil, errors.New("no live signing key")
	}
	return live[0], nil
}

// SAMLSourceDecrypters are the keys an assertion from an upstream may be encrypted
// to. All that are live, since an upstream takes up a new certificate in its own
// time.
func SAMLSourceDecrypters(ctx context.Context, q claimReader, root *keys.RootKey, providerID string) ([]crypto.Decrypter, error) {
	live, err := liveSAMLSourceKeys(ctx, q, root, providerID, saml.SPKeyEncryption, 16)
	if err != nil {
		return nil, err
	}
	out := make([]crypto.Decrypter, len(live))
	for i, k := range live {
		out[i] = k
	}
	return out, nil
}

func liveSAMLSourceKeys(ctx context.Context, q claimReader, root *keys.RootKey, providerID, purpose string, limit int) ([]saml.SPKey, error) {
	if root == nil {
		return nil, errors.New("a key is sealed under the root key, and none is configured")
	}
	rows, err := q.Query(ctx, `
		SELECT key_sealed FROM core.saml_source_keys
		 WHERE provider_id = $1::uuid AND purpose = $2 AND retired_at IS NULL
		 ORDER BY created_at DESC, id LIMIT $3`, providerID, purpose, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []saml.SPKey
	for rows.Next() {
		var sealed []byte
		if err := rows.Scan(&sealed); err != nil {
			return nil, err
		}
		pkcs8, err := root.Open(sealed, sealContextSAMLSourceKey)
		if err != nil {
			return nil, fmt.Errorf("opening a key: %w", err)
		}
		key, err := saml.ParseSPKey(pkcs8)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}
