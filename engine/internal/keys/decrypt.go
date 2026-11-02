package keys

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// Opening what was encrypted to this server. Everything else here signs; a wallet's
// credential request is the one message that arrives encrypted (OpenID4VCI §10).

// Decrypter is what opens a JWE addressed to a key, beside crypto.Signer for the same
// reason: nothing above this package holds private key material, so a key that lives
// in an HSM can answer the same way.
type Decrypter interface {
	OpenJWE(object *jose.JSONWebEncryption) ([]byte, error)
}

// OpenJWE opens it with the key's private half.
func (k *softwareKey) OpenJWE(object *jose.JSONWebEncryption) ([]byte, error) {
	return object.Decrypt(k.signer)
}

// EncryptionAlgorithm is the key agreement a Purpose Encryption key is published for. An
// ES256 key is a P-256 key, and this is what one does when it is not signing.
const EncryptionAlgorithm = "ECDH-ES"

// OpenJWE opens a compact JWE encrypted to one of the set's keys, named by its `kid`, so
// that a key rotated out still opens what a wallet sealed before it noticed.
func (s *Set) OpenJWE(raw string, contentEncryptions []string) ([]byte, error) {
	allowed := make([]jose.ContentEncryption, 0, len(contentEncryptions))
	for _, enc := range contentEncryptions {
		allowed = append(allowed, jose.ContentEncryption(enc))
	}
	object, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.ECDH_ES}, allowed)
	if err != nil {
		return nil, fmt.Errorf("not a JWE this server takes: %w", err)
	}
	// Nothing offers compression, and left alone the library would inflate what it was
	// handed before anybody had looked at it.
	if _, compressed := object.Header.ExtraHeaders["zip"]; compressed {
		return nil, fmt.Errorf("a compressed JWE, which this server does not take")
	}
	key, found := s.ByKID(object.Header.KeyID)
	if !found {
		return nil, fmt.Errorf("encrypted to a key this server does not hold")
	}
	decrypter, ok := key.(Decrypter)
	if !ok {
		return nil, fmt.Errorf("key %s cannot decrypt", key.KID())
	}
	return decrypter.OpenJWE(object)
}

// PublicEncryptionJWKS is the set's keys as a client should encrypt to them, the active
// one alone: a passive key is kept only to open what was already sealed.
func (s *Set) PublicEncryptionJWKS() jose.JSONWebKeySet {
	out := jose.JSONWebKeySet{}
	for _, k := range s.snapshot() {
		if k.State() != StateActive {
			continue
		}
		jwk := k.PublicJWK()
		jwk.Use, jwk.Algorithm = "enc", EncryptionAlgorithm
		out.Keys = append(out.Keys, jwk)
	}
	return out
}

// RotateEncryptionKey makes a new encryption key active and the one before it passive, so
// that a wallet holding a cached copy still gets through. The one before that stops
// opening anything, which is how a key known to be lost is got rid of: rotate twice.
//
// There is no dwell, as a signing key has. Nothing verifies against this key later on: a
// wallet takes it from metadata, uses it once, and a refusal sends it back for the new one.
func RotateEncryptionKey(ctx context.Context, tx pgx.Tx, instanceID string, root *RootKey, via string) (Key, error) {
	if _, err := tx.Exec(ctx, `UPDATE core.signing_keys SET state = 'retired', retire_after = now()
		WHERE instance_id = $1 AND purpose = $2 AND state = 'passive'`, instanceID, PurposeEncryption); err != nil {
		return nil, fmt.Errorf("retiring the old encryption key: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE core.signing_keys SET state = 'passive', demoted_at = now()
		WHERE instance_id = $1 AND purpose = $2 AND state = 'active'`, instanceID, PurposeEncryption); err != nil {
		return nil, fmt.Errorf("demoting the encryption key: %w", err)
	}
	generated, err := Generate(newKID(), ES256)
	if err != nil {
		return nil, err
	}
	active, err := WithState(generated, StateActive)
	if err != nil {
		return nil, err
	}
	if err := SaveFor(ctx, tx, instanceID, PurposeEncryption, active, root); err != nil {
		return nil, err
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: audit.EventKeyRotated, Detail: map[string]any{
		"purpose": PurposeEncryption, "published": active.KID(), "via": via}}); err != nil {
		return nil, err
	}
	return active, nil
}
