package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
)

// SubjectKey is one user's data encryption key.
//
// Everything personal we must store recoverably -- the TOTP secret, encrypted
// audit detail -- is sealed under the subject's OWN key rather than a global
// one. That single choice is what makes erasure possible without deleting rows:
//
//	destroy this key  ->  every ciphertext belonging to that person becomes
//	                      permanently unreadable, everywhere, including in
//	                      backups taken before the erasure
//
// This is crypto-shredding, and it is the only mechanism that erases data from
// backups you have already written. Deleting rows does not: yesterday's backup
// still has them, and a restore silently resurrects a person who asked to be
// forgotten.
//
// The corollary is deliberate and worth stating: an erased subject's TOTP secret
// is GONE. They cannot sign in with it, and no operator can recover it. That is
// what erasure means. Recovery after erasure is account re-creation, not repair.
type SubjectKey struct {
	aead cipher.AEAD
}

// ErrErased means the subject's key has been destroyed. Their ciphertext is
// unreadable by anyone, permanently, and that is the intended outcome -- callers
// should treat it as "this data no longer exists", not as a fault.
var ErrErased = errors.New("subject key has been erased")

// LoadOrCreateSubjectKey fetches a subject's DEK, minting one on first use.
//
// It takes a transaction, not a pool, so the key and whatever it protects are
// created atomically. A DEK that commits while the secret it was made for rolls
// back leaves an orphan; the reverse leaves ciphertext nobody can ever read.
func LoadOrCreateSubjectKey(ctx context.Context, tx pgx.Tx, subjectID string, root *RootKey) (*SubjectKey, error) {
	var wrapped []byte
	var erased bool

	err := tx.QueryRow(ctx, `
		SELECT wrapped_dek, erased_at IS NOT NULL
		FROM core.subject_keys WHERE subject_id = $1::uuid
		FOR UPDATE`, subjectID).Scan(&wrapped, &erased)

	switch {
	case err == pgx.ErrNoRows:
		return createSubjectKey(ctx, tx, subjectID, root)
	case err != nil:
		return nil, fmt.Errorf("loading subject key: %w", err)
	case erased:
		// Never silently mint a replacement. Doing so would make new data
		// readable again under the same subject id and quietly undo an erasure
		// that someone is legally entitled to rely on.
		return nil, ErrErased
	}

	raw, err := root.open(wrapped)
	if err != nil {
		// Almost always the wrong IDP_ROOT_KEY rather than corruption, and the
		// difference matters at 3am.
		return nil, fmt.Errorf("unwrapping subject key (is the root key correct?): %w", err)
	}
	return newSubjectKey(raw)
}

func createSubjectKey(ctx context.Context, tx pgx.Tx, subjectID string, root *RootKey) (*SubjectKey, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, fmt.Errorf("no entropy for a subject key: %w", err)
	}
	wrapped, err := root.seal(raw)
	if err != nil {
		return nil, fmt.Errorf("wrapping subject key: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.subject_keys (subject_id, wrapped_dek, wrap_key_ref)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (subject_id) DO NOTHING`, subjectID, wrapped, root.Ref()); err != nil {
		return nil, fmt.Errorf("storing subject key: %w", err)
	}
	return newSubjectKey(raw)
}

func newSubjectKey(raw []byte) (*SubjectKey, error) {
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SubjectKey{aead: aead}, nil
}

// Seal encrypts data belonging to this subject.
//
// `context` is authenticated but not encrypted -- pass something that names what
// the ciphertext IS ("totp_secret"). It binds the ciphertext to its purpose, so
// a blob lifted from one column and pasted into another fails to decrypt rather
// than silently becoming a different secret.
func (s *SubjectKey) Seal(plaintext []byte, context string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte(context)), nil
}

// Open decrypts. The context must match the one used to seal.
func (s *SubjectKey) Open(sealed []byte, context string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, fmt.Errorf("ciphertext is truncated")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], []byte(context))
}

// EraseSubject destroys a subject's key, rendering all their ciphertext
// permanently unreadable.
//
// The row survives with erased_at set, and that is the point: it is the evidence
// that an erasure was performed and when. A deleted row proves nothing, and
// "we did erase them, we just cannot show you" is not a position anyone wants to
// be in during an audit.
//
// The CHECK constraint on the table enforces the pairing -- erased_at set and
// wrapped_dek NULL must happen together, so a half-erasure cannot be committed.
func EraseSubject(ctx context.Context, tx pgx.Tx, subjectID string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE core.subject_keys
		SET wrapped_dek = NULL, erased_at = now()
		WHERE subject_id = $1::uuid AND erased_at IS NULL`, subjectID)
	if err != nil {
		return fmt.Errorf("erasing subject key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Already erased, or never had a key. Both are the requested end state,
		// so this is not an error -- an erasure request that arrives twice must
		// not fail the second time.
		return nil
	}
	return nil
}

// Seal and Open on the ROOT key, for secrets that belong to an ORGANISATION
// rather than a person -- today, a migration source's client secret.
//
// Deliberately separate from SubjectKey: a subject key is destroyed when that
// person is erased, and an organisation's configuration must survive that. Using
// the wrong one here would mean erasing any single user silently broke the
// migration for everyone else in the org.
func (r *RootKey) Seal(plaintext []byte, context string) ([]byte, error) {
	return r.seal(append([]byte(context+"\x00"), plaintext...))
}

// Open reverses Seal, checking the context binding.
func (r *RootKey) Open(sealed []byte, context string) ([]byte, error) {
	raw, err := r.open(sealed)
	if err != nil {
		return nil, err
	}
	prefix := []byte(context + "\x00")
	if len(raw) < len(prefix) || string(raw[:len(prefix)]) != string(prefix) {
		// The blob decrypted but was sealed for a different purpose -- almost
		// always a value copied between columns.
		return nil, errors.New("keys: ciphertext was sealed for a different purpose")
	}
	return raw[len(prefix):], nil
}
