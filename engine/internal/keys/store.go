package keys

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
)

// RootKey wraps the private material stored in core.signing_keys.
//
// It must NOT live in the database it protects. A database backup that also
// contains the key that decrypts it is not encryption, it is filing. Supply it
// from the environment, a file, or a KMS -- and note the corollary from ADR-007's
// backup section: a restored database with an unavailable root key invalidates
// every token you have ever issued, so root key and database must be backed up
// and *restore-tested* together.
type RootKey struct {
	aead cipher.AEAD
	ref  string
}

// NewRootKey takes 32 raw bytes. `ref` names which root key this is, so a future
// root-key rotation can tell wrapped blobs apart without trial decryption.
func NewRootKey(ref string, secret []byte) (*RootKey, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("root key must be 32 bytes, got %d", len(secret))
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &RootKey{aead: aead, ref: ref}, nil
}

// NewRootKeyFromBase64 parses the usual env-var form.
func NewRootKeyFromBase64(ref, b64 string) (*RootKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("root key is not valid base64: %w", err)
	}
	return NewRootKey(ref, raw)
}

// Ref identifies this root key in stored rows.
func (r *RootKey) Ref() string { return r.ref }

func (r *RootKey) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, r.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Nonce is prefixed to the ciphertext; GCM nonces are not secret.
	return r.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (r *RootKey) open(sealed []byte) ([]byte, error) {
	n := r.aead.NonceSize()
	if len(sealed) < n {
		return nil, fmt.Errorf("wrapped key is truncated")
	}
	return r.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

// Save persists a key. Private material is marshalled as PKCS#8 and sealed with
// the root key. A key whose private half lives in an HSM or KMS is stored with
// key_ref set and wrapped_private NULL -- the schema's CHECK constraint requires
// exactly one of the two.
// PurposeOIDC and PurposeFederation separate protocol signing keys from
// OpenID Federation Entity Statement keys.
//
// §3.1.1 of OpenID Federation 1.0: "These Federation Entity Keys SHOULD NOT be
// used in other protocols." The two answer different questions -- one asserts
// who a user is, the other asserts what this entity is and who vouches for it --
// so rotating or compromising one must not affect the other.
const (
	PurposeOIDC       = "oidc"
	PurposeFederation = "federation"
)

// Save persists an OIDC protocol key.
func Save(ctx context.Context, tx pgx.Tx, instanceID string, k Key, root *RootKey) error {
	return SaveFor(ctx, tx, instanceID, PurposeOIDC, k, root)
}

// SaveFor persists a key for a named purpose.
func SaveFor(ctx context.Context, tx pgx.Tx, instanceID, purpose string, k Key, root *RootKey) error {
	jwkBytes, err := json.Marshal(k.PublicJWK())
	if err != nil {
		return fmt.Errorf("marshalling public jwk: %w", err)
	}

	sk, ok := k.(*softwareKey)
	if !ok {
		return fmt.Errorf("Save supports software keys only; %T must persist its own key_ref", k)
	}
	der, err := x509.MarshalPKCS8PrivateKey(sk.signer)
	if err != nil {
		return fmt.Errorf("marshalling private key: %w", err)
	}
	wrapped, err := root.seal(der)
	if err != nil {
		return fmt.Errorf("wrapping private key: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO core.signing_keys
			(kid, instance_id, algorithm, state, public_jwk, wrapped_private, key_ref,
			 published_at, purpose)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (kid) DO UPDATE SET
			state = EXCLUDED.state,
			activated_at = CASE WHEN EXCLUDED.state = 'active'
			                    AND core.signing_keys.state <> 'active'
			                   THEN now() ELSE core.signing_keys.activated_at END,
			demoted_at   = CASE WHEN EXCLUDED.state = 'passive'
			                    AND core.signing_keys.state <> 'passive'
			                   THEN now() ELSE core.signing_keys.demoted_at END`,
		k.KID(), instanceID, string(k.Algorithm()), string(k.State()),
		jwkBytes, wrapped, root.Ref(), k.PublishedAt(), purpose,
	)
	if err != nil {
		return fmt.Errorf("saving key %s: %w", k.KID(), err)
	}
	return nil
}

// LoadSet reads every published key for an instance and builds a Set.
//
// It loads all three states deliberately: `next` so the JWKS can publish a key
// before it signs, and `passive` so tokens issued before the last rotation still
// verify. Loading only the active key is how rotation breaks verification.
func LoadSet(ctx context.Context, conn *pgx.Conn, instanceID string, root *RootKey) (*Set, error) {
	return LoadSetFor(ctx, conn, instanceID, PurposeOIDC, root)
}

// LoadSetFor reads the keys for one purpose.
func LoadSetFor(ctx context.Context, conn *pgx.Conn, instanceID, purpose string, root *RootKey) (*Set, error) {
	// OIDC keys only.
	//
	// `purpose` was added for OpenID Federation, whose §3.1.1 says "These
	// Federation Entity Keys SHOULD NOT be used in other protocols". Without
	// this filter a federation key would be loaded into the protocol key set and
	// published at /oauth2/jwks the moment one was generated -- the exact
	// conflation the separation exists to prevent, arriving silently rather than
	// as a decision anybody made.
	rows, err := conn.Query(ctx, `
		SELECT kid, algorithm, state, public_jwk, wrapped_private, key_ref, published_at
		FROM core.signing_keys
		WHERE instance_id = $1 AND purpose = $2
		ORDER BY published_at`, instanceID, purpose)
	if err != nil {
		return nil, fmt.Errorf("querying signing keys: %w", err)
	}
	defer rows.Close()

	var loaded []Key
	for rows.Next() {
		var (
			kid, alg, state, keyRef string
			jwkRaw                  []byte
			wrapped                 []byte
			publishedAt             time.Time
		)
		if err := rows.Scan(&kid, &alg, &state, &jwkRaw, &wrapped, &keyRef, &publishedAt); err != nil {
			return nil, err
		}
		if wrapped == nil {
			// An HSM/KMS-backed key. Resolving key_ref to a crypto.Signer is the
			// job of a backend this build does not have yet; skipping it silently
			// would mean serving a JWKS without a key we claim to hold.
			return nil, fmt.Errorf(
				"key %s is backed by %q, and no external signer backend is configured", kid, keyRef)
		}
		if keyRef != root.Ref() {
			return nil, fmt.Errorf(
				"key %s was wrapped with root key %q but %q is configured", kid, keyRef, root.Ref())
		}
		der, err := root.open(wrapped)
		if err != nil {
			return nil, fmt.Errorf("unwrapping key %s: %w", kid, err)
		}
		priv, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parsing key %s: %w", kid, err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key %s is not a signer (%T)", kid, priv)
		}
		k, err := NewSoftwareKey(kid, Algorithm(alg), State(state), signer, publishedAt)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", kid, err)
		}
		loaded = append(loaded, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return NewSet(loaded...)
}

// Ensure guarantees an instance has a usable signing key for each requested
// algorithm, generating and immediately activating one where none exists.
//
// Immediate activation is safe ONLY on first run: with no relying parties yet,
// there is no cached JWKS to invalidate. Every subsequent key must serve its
// publication dwell as `next` first -- see CanPromote.
func Ensure(ctx context.Context, conn *pgx.Conn, instanceID string, root *RootKey, algs ...Algorithm) ([]Key, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var created []Key
	for _, alg := range algs {
		var n int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM core.signing_keys
			WHERE instance_id = $1 AND algorithm = $2 AND state = 'active'
			  AND purpose = 'oidc'`,
			instanceID, string(alg)).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			continue
		}
		k, err := Generate(newKID(), alg)
		if err != nil {
			return nil, err
		}
		sk := k.(*softwareKey)
		sk.state = StateActive
		if err := Save(ctx, tx, instanceID, sk, root); err != nil {
			return nil, err
		}
		created = append(created, sk)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

// newKID returns a random key id. Deliberately opaque: a kid that encodes a
// timestamp or a counter tells an attacker about your rotation schedule, and a
// kid derived from the public key means rotating to the same key material
// silently reuses an id.
// NewKID is the exported form, for callers that mint a key outside this package
// (the rotate command). It exists so a caller cannot be tempted to invent its own
// scheme -- the properties above are the whole point.
func NewKID() string { return newKID() }

func newKID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("keys: no entropy available for key id: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// MarshalJWKS renders the public key set as the bytes served at the jwks_uri.
func (s *Set) MarshalJWKS() ([]byte, error) {
	return json.Marshal(s.JWKS())
}

var _ = jose.JSONWebKeySet{}

// KeyRefreshInterval is how often a running instance re-reads its keys.
//
// A minute. Rotation is not urgent -- the design publishes a `next` key a full
// day before promoting it -- but a reload interval measured in hours would make
// an operator wonder whether the rotation worked, and wondering leads to
// rotating again.
const KeyRefreshInterval = time.Minute

// Refresh re-reads the signing keys and replaces the live set.
//
// # Why this exists
//
// The set was loaded once at startup and never again, which defeated the
// rotation design completely. Rotation publishes a key as `next` so relying
// parties cache it BEFORE anything is signed with it, then promotes it a day
// later. With no reload:
//
//	the new key never reached any relying party
//	the day-long wait protected nothing
//	after a restart, instances signed with a key nobody had seen
//
// Found by rotating against two running instances and reading their JWKS: the
// new kid was in the database and in neither response.
//
// A failure here is logged and the previous set kept. The keys currently loaded
// are the ones known to work, and replacing them with nothing because the
// database was briefly unreachable would take an instance out of service for a
// transient fault.
func Refresh(ctx context.Context, conn *pgx.Conn, instanceID string, root *RootKey,
	live *Set) error {

	next, err := LoadSet(ctx, conn, instanceID, root)
	if err != nil {
		return fmt.Errorf("reloading signing keys: %w", err)
	}
	return live.Replace(next.Keys()...)
}
