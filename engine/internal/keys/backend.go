package keys

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Signing keys a module holds (3.14).
//
// A key made by a Backend never exists in this process. The module generates
// it, keeps it and signs with it, and what is here is a crypto.Signer that asks
// the module. Its row in core.signing_keys has no wrapped_private, and its
// key_ref names the backend and the key, `pkcs11:<kid>`: the room migration
// 0002's signing_keys_has_private_material constraint left for exactly this.
// A row with wrapped_private is a key sealed under the root key, as before,
// whatever its key_ref says, so the two kinds cannot be confused.
//
// Where a new key is made follows from what is configured, with no switch of
// its own: a node given a module makes every new signing key in it. A second
// switch would allow the combination that matters most to refuse, keys in a
// module and an unattended rotation making their successor in software. Keys
// made here before the module was configured go on loading from the database
// and are rotated out like any other, which is how a deployment moves its keys
// into a module.
//
// The encryption key a wallet seals to (decrypt.go) is always made here. It
// opens rather than signs, and opening in a module is not done.

// Backend makes and finds keys that never leave it.
type Backend interface {
	// Scheme prefixes the key_ref of every key it holds.
	Scheme() string
	// Generate makes a key for alg, named name, and returns a signer that
	// signs with it in place. rsaBits sizes an RSA key.
	Generate(name string, alg Algorithm, rsaBits int) (crypto.Signer, error)
	// Open finds the key named name.
	Open(name string) (crypto.Signer, error)
}

// HeldIn names where k's private half is: the scheme of the module that holds
// it, or "database" for one sealed under the root key.
func HeldIn(k Key) string {
	if sk, ok := k.(*signingKey); ok && sk.held != "" {
		scheme, _, _ := strings.Cut(sk.held, ":")
		return scheme
	}
	return "database"
}

// WithBackend returns this keyring making its signing keys in b and opening
// the keys b holds.
func (r *RootKey) WithBackend(b Backend) *RootKey {
	c := *r
	c.backend = b
	return &c
}

// Generate makes a signing key where this keyring makes them: in its backend
// when it has one, here otherwise.
func (r *RootKey) Generate(kid string, alg Algorithm) (Key, error) {
	return r.generate(kid, alg, RSABits)
}

// GenerateSized is Generate at a modulus an operator chose.
func (r *RootKey) GenerateSized(kid string, alg Algorithm, bits int) (Key, error) {
	if err := sizable(alg, bits); err != nil {
		return nil, err
	}
	return r.generate(kid, alg, bits)
}

// Successor makes the key that takes over from k, at k's size, where this
// keyring makes keys: a key made here is succeeded by one in the module once
// there is one.
func (r *RootKey) Successor(kid string, k Key) (Key, error) {
	return r.generate(kid, k.Algorithm(), successorBits(k))
}

func (r *RootKey) generate(kid string, alg Algorithm, rsaBits int) (Key, error) {
	if r == nil || r.backend == nil {
		return generate(kid, alg, rsaBits)
	}
	signer, err := r.backend.Generate(kid, alg, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("making a %s key in the %s module: %w", alg, r.backend.Scheme(), err)
	}
	if err := checkSignerMatchesAlg(alg, signer); err != nil {
		return nil, fmt.Errorf("the %s module made a key that %w", r.backend.Scheme(), err)
	}
	return &signingKey{
		kid:         kid,
		alg:         alg,
		state:       StateNext,
		signer:      signer,
		publishedAt: time.Now().UTC(),
		held:        r.backend.Scheme() + ":" + kid,
	}, nil
}

// openHeld finds a stored key in the module its key_ref names, and refuses one
// whose public half is not the one published. A module answering with another
// key under the same name, a second token given the same label or an object
// replaced by hand, would otherwise put a key nobody published in the JWKS and
// sign with it.
func (r *RootKey) openHeld(kid string, alg Algorithm, state State, ref string, published []byte,
	publishedAt time.Time) (Key, error) {
	scheme, name, ok := strings.Cut(ref, ":")
	if !ok || name == "" {
		return nil, fmt.Errorf("key %s has neither material nor a module reference (key_ref %q)", kid, ref)
	}
	if r.backend == nil || r.backend.Scheme() != scheme {
		setting := map[string]string{"pkcs11": "SIGNARI_PKCS11_MODULE", "vault-transit": "SIGNARI_VAULT_ADDR"}[scheme]
		return nil, fmt.Errorf("key %s is held in a %s module, and this node has none configured (%s)",
			kid, scheme, setting)
	}
	signer, err := r.backend.Open(name)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", kid, err)
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(published, &jwk); err != nil {
		return nil, fmt.Errorf("key %s: its published key does not parse: %w", kid, err)
	}
	same, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !same.Equal(jwk.Key) {
		return nil, fmt.Errorf("key %s: the %s module holds a different key under its name than the one "+
			"this deployment published", kid, scheme)
	}
	k, err := NewSoftwareKey(kid, alg, state, signer, publishedAt)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", kid, err)
	}
	k.(*signingKey).held = ref
	return k, nil
}
