package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

// Sealing under a secret the caller hands out and does not keep: a wallet's
// response code, an artifact's message handle. The row holds what only the
// holder of that secret can open, so a reader of the database learns nothing
// from it.
//
// The nonce is the module's own. GCM given one by its caller is refused under
// GODEBUG=fips140=only (keys/store.go says the same of the root key), and the
// wallet's presentation was sealed that way until November 2026, so a wallet
// sign-in failed in that mode. The output is what it was: a 96-bit nonce ahead
// of the ciphertext and tag.

func handleCipher(secret []byte, purpose string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, secret, nil, purpose, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// sealUnder seals plaintext under a key derived from secret for purpose, bound
// to ad.
func sealUnder(secret []byte, purpose string, plaintext, ad []byte) ([]byte, error) {
	aead, err := handleCipher(secret, purpose)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, ad), nil
}

// openUnder opens what sealUnder sealed.
func openUnder(secret []byte, purpose string, sealed, ad []byte) ([]byte, error) {
	aead, err := handleCipher(secret, purpose)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.Overhead() {
		return nil, errors.New("the sealed value is cut short")
	}
	return aead.Open(nil, nil, sealed, ad)
}
