package clients

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)


// FastSecretPrefix marks a secret hashed on the entropy assumption.
const FastSecretPrefix = "sha256$"

// MinFastSecretLen is the length at or above which a secret is treated as
// machine-generated.
//
// 32 characters. Ours are 43 (256 bits, base64url). Anything shorter might be
// human-chosen, and guessing wrong in that direction is the expensive mistake.
const MinFastSecretLen = 32

// HashSecret hashes a client secret, choosing by established entropy.
func HashSecret(plaintext string) (string, bool) {
	if len(plaintext) < MinFastSecretLen {
		// Not established as high-entropy. The caller must use the slow hash.
		return "", false
	}
	sum := sha256.Sum256([]byte(plaintext))
	return FastSecretPrefix + base64.RawStdEncoding.EncodeToString(sum[:]), true
}

// IsFastSecret reports whether a stored hash is in the fast format.
func IsFastSecret(stored string) bool {
	return strings.HasPrefix(stored, FastSecretPrefix)
}

// VerifyFastSecret checks a presented secret against a fast-format hash.
func VerifyFastSecret(stored, presented string) (bool, error) {
	if !IsFastSecret(stored) {
		return false, fmt.Errorf("not a fast-format secret hash")
	}
	want, err := base64.RawStdEncoding.DecodeString(stored[len(FastSecretPrefix):])
	if err != nil || len(want) != sha256.Size {
		return false, fmt.Errorf("the stored secret hash is malformed")
	}
	got := sha256.Sum256([]byte(presented))
	// Constant time. A fast hash that answered in variable time would hand back
	// through the clock exactly what it was meant to protect.
	return subtle.ConstantTimeCompare(want, got[:]) == 1, nil
}
