package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// ErrPKCEMismatch means the verifier did not produce the stored challenge.
var ErrPKCEMismatch = errors.New("code_verifier does not match code_challenge")

// ErrPKCEMalformed means the verifier is not a valid RFC 7636 verifier.
var ErrPKCEMalformed = errors.New("code_verifier is malformed")

func VerifyPKCE(method, challenge, verifier string) error {
	if method != "S256" {
		return ErrPKCEMismatch
	}
	if !validVerifier(verifier) {
		return ErrPKCEMalformed
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrPKCEMismatch
	}
	return nil
}

// Challenge derives the S256 challenge for a verifier. Used by tests and by the
// migration tooling that has to reproduce a client's computation.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validVerifier enforces the RFC 7636 shape: 43-128 characters from the
// unreserved set. A short verifier weakens the binding PKCE exists to provide,
// so accepting one would make the check decorative.
func validVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}
