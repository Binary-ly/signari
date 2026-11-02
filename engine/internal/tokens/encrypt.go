package tokens

import (
	"crypto/ecdsa"
	"crypto/fips140"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Encrypting what goes to a client, to a key it registered. Nothing here decrypts. The one
// message this server opens is a wallet's credential request, and that takes a key of its
// own, in internal/keys; an encrypted Request Object is refused.

// Encryption is how something is encrypted to a client. The zero value is not at all.
type Encryption struct {
	Alg, Enc string
}

// What a client may ask for. RSA-OAEP-256, because RSA1_5 is an oracle for anybody who
// can see which ciphertexts fail, and a key wrap that shares a secret would prove
// nothing about which side wrote it. The schema's own CHECKs, but for fips140=only.
var (
	EncryptionAlgorithms = []string{"RSA-OAEP-256", "ECDH-ES"}
	ContentEncryptions   = contentEncryptions()
)

// contentEncryptions leaves GCM out under fips140=only, which refuses a nonce the caller
// chose, and the JOSE library chooses its own. A deployment there is told so by
// discovery and by the setting, rather than by a sign-in that fails.
func contentEncryptions() []string {
	if fips140.Enforced() {
		return []string{"A128CBC-HS256", "A256CBC-HS512"}
	}
	return []string{"A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM"}
}

// DefaultContentEncryption is what an algorithm given alone comes with. JARM §3: "If
// authorization_encrypted_response_alg is specified, the default for this value is
// A128CBC-HS256."
const DefaultContentEncryption = "A128CBC-HS256"

// minEncryptionRSABits is the floor clientauth holds a signing key to.
const minEncryptionRSABits = 2048

// EncryptionKey is the key in a client's registered set to encrypt to with alg: one
// marked `use: enc` before one that does not say, and never one marked for signing,
// whose owner has said what it is for.
func EncryptionKey(jwksJSON, alg string) (*jose.JSONWebKey, error) {
	var set jose.JSONWebKeySet
	if jwksJSON != "" {
		if err := json.Unmarshal([]byte(jwksJSON), &set); err != nil {
			return nil, fmt.Errorf("the client's registered key set did not parse: %w", err)
		}
	}
	var unmarked *jose.JSONWebKey
	for i := range set.Keys {
		k := &set.Keys[i]
		switch {
		case !encryptsWith(k, alg):
		case k.Use == "enc":
			return k, nil
		case k.Use == "" && unmarked == nil:
			unmarked = k
		}
	}
	if unmarked == nil {
		return nil, fmt.Errorf("the client has registered no key to encrypt to with %s", alg)
	}
	return unmarked, nil
}

func encryptsWith(k *jose.JSONWebKey, alg string) bool {
	if k.Algorithm != "" && k.Algorithm != alg {
		return false
	}
	switch key := k.Key.(type) {
	case *rsa.PublicKey:
		return alg == "RSA-OAEP-256" && key.N.BitLen() >= minEncryptionRSABits
	case *ecdsa.PublicKey:
		return alg == "ECDH-ES"
	}
	return false
}

// EncryptTo encrypts payload to a client's key. nested says the payload is a signed JWT,
// so that what comes out is a Nested JWT: RFC 7519 §5.2 has `cty` say so.
func EncryptTo(payload []byte, nested bool, jwksJSON string, e Encryption) (string, error) {
	key, err := EncryptionKey(jwksJSON, e.Alg)
	if err != nil {
		return "", err
	}
	opts := &jose.EncrypterOptions{}
	if nested {
		opts = opts.WithContentType("JWT")
	}
	encrypter, err := jose.NewEncrypter(jose.ContentEncryption(e.Enc),
		jose.Recipient{Algorithm: jose.KeyAlgorithm(e.Alg), Key: key.Key, KeyID: key.KeyID}, opts)
	if err != nil {
		return "", fmt.Errorf("building an encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("encrypting: %w", err)
	}
	return object.CompactSerialize()
}
