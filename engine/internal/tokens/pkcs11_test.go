//go:build pkcs11 && cgo

package tokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/keys/softhsm"
)

func TestMain(m *testing.M) { softhsm.Main(m) }

// A token signed by a key a PKCS#11 module holds verifies against the public
// key published for it, in every algorithm the module makes. RSA-PSS is checked
// with the salt as long as the hash, as a strict verifier checks it.
func TestATokenSignedInAModuleVerifies(t *testing.T) {
	module, label, pin := softhsm.Token(t)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"SIGNARI_ROOT_KEY":      base64.StdEncoding.EncodeToString(secret),
		"SIGNARI_PKCS11_MODULE": module,
		"SIGNARI_PKCS11_TOKEN":  label,
		"SIGNARI_PKCS11_PIN":    pin,
	}
	ring, err := keys.LoadRootKeyring(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range keys.AllAlgorithms {
		if alg == keys.EdDSA {
			continue
		}
		k, err := ring.Generate(keys.NewKID(), alg)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		active, err := keys.WithState(k, keys.StateActive)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := NewSigner(active).SignJSON(map[string]string{"sub": "someone"}, "JWT")
		if err != nil {
			t.Errorf("%s: signing in the module: %v", alg, err)
			continue
		}
		published := active.PublicJWK()
		obj, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
		if err != nil {
			t.Errorf("%s: %v", alg, err)
			continue
		}
		if obj.Signatures[0].Header.KeyID != active.KID() {
			t.Errorf("%s: signed as %q", alg, obj.Signatures[0].Header.KeyID)
		}
		if _, err := obj.Verify(published.Key); err != nil {
			t.Errorf("%s: the signature does not verify with the published key: %v", alg, err)
		}
		if strings.HasPrefix(string(alg), "PS") {
			hash := map[keys.Algorithm]crypto.Hash{keys.PS256: crypto.SHA256, keys.PS384: crypto.SHA384,
				keys.PS512: crypto.SHA512}[alg]
			parts := strings.Split(raw, ".")
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			h := hash.New()
			h.Write([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPSS(published.Key.(*rsa.PublicKey), hash, h.Sum(nil), sig,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}); err != nil {
				t.Errorf("%s: the salt is not as long as the hash: %v", alg, err)
			}
		}
	}
}
