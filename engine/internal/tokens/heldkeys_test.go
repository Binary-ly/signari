package tokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
)

// heldRing is a keyring loaded from settings, as a node loads one, with a
// root key made up for the test.
func heldRing(t *testing.T, env map[string]string) *keys.RootKey {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	env["SIGNARI_ROOT_KEY"] = base64.StdEncoding.EncodeToString(secret)
	ring, err := keys.LoadRootKeyring(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// A token signed by a key held outside this process verifies against the
// public key published for it, in every algorithm the backend makes. RSA-PSS
// is checked with the salt as long as the hash, as a strict verifier checks it.
func heldKeysSignTokens(t *testing.T, ring *keys.RootKey, skip ...keys.Algorithm) {
	for _, alg := range keys.AllAlgorithms {
		if slices.Contains(skip, alg) {
			continue
		}
		k, err := ring.Generate(keys.NewKID(), alg)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if keys.HeldIn(k) == "database" {
			t.Fatalf("%s: the key was made here, not where the ring holds keys", alg)
		}
		active, err := keys.WithState(k, keys.StateActive)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := NewSigner(active).SignJSON(map[string]string{"sub": "someone"}, "JWT")
		if err != nil {
			t.Errorf("%s: signing: %v", alg, err)
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
