package keys

import (
	"crypto/fips140"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// enc is a content encryption that works in the mode this runs in: AES-GCM by way of the
// JOSE library is refused under fips140=only (docs/fips.md).
func enc() jose.ContentEncryption {
	if fips140.Enforced() {
		return jose.A256CBC_HS512
	}
	return jose.A256GCM
}

func offered() []string { return []string{string(enc())} }

func encryptionSet(t *testing.T, states ...State) (*Set, []Key) {
	t.Helper()
	made := make([]Key, 0, len(states))
	for _, state := range states {
		generated, err := Generate(newKID(), ES256)
		if err != nil {
			t.Fatal(err)
		}
		k, err := WithState(generated, state)
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, k)
	}
	set, err := NewSet(made...)
	if err != nil {
		t.Fatal(err)
	}
	return set, made
}

func sealTo(t *testing.T, k Key, opts *jose.EncrypterOptions, alg jose.ContentEncryption) string {
	t.Helper()
	jwk := k.PublicJWK()
	encrypter, err := jose.NewEncrypter(alg, jose.Recipient{Algorithm: jose.ECDH_ES, Key: jwk.Key, KeyID: k.KID()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	object, err := encrypter.Encrypt([]byte(`{"hello":"wallet"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAKeyOpensWhatWasSealedToIt(t *testing.T) {
	set, made := encryptionSet(t, StatePassive, StateActive)
	for _, k := range made {
		plain, err := set.OpenJWE(sealTo(t, k, nil, enc()), offered())
		if err != nil || string(plain) != `{"hello":"wallet"}` {
			t.Errorf("the %s key opened %q: %v", k.State(), plain, err)
		}
	}
}

// Metadata says nothing of compression, so a wallet was told not to, and inflating first
// is work for whoever sent the request to set.
func TestACompressedRequestIsNotInflated(t *testing.T) {
	set, made := encryptionSet(t, StateActive)
	raw := sealTo(t, made[0], &jose.EncrypterOptions{Compression: jose.DEFLATE}, enc())
	if _, err := set.OpenJWE(raw, offered()); err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Errorf("it answered %v", err)
	}
}

func TestOnlyWhatIsOfferedOpens(t *testing.T) {
	set, made := encryptionSet(t, StateActive)
	if _, err := set.OpenJWE(sealTo(t, made[0], nil, jose.A128CBC_HS256), offered()); err == nil {
		t.Error("a content encryption nothing offered opened")
	}
	other, _ := encryptionSet(t, StateActive)
	if _, err := other.OpenJWE(sealTo(t, made[0], nil, enc()), offered()); err == nil {
		t.Error("a JWE to a key the set does not hold opened")
	}
}

// §12.2.4's jwks is what a wallet is told to encrypt to. A passive key is only there to
// open what was sealed before it noticed.
func TestOnlyTheActiveKeyIsOffered(t *testing.T) {
	set, made := encryptionSet(t, StatePassive, StateActive)
	published := set.PublicEncryptionJWKS()
	if len(published.Keys) != 1 || published.Keys[0].KeyID != made[1].KID() {
		t.Fatalf("it published %+v", published.Keys)
	}
	if k := published.Keys[0]; k.Use != "enc" || k.Algorithm != EncryptionAlgorithm {
		t.Errorf("use %q alg %q: §10 has it that the alg is present and the JWE's equals it", k.Use, k.Algorithm)
	}
}
