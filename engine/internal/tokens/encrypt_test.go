package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func publicSet(t *testing.T, keys ...jose.JSONWebKey) string {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestWhatIsEncryptedToAClientOpensWithItsKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := publicSet(t, jose.JSONWebKey{Key: rsaKey.Public(), KeyID: "r", Use: "enc"},
		jose.JSONWebKey{Key: ecKey.Public(), KeyID: "e", Use: "enc"})

	for _, tc := range []struct {
		alg     string
		private any
		kid     string
	}{{"RSA-OAEP-256", rsaKey, "r"}, {"ECDH-ES", ecKey, "e"}} {
		for _, enc := range ContentEncryptions {
			raw, err := EncryptTo([]byte("the signed jwt"), true, set, Encryption{Alg: tc.alg, Enc: enc})
			if err != nil {
				t.Fatalf("%s %s: %v", tc.alg, enc, err)
			}
			if strings.Count(raw, ".") != 4 {
				t.Fatalf("%s %s is not a compact JWE: %q", tc.alg, enc, raw)
			}
			object, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.KeyAlgorithm(tc.alg)},
				[]jose.ContentEncryption{jose.ContentEncryption(enc)})
			if err != nil {
				t.Fatalf("%s %s: %v", tc.alg, enc, err)
			}
			if object.Header.KeyID != tc.kid {
				t.Errorf("%s names key %q", tc.alg, object.Header.KeyID)
			}
			// RFC 7519 §5.2: a Nested JWT says so.
			if cty := object.Header.ExtraHeaders[jose.HeaderContentType]; cty != "JWT" {
				t.Errorf("%s %s: cty is %v", tc.alg, enc, cty)
			}
			opened, err := object.Decrypt(tc.private)
			if err != nil || string(opened) != "the signed jwt" {
				t.Errorf("%s %s opened to %q (%v)", tc.alg, enc, opened, err)
			}
		}
	}

	// JSON alone is no Nested JWT, and must not claim to be.
	raw, err := EncryptTo([]byte(`{"sub":"x"}`), false, set, Encryption{Alg: "ECDH-ES", Enc: DefaultContentEncryption})
	if err != nil {
		t.Fatal(err)
	}
	object, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128CBC_HS256})
	if err != nil {
		t.Fatal(err)
	}
	if cty, said := object.Header.ExtraHeaders[jose.HeaderContentType]; said {
		t.Errorf("a plain JSON payload says cty %v", cty)
	}
}

// clientauth's floor on a signing key, on a key to encrypt to. Generated apart, since
// fips140=only will not make one this short.
func TestAShortKeyIsNotEncryptedTo(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("fips140=only refuses to generate the key this needs")
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	set := publicSet(t, jose.JSONWebKey{Key: weak.Public(), KeyID: "w", Use: "enc"})
	if key, err := EncryptionKey(set, "RSA-OAEP-256"); err == nil {
		t.Errorf("chose %q", key.KeyID)
	}
}

// A key is used for what its owner said it is for.
func TestAnEncryptionKeyIsOneTheClientMeantForThat(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := ecKey.Public()
	for name, tc := range map[string]struct {
		set, alg, want string
	}{
		"marked for encryption wins": {publicSet(t, jose.JSONWebKey{Key: public, KeyID: "plain"},
			jose.JSONWebKey{Key: public, KeyID: "enc", Use: "enc"}), "ECDH-ES", "enc"},
		"unmarked will do":      {publicSet(t, jose.JSONWebKey{Key: public, KeyID: "plain"}), "ECDH-ES", "plain"},
		"marked for signing":    {publicSet(t, jose.JSONWebKey{Key: public, KeyID: "s", Use: "sig"}), "ECDH-ES", ""},
		"named for signing":     {publicSet(t, jose.JSONWebKey{Key: public, KeyID: "s", Algorithm: "ES256"}), "ECDH-ES", ""},
		"the wrong kind of key": {publicSet(t, jose.JSONWebKey{Key: public, KeyID: "e", Use: "enc"}), "RSA-OAEP-256", ""},
		"nothing registered":    {"", "ECDH-ES", ""},
	} {
		key, err := EncryptionKey(tc.set, tc.alg)
		switch {
		case tc.want == "" && err == nil:
			t.Errorf("%s: chose %q", name, key.KeyID)
		case tc.want != "" && (err != nil || key.KeyID != tc.want):
			t.Errorf("%s: chose %+v (%v), want %s", name, key, err, tc.want)
		}
	}
}
