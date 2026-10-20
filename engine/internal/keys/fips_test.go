package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"os"
	"os/exec"
	"testing"
)

// oldGCMSeal is how a blob was sealed before 3.11: a nonce the caller made,
// written ahead of the ciphertext and tag.
func oldGCMSeal(t *testing.T, secret, plaintext, ad []byte) []byte {
	t.Helper()
	var out []byte
	fips140.WithoutEnforcement(func() {
		block, err := aes.NewCipher(secret)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, aead.NonceSize())
		_, _ = rand.Read(nonce)
		out = aead.Seal(nonce, nonce, plaintext, ad)
	})
	return out
}

func oldGCMOpen(t *testing.T, secret, sealed, ad []byte) ([]byte, error) {
	t.Helper()
	var out []byte
	var err error
	fips140.WithoutEnforcement(func() {
		block, berr := aes.NewCipher(secret)
		if berr != nil {
			t.Fatal(berr)
		}
		aead, gerr := cipher.NewGCM(block)
		if gerr != nil {
			t.Fatal(gerr)
		}
		out, err = aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], ad)
	})
	return out, err
}

// The nonce-owning AEAD reads what the caller-nonce one wrote and writes what
// it reads (3.11): the stored format did not change, so no row needs rewriting.
func TestSealedBlobsKeepTheirFormat(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	root, err := NewRootKey("r", secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := root.Open(oldGCMSeal(t, secret, []byte("ctx\x00a signing key"), nil), "ctx"); err != nil || string(got) != "a signing key" {
		t.Errorf("a root-sealed blob written before: %q %v", got, err)
	}
	sealed, err := root.Seal([]byte("a signing key"), "ctx")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := oldGCMOpen(t, secret, sealed, nil); err != nil || !bytes.Equal(got, []byte("ctx\x00a signing key")) {
		t.Errorf("a root-sealed blob written now, read the old way: %q %v", got, err)
	}

	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	sk, err := newSubjectKey(dek)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sk.Open(oldGCMSeal(t, dek, []byte("a TOTP secret"), []byte("totp_secret")), "totp_secret"); err != nil ||
		string(got) != "a TOTP secret" {
		t.Errorf("a subject-sealed value written before: %q %v", got, err)
	}
	sealed, err = sk.Seal([]byte("a TOTP secret"), "totp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := oldGCMOpen(t, dek, sealed, []byte("totp_secret")); err != nil || string(got) != "a TOTP secret" {
		t.Errorf("a subject-sealed value written now, read the old way: %q %v", got, err)
	}
}

// Under GODEBUG=fips140=only the root and subject keys seal and open (3.11).
// They gave GCM a nonce of their own, which the module refuses, so serve died
// at startup unwrapping its first signing key.
func TestKeysSealUnderFIPSOnly(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestKeysSealUnderFIPSOnly$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	root, err := NewRootKey("r", secret)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := root.Seal([]byte("a signing key"), "ctx")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := root.Open(sealed, "ctx"); err != nil || string(got) != "a signing key" {
		t.Errorf("root key round trip under fips140=only: %q %v", got, err)
	}
	sk, err := newSubjectKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = sk.Seal([]byte("a value"), "c")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sk.Open(sealed, "c"); err != nil || string(got) != "a value" {
		t.Errorf("subject key round trip under fips140=only: %q %v", got, err)
	}
}
