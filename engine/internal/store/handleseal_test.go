package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"testing"
)

// Under GODEBUG=fips140=only what is sealed under a handed-out secret seals and
// opens. The wallet's presentation gave GCM a nonce of its own, which the module
// refuses, so a wallet sign-in failed in that mode.
func TestAHandleSealWorksUnderFIPSOnly(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAHandleSealWorksUnderFIPSOnly$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	sealed, err := sealUnder([]byte("a handed-out code"), "purpose", []byte("what it proved"), []byte("bound"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openUnder([]byte("a handed-out code"), "purpose", sealed, []byte("bound")); err != nil ||
		string(got) != "what it proved" {
		t.Errorf("round trip: %q %v", got, err)
	}
	if _, err := openUnder([]byte("another code"), "purpose", sealed, []byte("bound")); err == nil {
		t.Error("opened under another code")
	}
	if _, err := openUnder([]byte("a handed-out code"), "purpose", sealed, []byte("other")); err == nil {
		t.Error("opened bound to something else")
	}
}

// A presentation sealed the way it was before, the nonce chosen here, still
// opens: a sign-in in flight across the upgrade is not lost.
func TestAPresentationSealedBeforeStillOpens(t *testing.T) {
	key, err := hkdf.Key(sha256.New, []byte("code"), nil, vpPresentationContext, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	old := aead.Seal(nonce, nonce, []byte("proved"), []byte("provider"))
	if got, err := openUnder([]byte("code"), vpPresentationContext, old, []byte("provider")); err != nil ||
		string(got) != "proved" {
		t.Errorf("a presentation sealed before: %q %v", got, err)
	}
}
