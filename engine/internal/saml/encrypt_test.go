package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OAEP, matching the production path.
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// decryptAssertion is a service provider's half of the exchange, written here so
// the round trip is proved rather than assumed. If this and EncryptAssertion
// disagree about layout, no real provider could read our output either.
func decryptAssertion(t *testing.T, ea *etree.Element, key *rsa.PrivateKey) string {
	t.Helper()

	ed := ea.FindElement("EncryptedData")
	if ed == nil {
		t.Fatal("no EncryptedData")
	}

	ekCipher := ed.FindElement("KeyInfo/EncryptedKey/CipherData/CipherValue")
	if ekCipher == nil {
		t.Fatal("no EncryptedKey CipherValue")
	}
	wrapped, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ekCipher.Text()))
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := rsa.DecryptOAEP(sha1.New(), nil, key, wrapped, nil)
	if err != nil {
		t.Fatalf("the session key did not unwrap: %v", err)
	}
	if len(sessionKey) != 32 {
		t.Fatalf("session key is %d bytes, want 32 (AES-256)", len(sessionKey))
	}

	dataCipher := ed.FindElement("CipherData/CipherValue")
	if dataCipher == nil {
		t.Fatal("no EncryptedData CipherValue")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dataCipher.Text()))
	if err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) < gcm.NonceSize() {
		t.Fatal("ciphertext shorter than the IV")
	}
	iv, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	plain, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	return string(plain)
}

func encryptedAssertionFor(t *testing.T, p *spKeyPair) *etree.Element {
	t.Helper()
	signed := signRequest(t, p, "_a1") // any signed element will do for layout
	doc := etree.NewDocument()
	if err := doc.ReadFromString(signed); err != nil {
		t.Fatal(err)
	}
	ea, err := EncryptAssertion(doc.Root(), p.certPEM, "")
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	return ea
}

func TestEncryptedAssertionRoundTrips(t *testing.T) {
	p := newSPKeyPair(t)
	ea := encryptedAssertionFor(t, p)
	plain := decryptAssertion(t, ea, p.key)

	if !strings.Contains(plain, "AuthnRequest") {
		t.Errorf("the decrypted document is not what went in: %.120s", plain)
	}
	// The signature must still be there and still be over the same bytes --
	// encryption happens after signing precisely so this holds.
	if !strings.Contains(plain, "Signature") {
		t.Error("the decrypted element carries no signature")
	}
	if err := VerifyEmbeddedSignature([]byte(plain), p.certPEM, "AuthnRequest", "_a1"); err != nil {
		t.Errorf("the signature did not survive encryption and decryption: %v", err)
	}
}

// TestCiphertextIsNotThePlaintext. A layout mistake that emitted the assertion
// unencrypted would still round-trip through a decrypt function that ignored it.
func TestCiphertextIsNotThePlaintext(t *testing.T) {
	p := newSPKeyPair(t)
	ea := encryptedAssertionFor(t, p)

	doc := etree.NewDocument()
	doc.SetRoot(ea)
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	// The envelope is saml:EncryptedAssertion wrapping xenc:EncryptedData and
	// nothing else, so none of the inner content may appear anywhere in it.
	for _, leak := range []string{"AuthnRequest", "sp.test", "Issuer", "NameID"} {
		if strings.Contains(s, leak) {
			t.Errorf("the encrypted envelope contains %q in the clear", leak)
		}
	}
	if strings.Contains(s, "SignatureValue") {
		t.Error("the envelope leaks the inner signature")
	}
}

// TestGCMDetectsTampering. This is the reason CBC is refused: without the
// authentication tag, a modified ciphertext decrypts to something, and the
// service provider's reaction to that something is a decryption oracle.
func TestGCMDetectsTampering(t *testing.T) {
	p := newSPKeyPair(t)
	ea := encryptedAssertionFor(t, p)

	cv := ea.FindElement("EncryptedData/CipherData/CipherValue")
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cv.Text()))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)/2] ^= 0x01
	cv.SetText(base64.StdEncoding.EncodeToString(blob))

	// Decrypt by hand rather than through the helper, which fails the test on
	// error -- here the error IS the expected result.
	ek := ea.FindElement("EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue")
	wrapped, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(ek.Text()))
	sessionKey, err := rsa.DecryptOAEP(sha1.New(), nil, p.key, wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(sessionKey)
	gcm, _ := cipher.NewGCM(block)
	iv, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	if _, err := gcm.Open(nil, iv, ct, nil); err == nil {
		t.Fatal("a modified ciphertext decrypted without error; there is no " +
			"authentication tag protecting it")
	}
}

// TestEachEncryptionUsesAFreshKeyAndIV. A reused GCM nonce under the same key
// destroys confidentiality outright, and a reused session key across providers
// would let one read another's assertions.
func TestEachEncryptionUsesAFreshKeyAndIV(t *testing.T) {
	p := newSPKeyPair(t)
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		ea := encryptedAssertionFor(t, p)
		cv := ea.FindElement("EncryptedData/CipherData/CipherValue")
		blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cv.Text()))
		if err != nil {
			t.Fatal(err)
		}
		iv := base64.StdEncoding.EncodeToString(blob[:12])
		if seen[iv] {
			t.Fatalf("IV repeated on iteration %d", i)
		}
		seen[iv] = true

		ek := ea.FindElement("EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue")
		wrapped, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(ek.Text()))
		key, err := rsa.DecryptOAEP(sha1.New(), nil, p.key, wrapped, nil)
		if err != nil {
			t.Fatal(err)
		}
		k := base64.StdEncoding.EncodeToString(key)
		if seen[k] {
			t.Fatalf("session key repeated on iteration %d", i)
		}
		seen[k] = true
	}
}

// TestWeakEncryptionKeyIsRefused, at the point of use as well as registration --
// a certificate can be replaced after the fact.
func TestWeakEncryptionKeyIsRefused(t *testing.T) {
	weak := weakKeyPair(t)
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<saml:Assertion xmlns:saml="x" ID="_a"/>`); err != nil {
		t.Fatal(err)
	}
	_, err := EncryptAssertion(doc.Root(), weak.certPEM, "")
	if err == nil {
		t.Fatal("a 1024-bit encryption certificate was accepted")
	}
	if !strings.Contains(err.Error(), "1024") {
		t.Errorf("the error should name the key size; got %v", err)
	}
}

func TestNoCertificateIsAnError(t *testing.T) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<saml:Assertion xmlns:saml="x" ID="_a"/>`); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptAssertion(doc.Root(), "", ""); err == nil {
		t.Fatal("encryption with no certificate did not fail")
	}
}

// TestGCMIsWhatWeAdvertise. A provider reads the algorithm identifier to decide
// how to decrypt, so a mismatch between what we say and what we did is
// undebuggable from its side.
func TestGCMIsWhatWeAdvertise(t *testing.T) {
	p := newSPKeyPair(t)
	ea := encryptedAssertionFor(t, p)

	em := ea.FindElement("EncryptedData/EncryptionMethod")
	if em == nil {
		t.Fatal("no EncryptionMethod")
	}
	if got := em.SelectAttrValue("Algorithm", ""); got != algAES256GCM {
		t.Errorf("EncryptionMethod is %q, want %q", got, algAES256GCM)
	}
	if strings.Contains(strings.ToLower(em.SelectAttrValue("Algorithm", "")), "cbc") {
		t.Error("CBC is advertised; it is refused for a reason")
	}
	kem := ea.FindElement("EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod")
	if got := kem.SelectAttrValue("Algorithm", ""); got != algRSAOAEPMGF1P {
		t.Errorf("key transport is %q, want %q", got, algRSAOAEPMGF1P)
	}
}

// TestSHA256KeyTransportMatchesWhatItAdvertises is the failure this setting
// exists to avoid causing.
//
// The EncryptedKey carries the algorithm as metadata, and the service provider
// unwraps using what that metadata names. If the metadata says SHA-256 and the
// bytes were produced with SHA-1, the far end fails to unwrap with no
// indication of which half disagreed -- and because the two paths differ by one
// hash argument, that is exactly the mistake a refactor makes.
//
// So this decrypts with the algorithm the document ADVERTISES, and then checks
// that the other algorithm does NOT work. The second half is the real test: a
// wrapper that somehow satisfied both would mean the metadata said nothing.
func TestSHA256KeyTransportMatchesWhatItAdvertises(t *testing.T) {
	p := newSPKeyPair(t)
	signed := signRequest(t, p, "_a1")
	doc := etree.NewDocument()
	if err := doc.ReadFromString(signed); err != nil {
		t.Fatal(err)
	}
	ea, err := EncryptAssertion(doc.Root(), p.certPEM, KeyTransportSHA256)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	em := ea.FindElement("EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod")
	if em == nil {
		t.Fatal("no EncryptedKey EncryptionMethod")
	}
	if got := em.SelectAttrValue("Algorithm", ""); got != algRSAOAEP {
		t.Errorf("key transport is %q, want %q", got, algRSAOAEP)
	}
	if d := em.FindElement("DigestMethod"); d == nil ||
		d.SelectAttrValue("Algorithm", "") != algSHA256 {
		t.Error("the digest is not declared as SHA-256")
	}
	// rsa-oaep's default MGF is MGF1-SHA1, so omitting this would describe a
	// SHA-256 digest with a SHA-1 mask -- a combination this does not produce.
	if m := em.FindElement("MGF"); m == nil ||
		m.SelectAttrValue("Algorithm", "") != algMGF1SHA256 {
		t.Error("the mask generation function is not declared as MGF1-SHA256")
	}

	wrapped := unwrappedKeyBytes(t, ea)
	if _, err := rsa.DecryptOAEP(crypto.SHA256.New(), nil, p.key, wrapped, nil); err != nil {
		t.Fatalf("the session key did not unwrap with the advertised SHA-256: %v", err)
	}
	// #nosec G401 -- deliberately the wrong algorithm, to prove it is wrong.
	if _, err := rsa.DecryptOAEP(sha1.New(), nil, p.key, wrapped, nil); err == nil {
		t.Error("the session key ALSO unwrapped with SHA-1, so the advertised " +
			"algorithm is not the one that was used")
	}
}

// TestDefaultKeyTransportStaysInteroperable pins the default.
//
// Every service provider implements rsa-oaep-mgf1p; xmlenc11 rsa-oaep is widely
// but not universally supported. Defaulting to the modern one would produce
// assertions that decrypt nowhere for whoever upgraded without reading a note.
func TestDefaultKeyTransportStaysInteroperable(t *testing.T) {
	p := newSPKeyPair(t)
	ea := encryptedAssertionFor(t, p) // passes "" for the key transport
	em := ea.FindElement("EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod")
	if got := em.SelectAttrValue("Algorithm", ""); got != algRSAOAEPMGF1P {
		t.Errorf("the default key transport is %q, want %q", got, algRSAOAEPMGF1P)
	}
}

func TestUnknownKeyTransportIsRefused(t *testing.T) {
	p := newSPKeyPair(t)
	signed := signRequest(t, p, "_a1")
	doc := etree.NewDocument()
	if err := doc.ReadFromString(signed); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptAssertion(doc.Root(), p.certPEM, "rsa-oaep-sha512"); err == nil {
		t.Error("an unknown key transport algorithm was accepted")
	}
}

func unwrappedKeyBytes(t *testing.T, ea *etree.Element) []byte {
	t.Helper()
	c := ea.FindElement("EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue")
	if c == nil {
		t.Fatal("no EncryptedKey CipherValue")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.Text()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
