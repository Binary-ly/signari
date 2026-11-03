package saml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

const sealedACS = "https://signari.test/saml/acs"

// sealer turns an assertion, or anything else, into its encrypted form.
type sealer func(*testing.T, *etree.Element) *etree.Element

// sealedResponse is an ordinary response with its assertion encrypted, and the
// response signed afterwards when asked: what such a signature covers is the
// ciphertext.
func (u *upstream) sealedResponse(t *testing.T, o respOpts, signOuter bool, seal sealer) []byte {
	t.Helper()
	o.destination = sealedACS
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(u.response(t, o)); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	a := root.FindElement("./Assertion")
	sealed := seal(t, a)
	root.RemoveChild(a)
	root.AddChild(sealed)
	if signOuter {
		signed, err := signElement(root, u.key, u.certDER)
		if err != nil {
			t.Fatal(err)
		}
		doc.SetRoot(signed)
	}
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func toCert(certPEM, transport string) sealer {
	return func(t *testing.T, a *etree.Element) *etree.Element {
		t.Helper()
		sealed, err := EncryptAssertion(a, certPEM, transport)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
}

// sealCBC encrypts as a provider that only does CBC does, with random padding as
// XML Encryption has it.
func sealCBC(certPEM, alg string, size int) sealer {
	return func(t *testing.T, a *etree.Element) *etree.Element {
		t.Helper()
		sealed, err := EncryptAssertion(a, certPEM, "")
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		doc.SetRoot(a.Copy())
		plain, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		filler := make([]byte, pad)
		if _, err := rand.Read(filler); err != nil {
			t.Fatal(err)
		}
		filler[pad-1] = byte(pad)
		plain = append(plain, filler...)
		session := make([]byte, size)
		out := make([]byte, aes.BlockSize+len(plain))
		for _, b := range [][]byte{session, out[:aes.BlockSize]} {
			if _, err := rand.Read(b); err != nil {
				t.Fatal(err)
			}
		}
		block, err := aes.NewCipher(session)
		if err != nil {
			t.Fatal(err)
		}
		cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], plain)
		certs, err := ParseCertificates(certPEM)
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, certs[0].PublicKey.(*rsa.PublicKey), session, nil)
		if err != nil {
			t.Fatal(err)
		}
		sealed.FindElement("./EncryptedData/EncryptionMethod").SelectAttr("Algorithm").Value = alg
		sealed.FindElement("./EncryptedData/CipherData/CipherValue").SetText(base64.StdEncoding.EncodeToString(out))
		sealed.FindElement("./EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue").
			SetText(base64.StdEncoding.EncodeToString(wrapped))
		return sealed
	}
}

func decrypting(u *upstream, keys ...crypto.Decrypter) *InboundProvider {
	p := inboundProvider(u)
	p.Decrypters = keys
	return p
}

func consumeSealed(raw []byte, p *InboundProvider) (*InboundAssertion, error) {
	return ConsumeResponse(raw, p, ConsumeOptions{Destination: sealedACS, Now: time.Now()})
}

func TestAnEncryptedAssertionIsRead(t *testing.T) {
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	other, _ := spKeyFor(t, SPKeyEncryption)
	p := decrypting(u, other, key)
	p.AllowUnsolicited = true
	signed := respOpts{signAssertion: true, audience: p.SPEntityID, nameID: "ada@corp.test"}
	bare := respOpts{audience: p.SPEntityID, nameID: "ada@corp.test"}

	for name, raw := range map[string][]byte{
		"GCM, the assertion signed":              u.sealedResponse(t, signed, false, toCert(certPEM, "")),
		"GCM, SHA-256 key transport":             u.sealedResponse(t, signed, false, toCert(certPEM, KeyTransportSHA256)),
		"GCM, both signed":                       u.sealedResponse(t, signed, true, toCert(certPEM, "")),
		"GCM, only the response signed":          u.sealedResponse(t, bare, true, toCert(certPEM, "")),
		"CBC, behind a signature on the outside": u.sealedResponse(t, signed, true, sealCBC(certPEM, algAES256CBC, 32)),
		"AES-128-CBC, the same":                  u.sealedResponse(t, bare, true, sealCBC(certPEM, algAES128CBC, 16)),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := consumeSealed(raw, p)
			if err != nil {
				t.Fatal(err)
			}
			if got.Subject != "ada@corp.test" {
				t.Errorf("read %q", got.Subject)
			}
		})
	}
}

// Under GODEBUG=fips140=only an assertion encrypted with AES-GCM and the SHA-256
// key transport, the configuration that mode allows, is read. The GCM step gave
// the module an IV of its own and was refused there until November 2026.
func TestAnEncryptedAssertionIsReadUnderFIPSOnly(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAnEncryptedAssertionIsReadUnderFIPSOnly$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	p := decrypting(u, key)
	p.AllowUnsolicited = true
	raw := u.sealedResponse(t, respOpts{signAssertion: true, audience: p.SPEntityID, nameID: "ada@corp.test"},
		false, toCert(certPEM, KeyTransportSHA256))
	got, err := consumeSealed(raw, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "ada@corp.test" {
		t.Errorf("read %q", got.Subject)
	}
}

// A provider may put the key beside the data rather than inside it.
func TestTheKeyMayLieBesideTheData(t *testing.T) {
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	p := decrypting(u, key)
	p.AllowUnsolicited = true
	raw := u.sealedResponse(t, respOpts{signAssertion: true, audience: p.SPEntityID}, false,
		func(t *testing.T, a *etree.Element) *etree.Element {
			sealed := toCert(certPEM, "")(t, a)
			info := sealed.FindElement("./EncryptedData/KeyInfo")
			k := info.FindElement("./EncryptedKey")
			info.RemoveChild(k)
			sealed.AddChild(k)
			return sealed
		})
	if _, err := consumeSealed(raw, p); err != nil {
		t.Fatal(err)
	}
}

// A signature is over the assertion as it stood in the response, so the namespaces
// it may lean on are the response's and not only its own.
func TestADecryptedAssertionKeepsTheNamespacesItWasIn(t *testing.T) {
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	p := decrypting(u, key)
	p.AllowUnsolicited = true
	raw := u.sealedResponse(t, respOpts{signAssertion: true, audience: p.SPEntityID}, false,
		func(t *testing.T, a *etree.Element) *etree.Element {
			c := a.Copy()
			c.RemoveAttr("xmlns:saml")
			return toCert(certPEM, "")(t, c)
		})
	if _, err := consumeSealed(raw, p); err != nil {
		t.Fatal(err)
	}
}

func TestAnEncryptedNameIDIsRead(t *testing.T) {
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	seal := func(nid *etree.Element) *etree.Element {
		sealed := toCert(certPEM, "")(t, nid)
		sealed.Tag = "EncryptedID"
		return sealed
	}
	cbc := func(nid *etree.Element) *etree.Element {
		sealed := sealCBC(certPEM, algAES256CBC, 32)(t, nid)
		sealed.Tag = "EncryptedID"
		return sealed
	}
	p := decrypting(u, key)
	p.AllowUnsolicited = true
	for name, id := range map[string]func(*etree.Element) *etree.Element{"GCM": seal, "CBC, inside a signature": cbc} {
		raw := u.response(t, respOpts{signAssertion: true, audience: p.SPEntityID, destination: sealedACS,
			nameID: "ada@corp.test", sealNameID: id})
		got, err := consumeSealed(raw, p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Subject != "ada@corp.test" || got.SubjectFormat != FullNameIDFormat("emailAddress") {
			t.Errorf("%s: read %q %q", name, got.Subject, got.SubjectFormat)
		}
	}

	p.Decrypters = nil
	raw := u.response(t, respOpts{signAssertion: true, audience: p.SPEntityID, destination: sealedACS, sealNameID: seal})
	if _, err := consumeSealed(raw, p); err == nil || !strings.Contains(err.Error(), "NameID is encrypted") {
		t.Errorf("with no key: %v", err)
	}
}

func TestAnEncryptedAssertionIsRefused(t *testing.T) {
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	stranger, _ := spKeyFor(t, SPKeyEncryption)
	p := decrypting(u, key)
	p.AllowUnsolicited = true
	signed := respOpts{signAssertion: true, audience: p.SPEntityID}
	bare := respOpts{audience: p.SPEntityID}
	gcm := toCert(certPEM, "")
	wrap := func(inner string) sealer {
		return func(t *testing.T, _ *etree.Element) *etree.Element {
			t.Helper()
			return reseal(t, gcm(t, etree.NewElement("x")), inner, certPEM)
		}
	}

	otherIdP := newUpstream(t)
	cases := []struct {
		name, want string
		raw        []byte
		provider   *InboundProvider
	}{
		{name: "no key to open it with", want: "not configured to decrypt",
			raw: u.sealedResponse(t, signed, false, gcm), provider: inboundProvider(u)},
		{name: "encrypted to somebody else", want: "not encrypted to any live key",
			raw: u.sealedResponse(t, signed, false, gcm), provider: decrypting(u, stranger)},
		{name: "CBC with no signature over the ciphertext", want: "decrypted only behind a signature",
			raw: u.sealedResponse(t, signed, false, sealCBC(certPEM, algAES256CBC, 32))},
		{name: "signed by nobody", want: "neither the response nor the assertion is signed",
			raw: u.sealedResponse(t, bare, false, gcm)},
		{name: "signed by somebody else", want: "signature",
			raw: otherIdP.sealedResponse(t, signed, false, gcm)},
		{name: "somebody else's signature on the outside", want: "signature",
			raw: otherIdP.sealedResponse(t, bare, true, gcm)},
		{name: "ciphertext changed under the outer signature", want: "signature",
			raw: alterCipher(t, u.sealedResponse(t, signed, true, gcm))},
		{name: "ciphertext changed with AES-GCM alone", want: "did not authenticate",
			raw: alterCipher(t, u.sealedResponse(t, signed, false, gcm))},
		{name: "RSA PKCS#1 v1.5", want: "PKCS#1 v1.5",
			raw: u.sealedResponse(t, signed, false, func(t *testing.T, a *etree.Element) *etree.Element {
				sealed := gcm(t, a)
				sealed.FindElement("./EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod").SelectAttr("Algorithm").Value = algRSA15
				return sealed
			})},
		{name: "an algorithm nobody asked for", want: "not taken here",
			raw: u.sealedResponse(t, signed, false, func(t *testing.T, a *etree.Element) *etree.Element {
				sealed := gcm(t, a)
				sealed.FindElement("./EncryptedData/EncryptionMethod").SelectAttr("Algorithm").Value = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
				return sealed
			})},
		{name: "a key of the wrong size", want: "needs 16",
			raw: u.sealedResponse(t, signed, false, func(t *testing.T, a *etree.Element) *etree.Element {
				sealed := gcm(t, a)
				sealed.FindElement("./EncryptedData/EncryptionMethod").SelectAttr("Algorithm").Value = algAES128GCM
				return sealed
			})},
		{name: "something other than an assertion inside", want: "not a Assertion",
			raw: u.sealedResponse(t, bare, true, wrap(`<Other/>`))},
		{name: "a DOCTYPE inside", want: "DOCTYPE",
			raw: u.sealedResponse(t, bare, true, wrap(`<!DOCTYPE x [<!ENTITY a "b">]><Assertion ID="_a"/>`))},
		{name: "a second assertion inside", want: "holds 2 assertions",
			raw: u.sealedResponse(t, bare, true, wrap(`<Assertion ID="_a"><Assertion ID="_b"/></Assertion>`))},
		{name: "wrong audience inside", want: "addressed to",
			raw: u.sealedResponse(t, respOpts{signAssertion: true, audience: "https://elsewhere.test"}, false, gcm)},
		{name: "a plain assertion beside an encrypted one", want: "exactly one",
			raw: beside(t, u, signed, gcm)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			use := p
			if c.provider != nil {
				use = c.provider
				use.AllowUnsolicited = true
			}
			got, err := consumeSealed(c.raw, use)
			if err == nil {
				t.Fatalf("accepted, reading %q", got.Subject)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// reseal puts plain bytes where an encrypted element's ciphertext was, under the
// same key, by encrypting them the way EncryptAssertion does.
func reseal(t *testing.T, sealed *etree.Element, inner, certPEM string) *etree.Element {
	t.Helper()
	session := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(session)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertificates(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, certs[0].PublicKey.(*rsa.PublicKey), session, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed.FindElement("./EncryptedData/CipherData/CipherValue").
		SetText(base64.StdEncoding.EncodeToString(gcm.Seal(nil, nil, []byte(inner), nil)))
	sealed.FindElement("./EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue").
		SetText(base64.StdEncoding.EncodeToString(wrapped))
	return sealed
}

// alterCipher flips a bit of the assertion's ciphertext.
func alterCipher(t *testing.T, raw []byte) []byte {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	v := doc.FindElement("//EncryptedData/CipherData/CipherValue")
	b, err := base64.StdEncoding.DecodeString(v.Text())
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	v.SetText(base64.StdEncoding.EncodeToString(b))
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func beside(t *testing.T, u *upstream, o respOpts, seal sealer) []byte {
	t.Helper()
	o.destination = sealedACS
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(u.response(t, o)); err != nil {
		t.Fatal(err)
	}
	doc.Root().AddChild(seal(t, doc.Root().FindElement("./Assertion")))
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAnUpstreamHeldToEncryptionCannotSendAPlainAssertion(t *testing.T) {
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	p := decrypting(u, key)
	p.AllowUnsolicited, p.RequireEncryption = true, true
	o := respOpts{signAssertion: true, audience: p.SPEntityID, destination: sealedACS}
	if _, err := consumeSealed(u.response(t, o), p); err == nil || !strings.Contains(err.Error(), "held to encrypting") {
		t.Errorf("a plain assertion: %v", err)
	}
	if _, err := consumeSealed(u.sealedResponse(t, o, false, toCert(certPEM, "")), p); err != nil {
		t.Errorf("an encrypted one: %v", err)
	}
}

// The check that this is not this package agreeing with itself: xmlsec1 encrypts,
// with each pairing it offers that is taken here.
func TestWhatXmlsec1EncryptsIsRead(t *testing.T) {
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; it is the independent check")
	}
	u := newUpstream(t)
	key, certPEM := spKeyFor(t, SPKeyEncryption)
	p := decrypting(u, key)
	p.AllowUnsolicited = true
	dir := t.TempDir()
	certPath := filepath.Join(dir, "enc.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, data, session, transport string
		signOuter                      bool
	}{
		{"aes256-gcm, rsa-oaep-mgf1p", algAES256GCM, "aes-256", algRSAOAEPMGF1P, false},
		{"aes128-gcm, rsa-oaep-mgf1p", algAES128GCM, "aes-128", algRSAOAEPMGF1P, false},
		{"aes256-cbc, rsa-oaep-mgf1p, behind a signature", algAES256CBC, "aes-256", algRSAOAEPMGF1P, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := u.sealedResponse(t, respOpts{signAssertion: true, audience: p.SPEntityID}, c.signOuter,
				func(t *testing.T, a *etree.Element) *etree.Element {
					t.Helper()
					doc := etree.NewDocument()
					doc.SetRoot(a.Copy())
					plain, err := doc.WriteToBytes()
					if err != nil {
						t.Fatal(err)
					}
					data := filepath.Join(dir, "plain.xml")
					if err := os.WriteFile(data, plain, 0o600); err != nil {
						t.Fatal(err)
					}
					template := filepath.Join(dir, "template.xml")
					if err := os.WriteFile(template, []byte(`<saml:EncryptedAssertion xmlns:saml="`+nsAssertion+`">
<xenc:EncryptedData xmlns:xenc="`+nsXMLEnc+`" Type="`+nsXMLEnc+`Element">
<xenc:EncryptionMethod Algorithm="`+c.data+`"/>
<ds:KeyInfo xmlns:ds="`+nsDS+`"><xenc:EncryptedKey>
<xenc:EncryptionMethod Algorithm="`+c.transport+`"/>
<xenc:CipherData><xenc:CipherValue/></xenc:CipherData>
</xenc:EncryptedKey></ds:KeyInfo>
<xenc:CipherData><xenc:CipherValue/></xenc:CipherData>
</xenc:EncryptedData></saml:EncryptedAssertion>`), 0o600); err != nil {
						t.Fatal(err)
					}
					out, err := exec.Command(bin, "encrypt", "--lax-key-search", "--pubkey-cert-pem", certPath,
						"--session-key", c.session, "--binary-data", data, template).CombinedOutput()
					if err != nil {
						t.Fatalf("xmlsec1: %v\n%s", err, out)
					}
					sealed := etree.NewDocument()
					if err := sealed.ReadFromBytes(out); err != nil {
						t.Fatal(err)
					}
					return sealed.Root()
				})
			if _, err := consumeSealed(raw, p); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A check of the fixtures: the padding sealCBC writes is the padding open strips.
func TestCBCPaddingIsRead(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("sixteen bytes ok")
	plain := append(bytes.Clone(want), bytes.Repeat([]byte{0xee}, 15)...)
	plain = append(plain, 16)
	iv := sha256.Sum256(nil)
	out := append(bytes.Clone(iv[:aes.BlockSize]), make([]byte, len(plain))...)
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], plain)
	got, err := openCBC(block, out)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read %q, %v", got, err)
	}
	plain[len(plain)-1] = 17
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], plain)
	if _, err := openCBC(block, out); err == nil {
		t.Error("padding longer than a block was accepted")
	}
}
