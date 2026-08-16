package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	// #nosec G505 -- SHA-1 here is OAEP's mask generation function, which needs a
	// pseudorandom function and not collision resistance. See the note in
	// EncryptAssertion on why this is unrelated to the SHA-1 this package refuses
	// in signatures.
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/beevik/etree"
)

// XML Encryption algorithm identifiers.
const (
	// AES-256-GCM. The ONLY data encryption algorithm offered here; see below.
	algAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	// RSA-OAEP with MGF1-SHA1, the interoperable key transport algorithm.
	algRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	// RSA-OAEP with explicit digest and MGF parameters, so SHA-256 can be named.
	algRSAOAEP    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	algMGF1SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	algSHA256     = "http://www.w3.org/2001/04/xmlenc#sha256"
	algSHA1Digest = "http://www.w3.org/2000/09/xmldsig#sha1"
)

// Key transport choices, as stored against a service provider.
const (
	// KeyTransportMGF1P is rsa-oaep-mgf1p: universal, and SHA-1 inside OAEP.
	KeyTransportMGF1P = "rsa-oaep-mgf1p"
	// KeyTransportSHA256 is xmlenc11 rsa-oaep with SHA-256, which FIPS allows.
	KeyTransportSHA256 = "rsa-oaep-sha256"

	nsXMLEnc   = "http://www.w3.org/2001/04/xmlenc#"
	nsXMLEnc11 = "http://www.w3.org/2009/xmlenc11#"
	nsDS     = "http://www.w3.org/2000/09/xmldsig#"
)

// EncryptAssertion wraps a signed assertion in <saml:EncryptedAssertion>.
//
// # Sign first, then encrypt
//
// The assertion handed in is already signed, and that order is the point.
// Encrypt-then-sign leaves the signature over ciphertext, which proves who
// produced the envelope and says nothing about the identity inside it -- so a
// service provider that decrypts gets an unsigned assertion and has to trust the
// wrapper. Signing the assertion itself means the thing carrying the identity is
// the thing covered by the signature, whether or not it is later encrypted.
//
// # Why AES-GCM only, and never CBC
//
// XML Encryption's CBC modes are broken in practice, not in theory. Jager and
// Somorovsky (CCS 2011) recovered plaintext from XML Encryption implementations
// at a cost of a few thousand queries per block, using the service provider
// itself as a decryption oracle: it distinguishes "this decrypted to malformed
// XML" from "this decrypted cleanly", and that single bit is enough.
//
// The response was authenticated encryption. GCM fails the whole ciphertext on
// the authentication tag before any of it is parsed, so there is no oracle to
// query. Offering CBC "for compatibility" would mean every deployment that
// enabled it inherited the attack, and a service provider that cannot do GCM is
// better served by TLS alone than by encryption that does not hold.
//
// # Why SHA-1 appears here and is refused elsewhere
//
// rsa-oaep-mgf1p uses SHA-1 inside OAEP's mask generation function. That is not
// a signature and not a collision-resistance claim: MGF1 needs a pseudorandom
// function, and SHA-1 remains one. The SHA-1 this package refuses is SHA-1 in a
// signature, where chosen-prefix collisions are practical and let two different
// documents share one signature. The two uses are unrelated, and conflating them
// would mean refusing the one key transport algorithm every service provider
// implements.
func EncryptAssertion(signedAssertion *etree.Element, certPEM, keyTransport string) (
	*etree.Element, error) {

	switch keyTransport {
	case "", KeyTransportMGF1P:
		keyTransport = KeyTransportMGF1P
	case KeyTransportSHA256:
	default:
		return nil, fmt.Errorf("unknown key transport algorithm %q for this service "+
			"provider; expected %q or %q", keyTransport, KeyTransportMGF1P,
			KeyTransportSHA256)
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the encryption certificate registered for this service "+
			"provider holds a %T key; SAML assertion encryption here needs RSA",
			cert.PublicKey)
	}
	// A 1024-bit key transports a 256-bit AES key perfectly well and is far below
	// what anyone should be relying on in 2026. Refused at the point of use as
	// well as at registration, because a certificate can be replaced later.
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("the encryption certificate is a %d-bit RSA key; "+
			"2048 is the minimum", pub.N.BitLen())
	}

	// Serialise the assertion exactly as it is. No indenting, no re-canonicalising
	// -- the signature inside was computed over these bytes, and changing them
	// here would produce something that decrypts cleanly and then fails to verify
	// at the far end, which is the hardest possible failure to diagnose.
	plainDoc := etree.NewDocument()
	plainDoc.SetRoot(signedAssertion.Copy())
	plaintext, err := plainDoc.WriteToString()
	if err != nil {
		return nil, fmt.Errorf("serialising the assertion for encryption: %w", err)
	}

	sessionKey := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, fmt.Errorf("generating a session key: %w", err)
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	// XML Encryption carries the IV as a prefix of the cipher value and GCM's
	// tag as a suffix, which is exactly the layout NewGCMWithRandomNonce
	// produces: it generates the nonce itself and prepends it.
	//
	// Letting the library generate the nonce rather than doing it here is also
	// what makes this work under FIPS 140-only mode, where GCM with a
	// caller-supplied IV is refused outright -- a nonce reused under the same
	// key destroys GCM completely, so the rule is that the module owns it.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nil, []byte(plaintext), nil)

	oaepHash := crypto.SHA256.New()
	if keyTransport == KeyTransportMGF1P {
		// #nosec G401 -- as above: OAEP mask generation, not a digest anyone signs.
		oaepHash = sha1.New()
	}
	wrapped, err := rsa.EncryptOAEP(oaepHash, rand.Reader, pub, sessionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("wrapping the session key: %w", err)
	}

	return buildEncryptedAssertion(ciphertext, wrapped, cert, keyTransport), nil
}

// buildEncryptedAssertion assembles the XML Encryption structure.
func buildEncryptedAssertion(ciphertext, wrappedKey []byte, cert *x509.Certificate,
	keyTransport string) *etree.Element {
	ea := etree.NewElement("saml:EncryptedAssertion")
	ea.CreateAttr("xmlns:saml", nsAssertion)

	ed := ea.CreateElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", nsXMLEnc)
	// Type says the plaintext is a whole element, so the service provider knows
	// to parse the result as XML rather than treat it as element content.
	ed.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", algAES256GCM)

	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", nsDS)

	ek := ki.CreateElement("xenc:EncryptedKey")
	em := ek.CreateElement("xenc:EncryptionMethod")
	if keyTransport == KeyTransportSHA256 {
		// xmlenc11 rsa-oaep takes its parameters explicitly: the digest as a
		// DigestMethod and the mask generation function as MGF. Naming the MGF is
		// not optional here -- rsa-oaep's default MGF is MGF1-SHA1, so an
		// EncryptedKey that names SHA-256 as the digest and omits the MGF
		// describes a combination Go does not produce, and the far end fails to
		// unwrap the key with no indication of which half disagreed.
		em.CreateAttr("Algorithm", algRSAOAEP)
		em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", algSHA256)
		em.CreateElement("xenc11:MGF").CreateAttr("Algorithm", algMGF1SHA256)
		em.CreateAttr("xmlns:xenc11", nsXMLEnc11)
	} else {
		em.CreateAttr("Algorithm", algRSAOAEPMGF1P)
		em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", algSHA1Digest)
	}

	// Which certificate this was encrypted to. A service provider holding more
	// than one decryption key -- which is every provider mid-rotation -- otherwise
	// has to try each in turn and cannot tell a wrong key from a corrupt message.
	ekKI := ek.CreateElement("ds:KeyInfo")
	ekKI.CreateElement("ds:X509Data").
		CreateElement("ds:X509Certificate").
		SetText(CertificateB64(cert.Raw))

	ek.CreateElement("xenc:CipherData").
		CreateElement("xenc:CipherValue").
		SetText(base64.StdEncoding.EncodeToString(wrappedKey))

	ed.CreateElement("xenc:CipherData").
		CreateElement("xenc:CipherValue").
		SetText(base64.StdEncoding.EncodeToString(ciphertext))

	return ea
}
