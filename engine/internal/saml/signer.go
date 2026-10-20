package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// xmlSigner adapts a key to what XML Signature carries as a signature value.
//
// An RSA signature is the same octets in both worlds. An ECDSA one is not: a
// crypto.Signer returns the ASN.1 DER SEQUENCE of r and s, and the value XML
// Signature carries for ecdsa-sha256 is r and s as two fixed-width big-endian
// integers, concatenated. xmlsec1 1.3.12 writes 64 bytes for a P-256 key and
// refuses the DER form (TestAnECDSAAssertionVerifiesInXmlsec1).
//
// goxmldsig base64-encodes whatever Sign returns, and its own validator checks
// through x509, which wants DER (goxmldsig v1.6.1 validate.go:249,286). So
// without this adapter every ECDSA signature would verify against goxmldsig,
// and therefore against every test that round-trips through it, and against
// nothing else.
func xmlSigner(s crypto.Signer) crypto.Signer {
	if pub, ok := s.Public().(*ecdsa.PublicKey); ok {
		return rawECDSA{Signer: s, size: (pub.Curve.Params().BitSize + 7) / 8}
	}
	return s
}

// rawECDSA is a key whose signatures come out as r||s.
type rawECDSA struct {
	crypto.Signer
	size int
}

func (k rawECDSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	der, err := k.Signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 ||
		sig.R.BitLen() > 8*k.size || sig.S.BitLen() > 8*k.size {
		return nil, fmt.Errorf("the key returned an ECDSA signature that is not a DER pair of integers")
	}
	out := make([]byte, 2*k.size)
	sig.R.FillBytes(out[:k.size])
	sig.S.FillBytes(out[k.size:])
	return out, nil
}

// p256Key is a certificate's key when it is ECDSA on P-256, the only curve
// ecdsa-sha256 is accepted with.
func p256Key(cert *x509.Certificate) (*ecdsa.PublicKey, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the message is signed with ecdsa-sha256 and the certificate " +
			"registered for its sender is not a P-256 key")
	}
	return pub, nil
}

// rawRS splits an ecdsa-sha256 signature value into r and s. Exactly 64 bytes:
// a DER value is what a sender that skipped the conversion sends (see
// xmlSigner), and is refused here as xmlsec1 refuses it, not guessed at.
func rawRS(raw []byte) (r, s *big.Int, err error) {
	if len(raw) != 64 {
		return nil, nil, fmt.Errorf("the ecdsa-sha256 signature value is %d bytes; XML "+
			"Signature carries r and s as 64, and a DER-encoded value is refused", len(raw))
	}
	return new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]), nil
}

// ecdsaValueToDER rewrites an inbound ecdsa-sha256 SignatureValue from the r||s
// XML Signature carries into the DER goxmldsig verifies (3.36). The value is
// not covered by the signature, so rewriting it changes nothing that was
// signed. A sender's EC-signed request used to fail as a bad signature.
func ecdsaValueToDER(sig *etree.Element, cert *x509.Certificate) error {
	if sig == nil {
		return nil
	}
	method := sig.FindElement("SignedInfo/SignatureMethod")
	if method == nil {
		return nil
	}
	alg := method.SelectAttrValue("Algorithm", "")
	if !strings.Contains(alg, "ecdsa") {
		return nil
	}
	if alg != dsig.ECDSASHA256SignatureMethod {
		return fmt.Errorf("the message is signed with %s; of the ECDSA algorithms only "+
			"ecdsa-sha256 is accepted", alg)
	}
	if _, err := p256Key(cert); err != nil {
		return err
	}
	value := sig.FindElement("SignatureValue")
	if value == nil {
		return fmt.Errorf("the Signature has no SignatureValue")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value.Text()), ""))
	if err != nil {
		return fmt.Errorf("the signature value is not valid base64: %w", err)
	}
	r, s, err := rawRS(raw)
	if err != nil {
		return err
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return err
	}
	value.SetText(base64.StdEncoding.EncodeToString(der))
	return nil
}
