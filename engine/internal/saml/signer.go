package saml

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
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
