package oid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// COSE, as much of it as an mdoc's two signatures need: COSE_Sign1 with an algorithm in
// its protected header and a certificate chain or nothing in its unprotected one, and the
// COSE_Key an MSO carries the device key in.

// Header labels (specs/rfc9052.txt:751; specs/rfc9360.txt:296).
const (
	coseLabelAlg     = 1
	coseLabelX5Chain = 33
)

// The algorithms ISO/IEC 18013-5 lets an issuer and a device sign with, by COSE value
// (specs/rfc9053.txt:248-252, :365): ES256, ES384, ES512 and EdDSA (18013-5 9.1.2.4 and
// 9.1.3.6, specs/iso-iec-18013-5-2021.pdf pages 58 and 60-61).
const (
	coseES256 = -7
	coseES384 = -35
	coseES512 = -36
	coseEdDSA = -8
)

// MdocAlgorithms are the COSE algorithms an mdoc may be signed with here, as
// issuerauth_alg_values and deviceauth_alg_values name them (specs/oid4vp.txt:3092-3100).
// 18013-5 also allows brainpool curves for ECDSA and Ed448 for EdDSA, which Go's
// standard library does not implement: such a credential is refused by name.
func MdocAlgorithms() []int { return []int{coseES256, coseES384, coseES512, coseEdDSA} }

// coseSign1 is COSE_Sign1 (specs/rfc9052.txt:935-939), untagged as 18013-5 sends it
// (9.1.2.4: "the untagged COSE_Sign1 structure", PDF page 57), or tagged 18
// (specs/rfc9052.txt:913), which a decoder may meet and is the same structure.
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]cbor.RawMessage
	Payload     []byte // nil when detached, as the device signature is
	Signature   []byte
}

func decodeSign1(raw []byte) (*coseSign1, error) {
	var tag cbor.RawTag
	if err := mdocDecMode.Unmarshal(raw, &tag); err == nil {
		if tag.Number != 18 {
			return nil, fmt.Errorf("a COSE_Sign1 tagged %d", tag.Number)
		}
		raw = tag.Content
	}
	var s coseSign1
	if err := mdocDecMode.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("not a COSE_Sign1: %w", err)
	}
	return &s, nil
}

// alg is the algorithm in the protected header, where 18013-5 requires it (9.1.2.4 and
// 9.1.3.6: "The alg element ... shall be included as an element in the protected
// header"). One in the unprotected header is not signed, so it is not read.
func (s *coseSign1) alg() (int, error) {
	if len(s.Protected) == 0 {
		return 0, errors.New("the protected header is empty, and the algorithm has to be in it")
	}
	var h map[any]cbor.RawMessage
	if err := mdocDecMode.Unmarshal(s.Protected, &h); err != nil {
		return 0, fmt.Errorf("the protected header is not a map: %w", err)
	}
	raw, ok := label(h, coseLabelAlg)
	if !ok {
		return 0, errors.New("the protected header names no algorithm")
	}
	var alg int
	if err := mdocDecMode.Unmarshal(raw, &alg); err != nil {
		return 0, fmt.Errorf("the algorithm is not an integer: %w", err)
	}
	return alg, nil
}

// label reads an integer-labelled header, however the decoder typed the label.
func label(h map[any]cbor.RawMessage, want int64) (cbor.RawMessage, bool) {
	for k, v := range h {
		switch n := k.(type) {
		case int64:
			if n == want {
				return v, true
			}
		case uint64:
			if want >= 0 && n == uint64(want) {
				return v, true
			}
		}
	}
	return nil, false
}

// x5chain is the certificate chain in the unprotected header, end-entity first
// (specs/rfc9360.txt:181, :296; the CDDL `bstr / [ 2*certs: bstr ]`).
func (s *coseSign1) x5chain() ([][]byte, error) {
	raw, ok := label(s.Unprotected, coseLabelX5Chain)
	if !ok {
		return nil, errors.New("the issuer signature carries no x5chain")
	}
	var one []byte
	if err := mdocDecMode.Unmarshal(raw, &one); err == nil {
		return [][]byte{one}, nil
	}
	var many [][]byte
	if err := mdocDecMode.Unmarshal(raw, &many); err != nil || len(many) < 2 {
		return nil, errors.New("x5chain is neither one certificate nor a list of two or more")
	}
	return many, nil
}

// verify checks the signature over the Sig_structure ["Signature1", protected,
// external_aad, payload] (specs/rfc9052.txt:1003, :1024-1030), with an empty
// external_aad as 18013-5 has it for both signatures, and payload the attached one or,
// detached, the content given.
func (s *coseSign1) verify(pub crypto.PublicKey, detached []byte) error {
	alg, err := s.alg()
	if err != nil {
		return err
	}
	payload := s.Payload
	if detached != nil {
		if s.Payload != nil {
			return errors.New("a signature over detached content carries a payload of its own")
		}
		payload = detached
	}
	if payload == nil {
		return errors.New("there is nothing the signature is over")
	}
	tbs, err := cbor.Marshal([]any{"Signature1", s.Protected, []byte{}, payload})
	if err != nil {
		return err
	}
	return coseVerify(alg, pub, tbs, s.Signature)
}

// coseVerify checks sig over tbs with pub under alg, the key's curve held to the one the
// algorithm names (18013-5 9.1.2.4: ES256 with P-256, ES384 with P-384, ES512 with P-521,
// EdDSA with Ed25519, of those Go implements).
func coseVerify(alg int, pub crypto.PublicKey, tbs, sig []byte) error {
	switch alg {
	case coseES256, coseES384, coseES512:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %d needs an EC key", alg)
		}
		curve, hash := map[int]elliptic.Curve{coseES256: elliptic.P256(), coseES384: elliptic.P384(),
			coseES512: elliptic.P521()}[alg], map[int]crypto.Hash{coseES256: crypto.SHA256,
			coseES384: crypto.SHA384, coseES512: crypto.SHA512}[alg]
		if k.Curve != curve {
			return fmt.Errorf("algorithm %d with a key on %s", alg, k.Curve.Params().Name)
		}
		// R and S, each the key's size, left-padded, concatenated (specs/rfc9053.txt:269-282).
		n := (curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return fmt.Errorf("an ECDSA signature of %d bytes, and %d were due", len(sig), 2*n)
		}
		h := hash.New()
		h.Write(tbs)
		r, sv := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(k, h.Sum(nil), r, sv) {
			return errors.New("the signature does not verify")
		}
		return nil
	case coseEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("EdDSA here verifies Ed25519 keys; Ed448 is not implemented")
		}
		if !ed25519.Verify(k, tbs, sig) {
			return errors.New("the signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("algorithm %d is not one an mdoc is signed with here (ES256, ES384, ES512, EdDSA)", alg)
}

// coseKey reads a public COSE_Key: EC2 on P-256, P-384 or P-521 with x and y, y a
// coordinate or the sign bit of a compressed point, or OKP on Ed25519
// (specs/rfc9053.txt:1627-1664, :1680-1706).
func coseKey(raw cbor.RawMessage) (crypto.PublicKey, error) {
	var m map[any]cbor.RawMessage
	if err := mdocDecMode.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("the device key is not a COSE_Key: %w", err)
	}
	read := func(l int64, into any) bool {
		v, ok := label(m, l)
		return ok && mdocDecMode.Unmarshal(v, into) == nil
	}
	var kty, crv int
	if !read(1, &kty) || !read(-1, &crv) {
		return nil, errors.New("the device key names no key type or curve")
	}
	var x []byte
	if !read(-2, &x) {
		return nil, errors.New("the device key has no x")
	}
	switch {
	case kty == 2 && crv >= 1 && crv <= 3:
		curve := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}[crv-1]
		n := (curve.Params().BitSize + 7) / 8
		if len(x) != n {
			return nil, fmt.Errorf("the device key's x is %d bytes on a curve of %d", len(x), n)
		}
		yRaw, ok := label(m, -3)
		if !ok {
			return nil, errors.New("the device key has no y")
		}
		var point []byte
		var y []byte
		var sign bool
		if mdocDecMode.Unmarshal(yRaw, &y) == nil {
			if len(y) != n {
				return nil, fmt.Errorf("the device key's y is %d bytes on a curve of %d", len(y), n)
			}
			point = append(append([]byte{4}, x...), y...)
		} else if mdocDecMode.Unmarshal(yRaw, &sign) == nil {
			prefix := byte(2)
			if sign {
				prefix = 3
			}
			px, py := elliptic.UnmarshalCompressed(curve, append([]byte{prefix}, x...))
			if px == nil {
				return nil, errors.New("the device key's compressed point is not on its curve")
			}
			// The uncompressed form of a point UnmarshalCompressed has put on the curve.
			point = elliptic.Marshal(curve, px, py)
		} else {
			return nil, errors.New("the device key's y is neither a coordinate nor a sign bit")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("the device key is not a point on its curve: %w", err)
		}
		return pub, nil
	case kty == 1 && crv == 6:
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("an Ed25519 device key that is not 32 bytes")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("a device key of type %d on curve %d, which is not one implemented here", kty, crv)
}
