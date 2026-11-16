package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"signari.dev/engine/internal/oid4vp/mdoctest"
)

// A wallet's answer is posted by anybody holding a live request's state. An mdoc
// DeviceResponse is CBOR of the wallet's choosing, read before any signature in it is
// known good: whatever its bytes, the verifier ends in a refusal and does not panic, and
// with no IACA nobody's document is believed.
func FuzzVerifyMdoc(f *testing.F) {
	f.Add([]byte{0xa3, 0x67, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x63, '1', '.', '0', 0x66, 's', 't', 'a',
		't', 'u', 's', 0x00, 0x69, 'd', 'o', 'c', 'u', 'm', 'e', 'n', 't', 's', 0x80})
	f.Add([]byte{0xd8, 0x18, 0x41, 0xa0})
	f.Add([]byte{0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0xf6, 0x40})
	f.Add([]byte{0xbf, 0xff})
	f.Add([]byte{})
	roots := mdoctest.NewIssuer(f, mdoctest.IssuerOptions{Country: "UT"}).RootPool()
	e := Expect{ClientID: "x509_san_dns:verifier.example", Nonce: "n", ResponseURI: "https://verifier.example/r",
		Ask: Ask{ID: "credential", Format: FormatMdoc, DocType: MdocDocType}, MdocRoots: roots, Now: time.Now()}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if p, err := verifyMdoc(base64.RawURLEncoding.EncodeToString(raw), e); err == nil {
			t.Fatalf("believed a document from bytes nobody signed: %+v", p)
		}
	})
}

// A wallet's answer through the Digital Credentials API is JSON the page posts; reading
// it ends in a token, a refusal or an error.
func FuzzReadDCAPIAnswer(f *testing.F) {
	for _, s := range []string{`{"vp_token":{"credential":["x"]}}`, `{"response":"a.b.c.d.e"}`,
		`{"error":"access_denied"}`, `{}`, `[]`, ``} {
		f.Add([]byte(s))
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadDCAPIAnswer(data, nil, "kid")
		_, _, _ = ReadDCAPIAnswer(data, key, "kid")
	})
}

// A claims path is an operator's, but the mdoc and SD-JWT paths are selected against a
// credential a wallet sent; parsing and selecting end in a value or an error.
func FuzzParsePath(f *testing.F) {
	for _, s := range []string{`["address","country"]`, `["degrees",null,"type"]`, `["a",0]`, `name`, `[`, `[-1]`, ``} {
		f.Add(s)
	}
	credential := map[string]any{"address": map[string]any{"country": "UT"}, "degrees": []any{map[string]any{"type": "BSc"}}}
	f.Fuzz(func(t *testing.T, s string) {
		if p, err := ParsePath(s); err == nil {
			_, _ = Select(credential, p)
		}
	})
}
