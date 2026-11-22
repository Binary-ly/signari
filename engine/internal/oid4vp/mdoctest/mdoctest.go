// Package mdoctest issues and presents ISO mdocs for tests: an IACA, a document signer
// under it, and a holder whose device signs a DeviceResponse for one request. It builds
// the structures of ISO/IEC 18013-5:2021 8.3.2.1.2.2 and 9.1.2-9.1.3 as an mdoc would,
// and each field of Doc that is not the credential itself is a fault a test asks for.
// It is used by tests only.
package mdoctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// OIDMdlDS is the document signer's extended key usage, 1.0.18013.5.1.2.
var OIDMdlDS = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}

// Issuer is an issuing authority: its IACA and one document signer under it.
type Issuer struct {
	IACA    *x509.Certificate
	IACAKey *ecdsa.PrivateKey
	DS      *x509.Certificate
	DSKey   *ecdsa.PrivateKey
}

// IssuerOptions shape the authority's two certificates.
type IssuerOptions struct {
	Country, State string
	// SignerCountry and SignerState are the document signer's, when a test wants them
	// to differ from the IACA's.
	SignerCountry, SignerState string
	// NoMdlDS leaves the mdlDS extended key usage out of the signer's certificate.
	NoMdlDS bool
	// CRL is a distribution point the signer's certificate names.
	CRL string
	// SignerNotBefore and SignerNotAfter set the signer certificate's validity.
	SignerNotBefore, SignerNotAfter time.Time
}

// NewIssuer makes an IACA and a document signer certificate as Annex B profiles them.
func NewIssuer(t testing.TB, o IssuerOptions) *Issuer {
	t.Helper()
	if o.Country == "" {
		o.Country = "UT"
	}
	if o.SignerCountry == "" {
		o.SignerCountry = o.Country
	}
	if o.SignerState == "" {
		o.SignerState = o.State
	}
	now := time.Now()
	if o.SignerNotBefore.IsZero() {
		o.SignerNotBefore = now.Add(-24 * time.Hour)
	}
	if o.SignerNotAfter.IsZero() {
		o.SignerNotAfter = now.Add(365 * 24 * time.Hour)
	}
	iacaKey, dsKey := genKey(t), genKey(t)
	name := func(cn, country, state string) pkix.Name {
		n := pkix.Name{CommonName: cn, Country: []string{country}}
		if state != "" {
			n.Province = []string{state}
		}
		return n
	}
	iacaTmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: name("Test IACA", o.Country, o.State),
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	iacaDER, err := x509.CreateCertificate(rand.Reader, iacaTmpl, iacaTmpl, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatal(err)
	}
	iaca, err := x509.ParseCertificate(iacaDER)
	if err != nil {
		t.Fatal(err)
	}
	dsTmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: name("Test DS", o.SignerCountry, o.SignerState),
		NotBefore: o.SignerNotBefore, NotAfter: o.SignerNotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if !o.NoMdlDS {
		dsTmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{OIDMdlDS}
	}
	if o.CRL != "" {
		dsTmpl.CRLDistributionPoints = []string{o.CRL}
	}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTmpl, iaca, &dsKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := x509.ParseCertificate(dsDER)
	if err != nil {
		t.Fatal(err)
	}
	return &Issuer{IACA: iaca, IACAKey: iacaKey, DS: ds, DSKey: dsKey}
}

// RootsPEM is the IACA certificate as an operator would configure it.
func (i *Issuer) RootsPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.IACA.Raw}))
}

// RootPool is the IACA alone, as a pool.
func (i *Issuer) RootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(i.IACA)
	return p
}

// Revoke is a CRL from the IACA listing its document signer.
func (i *Issuer) Revoke(t testing.TB) []byte {
	t.Helper()
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: i.DS.SerialNumber,
			RevocationTime: time.Now().Add(-time.Minute)}},
	}, i.IACA, i.IACAKey)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

// Doc is one document as a holder's mdoc holds it, and the faults a test asks for.
type Doc struct {
	DocType string
	// Elements are the issuer-signed data elements, namespace -> identifier -> value.
	Elements map[string]map[string]any
	// DeviceKey signs mdoc authentication: an *ecdsa.PrivateKey or ed25519.PrivateKey.
	DeviceKey crypto.Signer
	// CompressDeviceKey sends the EC device key's y as its sign bit.
	CompressDeviceKey bool
	// The MSO's validity; zero, signed and validFrom are an hour ago and validUntil a
	// day ahead.
	Signed, ValidFrom, ValidUntil time.Time

	// Faults.
	MSODocType       string            // the MSO says another document type
	DropDigest       string            // this element's digest is left out of the MSO
	TamperElement    string            // this element's value is changed after signing
	ShortRandom      bool              // each element's random is 8 bytes
	DuplicateElement string            // this element is returned twice
	IssuerKey        *ecdsa.PrivateKey // the MSO is signed with this rather than the signer's key
	AlgUnprotected   bool              // the issuer signature's alg is in the unprotected header only
	// DeviceSigned are elements the device signs itself, and KeyAuthorizedNameSpaces the
	// namespaces the MSO authorizes its key for.
	DeviceSigned            map[string]map[string]any
	KeyAuthorizedNameSpaces []string
	UseMAC                  bool // device authentication by a MAC
	Status                  uint64
	ExtraDocument           bool // a second document beside this one
	NoDeviceNameSpaces      bool // deviceSigned without its nameSpaces
}

// Present is the DeviceResponse a holder's mdoc answers transcript with, base64url as a
// vp_token carries it.
func (i *Issuer) Present(t testing.TB, d Doc, transcript []any) string {
	t.Helper()
	doc := i.document(t, d, transcript)
	docs := []any{doc}
	if d.ExtraDocument {
		docs = append(docs, doc)
	}
	resp := map[string]any{"version": "1.0", "documents": docs, "status": d.Status}
	raw, err := cbor.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (i *Issuer) document(t testing.TB, d Doc, transcript []any) map[string]any {
	now := time.Now()
	if d.Signed.IsZero() {
		d.Signed = now.Add(-time.Hour)
	}
	if d.ValidFrom.IsZero() {
		d.ValidFrom = d.Signed
	}
	if d.ValidUntil.IsZero() {
		d.ValidUntil = now.Add(24 * time.Hour)
	}
	randLen := 16
	if d.ShortRandom {
		randLen = 8
	}
	nameSpaces := map[string][]cbor.RawMessage{}
	digests := map[string]map[uint64][]byte{}
	var next uint64 = 7
	for ns, elements := range d.Elements {
		digests[ns] = map[uint64][]byte{}
		for id, value := range elements {
			item := func(v any) cbor.RawMessage {
				r := make([]byte, randLen)
				_, _ = rand.Read(r)
				inner := mustCBOR(t, map[string]any{"digestID": next, "random": r,
					"elementIdentifier": id, "elementValue": v})
				return mustCBOR(t, cbor.Tag{Number: 24, Content: inner})
			}
			signed := item(value)
			sum := sha256.Sum256(signed)
			if id != d.DropDigest {
				digests[ns][next] = sum[:]
			}
			sent := signed
			if id == d.TamperElement {
				// The same digestID, another value: what the issuer signed and what
				// arrives differ.
				sent = item("tampered")
			}
			nameSpaces[ns] = append(nameSpaces[ns], sent)
			if id == d.DuplicateElement {
				next++
				again := item(value)
				s := sha256.Sum256(again)
				digests[ns][next] = s[:]
				nameSpaces[ns] = append(nameSpaces[ns], again)
			}
			next += 3
		}
	}
	docType := d.DocType
	msoDocType := docType
	if d.MSODocType != "" {
		msoDocType = d.MSODocType
	}
	deviceKeyInfo := map[string]any{"deviceKey": coseKey(t, d.DeviceKey.Public(), d.CompressDeviceKey)}
	if len(d.KeyAuthorizedNameSpaces) > 0 {
		deviceKeyInfo["keyAuthorizations"] = map[string]any{"nameSpaces": d.KeyAuthorizedNameSpaces}
	}
	tdate := func(at time.Time) cbor.Tag {
		return cbor.Tag{Number: 0, Content: at.UTC().Truncate(time.Second).Format(time.RFC3339)}
	}
	mso := map[string]any{
		"version": "1.0", "digestAlgorithm": "SHA-256", "valueDigests": digests,
		"deviceKeyInfo": deviceKeyInfo, "docType": msoDocType,
		"validityInfo": map[string]any{"signed": tdate(d.Signed), "validFrom": tdate(d.ValidFrom),
			"validUntil": tdate(d.ValidUntil)},
	}
	msoBytes := mustCBOR(t, cbor.Tag{Number: 24, Content: mustCBOR(t, mso)})
	issuerKey := i.DSKey
	if d.IssuerKey != nil {
		issuerKey = d.IssuerKey
	}
	issuerAuth := sign1(t, issuerKey, -7, msoBytes, nil, map[int]any{33: i.DS.Raw}, d.AlgUnprotected)

	deviceNS := mustCBOR(t, cbor.Tag{Number: 24, Content: mustCBOR(t, orEmpty(d.DeviceSigned))})
	auth := mustCBOR(t, []any{"DeviceAuthentication", transcript, docType, cbor.RawMessage(deviceNS)})
	authBytes := mustCBOR(t, cbor.Tag{Number: 24, Content: auth})
	deviceAuth := map[string]any{}
	if d.UseMAC {
		deviceAuth["deviceMac"] = cbor.RawMessage(mustCBOR(t, []any{mustCBOR(t, map[int]int{1: 5}),
			map[int]any{}, nil, make([]byte, 32)}))
	} else {
		alg := -7
		if _, ok := d.DeviceKey.(ed25519.PrivateKey); ok {
			alg = -8
		}
		deviceAuth["deviceSignature"] = cbor.RawMessage(sign1(t, d.DeviceKey, alg, nil, authBytes, map[int]any{}, false))
	}
	deviceSigned := map[string]any{"nameSpaces": cbor.RawMessage(deviceNS), "deviceAuth": deviceAuth}
	if d.NoDeviceNameSpaces {
		delete(deviceSigned, "nameSpaces")
	}
	return map[string]any{
		"docType": docType,
		"issuerSigned": map[string]any{"nameSpaces": nameSpaces,
			"issuerAuth": cbor.RawMessage(issuerAuth)},
		"deviceSigned": deviceSigned,
	}
}

func orEmpty(m map[string]map[string]any) map[string]map[string]any {
	if m == nil {
		return map[string]map[string]any{}
	}
	return m
}

// sign1 is a COSE_Sign1 with alg in the protected header (or, as a fault, only in the
// unprotected one), over payload attached or, when detached is given, over that.
func sign1(t testing.TB, key crypto.Signer, alg int, payload, detached []byte, unprotected map[int]any,
	algUnprotected bool) []byte {
	protected := mustCBOR(t, map[int]int{1: alg})
	if algUnprotected {
		protected = mustCBOR(t, map[int]int{})
		unprotected[1] = alg
	}
	content := payload
	if detached != nil {
		content = detached
	}
	tbs := mustCBOR(t, []any{"Signature1", protected, []byte{}, content})
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(tbs)
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			t.Fatal(err)
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		sig = append(r.FillBytes(make([]byte, n)), s.FillBytes(make([]byte, n))...)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, tbs)
	default:
		t.Fatalf("a key of type %T", key)
	}
	var p any = payload
	if payload == nil {
		p = nil
	}
	return mustCBOR(t, []any{protected, unprotected, p, sig})
}

// coseKey is a public COSE_Key (EC2 P-256 or OKP Ed25519).
func coseKey(t testing.TB, pub crypto.PublicKey, compress bool) map[int]any {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		x, y := point[1:1+n], point[1+n:]
		m := map[int]any{1: 2, -1: 1, -2: x}
		if compress {
			m[-3] = y[len(y)-1]&1 == 1
		} else {
			m[-3] = y
		}
		return m
	case ed25519.PublicKey:
		return map[int]any{1: 1, -1: 6, -2: []byte(k)}
	}
	t.Fatalf("a key of type %T", pub)
	return nil
}

func genKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// DeviceKey is a P-256 device key.
func DeviceKey(t testing.TB) *ecdsa.PrivateKey { return genKey(t) }

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 70))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func mustCBOR(t testing.TB, v any) []byte {
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
