package oid4vp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oid4vp/mdoctest"
)

// OID4VP's own examples of the handover and the SessionTranscript, byte for byte, for a
// request by redirect (specs/oid4vp.txt:3255-3330) and through the Digital Credentials
// API (:3402-3440). The JWK's thumbprint is the third element of each (RFC 7638 over the
// required members only, so its use, alg and kid change nothing).
func TestTheSessionTranscriptIsOID4VPs(t *testing.T) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(`{"kty":"EC","crv":"P-256","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",`+
		`"y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc","use":"enc","alg":"ECDH-ES","kid":"1"}`), &jwk); err != nil {
		t.Fatal(err)
	}
	const nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
	for name, c := range map[string]struct {
		e    Expect
		want string
	}{
		"redirect": {Expect{ClientID: "x509_san_dns:example.com", Nonce: nonce,
			ResponseURI: "https://example.com/response", EncryptedTo: &jwk},
			"83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"},
		"dc api": {Expect{Origin: "https://example.com", Nonce: nonce, EncryptedTo: &jwk},
			"83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"},
	} {
		transcript, err := SessionTranscript(c.e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := cbor.Marshal(transcript)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%s: SessionTranscript %x, want %s", name, got, c.want)
		}
	}
}

type mdocFixture struct {
	issuer *mdoctest.Issuer
	e      Expect
}

func newMdocFixture(t *testing.T) *mdocFixture {
	t.Helper()
	is := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT", State: "NORTH"})
	return &mdocFixture{issuer: is, e: Expect{
		ClientID: "x509_san_dns:verifier.example", Nonce: "n-" + rand.Text(), ResponseURI: "https://verifier.example/oid4vp/r",
		Ask: Ask{ID: "credential", Format: FormatMdoc, DocType: MdocDocType,
			Claims: []Path{{"org.iso.18013.5.1", "document_number"}, {"org.iso.18013.5.1", "family_name"}}},
		MdocRoots: is.RootPool(), Now: time.Now(),
	}}
}

func (f *mdocFixture) doc(t *testing.T) mdoctest.Doc {
	return mdoctest.Doc{DocType: MdocDocType, DeviceKey: mdoctest.DeviceKey(t),
		Elements: map[string]map[string]any{"org.iso.18013.5.1": {
			"document_number": "D1234567", "family_name": "Lovelace",
			"birth_date": cbor.Tag{Number: 1004, Content: "1815-12-10"}, "age_over_18": true}}}
}

func (f *mdocFixture) present(t *testing.T, d mdoctest.Doc, e Expect) string {
	transcript, err := SessionTranscript(e)
	if err != nil {
		t.Fatal(err)
	}
	return token("credential", f.issuer.Present(t, d, transcript))
}

func TestAnMdocIsAccepted(t *testing.T) {
	f := newMdocFixture(t)
	got, err := Verify(f.present(t, f.doc(t), f.e), f.e)
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "mdoc:"+MdocDocType+":UT-NORTH" || got.VCT != MdocDocType {
		t.Errorf("issuer %q, type %q", got.Issuer, got.VCT)
	}
	el := got.Claims["org.iso.18013.5.1"].(map[string]any)
	if el["document_number"] != "D1234567" || el["family_name"] != "Lovelace" ||
		el["birth_date"] != "1815-12-10" || el["age_over_18"] != true {
		t.Errorf("elements %v", el)
	}
	if sel, err := Select(got.Claims, Path{"org.iso.18013.5.1", "document_number"}); err != nil || sel[0] != "D1234567" {
		t.Errorf("the claims path selects %v, %v", sel, err)
	}

	// The device key as an Ed25519 key, and as a compressed P-256 point.
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, edit := range map[string]func(*mdoctest.Doc){
		"ed25519":    func(d *mdoctest.Doc) { d.DeviceKey = edKey },
		"compressed": func(d *mdoctest.Doc) { d.CompressDeviceKey = true },
		"authorized device element": func(d *mdoctest.Doc) {
			d.DeviceSigned = map[string]map[string]any{"org.example.device": {"nickname": "x"}}
			d.KeyAuthorizedNameSpaces = []string{"org.example.device"}
		},
	} {
		d := f.doc(t)
		edit(&d)
		if _, err := Verify(f.present(t, d, f.e), f.e); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every check refuses what it is for. Each case changes one thing, and the error is
// held to name it, so a case that fails for some other reason is caught.
func TestAnMdocIsRefused(t *testing.T) {
	f := newMdocFixture(t)
	other := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT", State: "NORTH"})
	for name, c := range map[string]struct {
		doc    func(*mdoctest.Doc)
		expect func(*Expect)
		issuer *mdoctest.Issuer
		want   string
	}{
		"another IACA":            {issuer: other, want: "document signer certificate"},
		"tampered element":        {doc: func(d *mdoctest.Doc) { d.TamperElement = "family_name" }, want: "not what the issuer signed"},
		"element nobody digested": {doc: func(d *mdoctest.Doc) { d.DropDigest = "family_name" }, want: "did not sign"},
		"another document type":   {doc: func(d *mdoctest.Doc) { d.MSODocType = "org.example.other" }, want: "issuer signed"},
		"short random":            {doc: func(d *mdoctest.Doc) { d.ShortRandom = true }, want: "random"},
		"element twice":           {doc: func(d *mdoctest.Doc) { d.DuplicateElement = "family_name" }, want: "twice"},
		"issuer key not the signer's": {doc: func(d *mdoctest.Doc) { d.IssuerKey = mdoctest.DeviceKey(t) },
			want: "issuer's signature"},
		"alg unsigned":    {doc: func(d *mdoctest.Doc) { d.AlgUnprotected = true }, want: "names no algorithm"},
		"expired":         {doc: func(d *mdoctest.Doc) { d.ValidUntil = time.Now().Add(-time.Hour) }, want: "valid until"},
		"not yet valid":   {doc: func(d *mdoctest.Doc) { d.ValidFrom = time.Now().Add(time.Hour) }, want: "not valid until"},
		"signed too soon": {doc: func(d *mdoctest.Doc) { d.Signed = time.Now().Add(-72 * time.Hour) }, want: "outside its signer"},
		"another nonce": {expect: func(e *Expect) { e.Nonce = "another" },
			want: "device's signature over this request"},
		"another verifier": {expect: func(e *Expect) { e.ClientID = "x509_san_dns:other.example" },
			want: "device's signature over this request"},
		"another response uri": {expect: func(e *Expect) { e.ResponseURI = "https://other.example/r" },
			want: "device's signature over this request"},
		"a MAC": {doc: func(d *mdoctest.Doc) { d.UseMAC = true }, want: "MAC"},
		"unauthorized device element": {doc: func(d *mdoctest.Doc) {
			d.DeviceSigned = map[string]map[string]any{"org.example.device": {"nickname": "x"}}
		}, want: "not authorized"},
		"no device namespaces": {doc: func(d *mdoctest.Doc) { d.NoDeviceNameSpaces = true }, want: "DeviceNameSpaces"},
		"status not OK":        {doc: func(d *mdoctest.Doc) { d.Status = 10 }, want: "OK"},
		"two documents":        {doc: func(d *mdoctest.Doc) { d.ExtraDocument = true }, want: "2 documents"},
		"a claim it lacks": {doc: func(d *mdoctest.Doc) {
			delete(d.Elements["org.iso.18013.5.1"], "family_name")
		}, want: "family_name"},
		"no roots": {expect: func(e *Expect) { e.MdocRoots = nil }, want: "believes no IACA"},
	} {
		t.Run(name, func(t *testing.T) {
			d := f.doc(t)
			if c.doc != nil {
				c.doc(&d)
			}
			signed := f.e // what the device signs over
			check := f.e  // what the verifier holds it to
			if c.expect != nil {
				c.expect(&check)
				if check.MdocRoots == nil {
					signed = check
				}
			}
			is := f.issuer
			if c.issuer != nil {
				is = c.issuer
			}
			transcript, err := SessionTranscript(signed)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(token("credential", is.Present(t, d, transcript)), check)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want an error naming %q", err, c.want)
			}
		})
	}
}

// The signer's certificate is held to the document signer profile and its IACA: the
// mdlDS extended key usage, the IACA's country and state, and a CRL that lists it.
func TestAnMdocSignerIsHeldToItsIACA(t *testing.T) {
	for name, c := range map[string]struct {
		o    mdoctest.IssuerOptions
		want string
	}{
		"no mdlDS":        {mdoctest.IssuerOptions{Country: "UT", NoMdlDS: true}, "mdlDS"},
		"another country": {mdoctest.IssuerOptions{Country: "UT", SignerCountry: "XX"}, "country"},
		"another state":   {mdoctest.IssuerOptions{Country: "UT", State: "NORTH", SignerState: "SOUTH"}, "state"},
	} {
		is := mdoctest.NewIssuer(t, c.o)
		f := newMdocFixture(t)
		f.issuer, f.e.MdocRoots = is, is.RootPool()
		if _, err := Verify(f.present(t, f.doc(t), f.e), f.e); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error naming %q", name, err, c.want)
		}
	}

	is := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT", CRL: "https://iaca.example/crl"})
	f := newMdocFixture(t)
	f.issuer, f.e.MdocRoots = is, is.RootPool()
	vp := f.present(t, f.doc(t), f.e)
	if _, err := Verify(vp, f.e); err == nil || !strings.Contains(err.Error(), "CRL") {
		t.Errorf("a signer naming a CRL with no way to read it: %v", err)
	}
	asked := 0
	f.e.Fetch = func(uri, accept string) ([]byte, string, error) {
		asked++
		return is.Revoke(t), CRLMedia, nil
	}
	if _, err := Verify(vp, f.e); err == nil || !strings.Contains(err.Error(), "revoked") || asked != 1 {
		t.Errorf("a revoked signer: %v (CRL asked %d times)", err, asked)
	}
}

// An mdoc ask is what OID4VP says an mdoc query is, and the request names the formats
// and algorithms this verifier checks.
func TestAnMdocQueryIsWhatOID4VPSays(t *testing.T) {
	a := Ask{ID: "credential", Format: FormatMdoc, DocType: MdocDocType,
		Claims: []Path{{"org.iso.18013.5.1", "document_number"}}}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	q, _ := json.Marshal(a.Query())
	if want := `{"credentials":[{"claims":[{"path":["org.iso.18013.5.1","document_number"]}],"format":"mso_mdoc",` +
		`"id":"credential","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}`; string(q) != want {
		t.Errorf("query %s", q)
	}
	meta, _ := json.Marshal(Request{Ask: a}.metadata())
	if !strings.Contains(string(meta), `"mso_mdoc":{"deviceauth_alg_values":[-7,-35,-36,-8],"issuerauth_alg_values":[-7,-35,-36,-8]}`) ||
		strings.Contains(string(meta), "sd-jwt") {
		t.Errorf("client_metadata %s", meta)
	}
	for name, bad := range map[string]Ask{
		"no doctype":        {ID: "c", Format: FormatMdoc},
		"vct_values":        {ID: "c", Format: FormatMdoc, DocType: MdocDocType, VCTValues: []string{"x"}},
		"one-part path":     {ID: "c", Format: FormatMdoc, DocType: MdocDocType, Claims: []Path{{"family_name"}}},
		"index in a path":   {ID: "c", Format: FormatMdoc, DocType: MdocDocType, Claims: []Path{{"ns", 0}}},
		"an unknown format": {ID: "c", Format: "jwt_vc_json", VCTValues: []string{"x"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
