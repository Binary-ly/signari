package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"
)

type issuerDoc struct {
	XMLName xml.Name
	Issuer  string `xml:"Issuer"`
}

func deflate64(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// TestCommentTruncationIsRefused is the CVE-2017-11427 class.
//
// Go concatenates the text either side of a comment, so this document parses as
// `admin@evil.test`. Exclusive canonicalisation drops the comment before the
// digest is computed, and other implementations keep only the first text node --
// so the signed bytes, our value, and the peer's value can all be different.
// The whole class is refused rather than reconciled.
func TestCommentTruncationIsRefused(t *testing.T) {
	doc := []byte(`<AuthnRequest><Issuer>admin<!---->@evil.test</Issuer></AuthnRequest>`)

	// First, prove the danger is real in this Go version rather than assuming it.
	var unguarded issuerDoc
	if err := xml.Unmarshal(doc, &unguarded); err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	if unguarded.Issuer != "admin@evil.test" {
		t.Fatalf("this Go version parses the comment fixture as %q; the test fixture "+
			"no longer demonstrates the attack and needs revisiting", unguarded.Issuer)
	}

	var guarded issuerDoc
	err := Unmarshal(doc, &guarded)
	if err == nil {
		t.Fatal("a document using comment truncation was accepted")
	}
	if !strings.Contains(err.Error(), "comment") {
		t.Errorf("error should name the construct refused; got %v", err)
	}
}

func TestPlainDocumentStillParses(t *testing.T) {
	var d issuerDoc
	if err := Unmarshal([]byte(`<AuthnRequest><Issuer>sp.example.com</Issuer></AuthnRequest>`), &d); err != nil {
		t.Fatalf("a legitimate document was refused: %v", err)
	}
	if d.Issuer != "sp.example.com" {
		t.Errorf("Issuer = %q", d.Issuer)
	}
}

func TestDoctypeIsRefused(t *testing.T) {
	doc := []byte(`<!DOCTYPE r [<!ENTITY x "y">]><AuthnRequest><Issuer>sp</Issuer></AuthnRequest>`)
	var d issuerDoc
	if err := Unmarshal(doc, &d); err == nil {
		t.Fatal("a document with a DOCTYPE was accepted")
	}
}

// TestExternalEntityIsRefused pins Go's own behaviour.
//
// Go rejects external entities today, which is why no unescaping code is needed
// here. That is a property this package DEPENDS on, so it is asserted rather
// than assumed -- if a future Go relaxed it, this fails loudly instead of
// quietly becoming a file-disclosure bug.
func TestExternalEntityIsRefused(t *testing.T) {
	doc := []byte(`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` +
		`<AuthnRequest><Issuer>&x;</Issuer></AuthnRequest>`)
	var d issuerDoc
	if err := Unmarshal(doc, &d); err == nil {
		t.Fatal("a document with an external entity was accepted")
	}
	if strings.Contains(d.Issuer, "root:") {
		t.Fatal("an external entity was RESOLVED: this is file disclosure")
	}
}

// TestEntityExpansionIsRefused covers the billion-laughs shape.
func TestEntityExpansionIsRefused(t *testing.T) {
	doc := []byte(`<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>` +
		`<AuthnRequest><Issuer>&b;</Issuer></AuthnRequest>`)
	var d issuerDoc
	if err := Unmarshal(doc, &d); err == nil {
		t.Fatal("a document with nested entity definitions was accepted")
	}
}

// TestDeflateBombIsRefused is the DoS that hit both crewjam/saml and gosaml2.
//
// The assertion that matters is not just "an error came back" -- it is that the
// bound is enforced during the read, so the process never allocates the
// expanded document. A version that inflates first and measures afterwards
// passes a naive test and still falls over.
func TestDeflateBombIsRefused(t *testing.T) {
	// 8 MiB of zeroes compresses to a few kilobytes.
	bomb := deflate64(t, strings.Repeat("A", 8<<20))
	if len(bomb) > maxEncoded {
		t.Fatalf("the compressed bomb is %d bytes, over maxEncoded, so this would be "+
			"rejected on length alone and would not exercise the inflate bound", len(bomb))
	}

	out, err := DecodeRedirect(bomb)
	if err == nil {
		t.Fatalf("an 8 MiB deflate bomb was accepted, yielding %d bytes", len(out))
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error should name the limit; got %v", err)
	}
}

// TestOversizedEncodedInputIsRefusedBeforeDecoding -- the cheapest check has to
// come first, or the expensive ones are reachable by anyone.
func TestOversizedEncodedInputIsRefusedBeforeDecoding(t *testing.T) {
	if _, err := DecodeRedirect(strings.Repeat("A", maxEncoded+1)); err == nil {
		t.Error("an oversized encoded message was accepted")
	}
	if _, err := DecodePOST(strings.Repeat("A", maxEncoded+1)); err == nil {
		t.Error("an oversized POST message was accepted")
	}
}

func TestRedirectRoundTrip(t *testing.T) {
	want := `<AuthnRequest><Issuer>sp.example.com</Issuer></AuthnRequest>`
	got, err := DecodeRedirect(deflate64(t, want))
	if err != nil {
		t.Fatalf("a legitimate redirect-binding message was refused: %v", err)
	}
	if string(got) != want {
		t.Errorf("round trip = %q", got)
	}
}

func TestGarbageIsRefused(t *testing.T) {
	if _, err := DecodeRedirect("!!!not base64!!!"); err == nil {
		t.Error("non-base64 was accepted")
	}
	// Valid base64, not valid DEFLATE.
	if _, err := DecodeRedirect(base64.StdEncoding.EncodeToString([]byte("plain text"))); err == nil {
		t.Error("undecompressable input was accepted")
	}
}

// FuzzUnmarshal looks for inputs that panic rather than return an error. A
// panic in a handler is an unauthenticated crash, which is how gosaml2's
// GHSA-hwqm-qvj9-4jr2 was reported.
func FuzzUnmarshal(f *testing.F) {
	f.Add([]byte(`<AuthnRequest><Issuer>sp</Issuer></AuthnRequest>`))
	f.Add([]byte(`<AuthnRequest><Issuer>a<!---->b</Issuer></AuthnRequest>`))
	f.Add([]byte(`<!DOCTYPE r><A/>`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, doc []byte) {
		var d issuerDoc
		_ = Unmarshal(doc, &d)
	})
}
