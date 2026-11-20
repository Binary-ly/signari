package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The AuthnRequest saml-sso sends, read back as a provider reads the redirect binding:
// SAMLRequest base64, then raw DEFLATE, then the request, naming the service provider,
// the provider's endpoint and where to post the answer, with an ID of its own each time.
func TestAnAuthnRequestReadsAsAProviderReadsIt(t *testing.T) {
	type authnRequest struct {
		ID          string `xml:"ID,attr"`
		Version     string `xml:"Version,attr"`
		Destination string `xml:"Destination,attr"`
		ACS         string `xml:"AssertionConsumerServiceURL,attr"`
		Binding     string `xml:"ProtocolBinding,attr"`
		Issuer      string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	}
	read := func(raw string) authnRequest {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		deflated, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
		if err != nil {
			t.Fatal(err)
		}
		var r authnRequest
		if err := xml.Unmarshal(doc, &r); err != nil {
			t.Fatalf("%v: %s", err, doc)
		}
		return r
	}
	const sso, sp, acs = "https://id.test/saml/sso?tenant=a", "urn:bench:sp", "https://sp.test/acs?x=1&y=2"
	first, err := authnRequestURL(sso, sp, acs, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, sso+"&SAMLRequest=") {
		t.Errorf("not on the endpoint's own query: %s", first)
	}
	r := read(first)
	if r.Version != "2.0" || r.Destination != sso || r.ACS != acs || r.Issuer != sp ||
		r.Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" || !strings.HasPrefix(r.ID, "_") {
		t.Errorf("read back as %+v", r)
	}
	second, _ := authnRequestURL(sso, sp, "", time.Unix(1_800_000_000, 0))
	if again := read(second); again.ID == r.ID || again.ACS != "" {
		t.Errorf("a second request reads %+v", again)
	}
}
