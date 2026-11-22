package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"strings"
	"time"
)

// authnRequestURL is a SAML 2.0 AuthnRequest in the HTTP-Redirect binding: the request
// DEFLATE-compressed, base64-encoded and carried as SAMLRequest on the provider's single
// sign-on URL, unsigned, asking for the response by HTTP-POST at acs when acs is given.
// A fresh ID each time, so a provider that remembers the requests it answered answers
// each one.
func authnRequestURL(sso, issuer, acs string, now time.Time) (string, error) {
	var x strings.Builder
	x.WriteString(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_`)
	x.WriteString(randomString(24))
	x.WriteString(`" Version="2.0" IssueInstant="` + now.UTC().Format("2006-01-02T15:04:05Z") +
		`" Destination="` + escapeXML(sso) +
		`" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`)
	if acs != "" {
		x.WriteString(` AssertionConsumerServiceURL="` + escapeXML(acs) + `"`)
	}
	x.WriteString(`><saml:Issuer>` + escapeXML(issuer) + `</saml:Issuer></samlp:AuthnRequest>`)

	var deflated bytes.Buffer
	w, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write([]byte(x.String())); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	sep := "?"
	if strings.Contains(sso, "?") {
		sep = "&"
	}
	return sso + sep + url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(deflated.Bytes())}}.Encode(), nil
}

func escapeXML(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
