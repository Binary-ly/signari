package saml

import (
	"github.com/beevik/etree"
)

const (
	nsMetadata = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDsig     = "http://www.w3.org/2000/09/xmldsig#"

	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// MetadataInput is what the IdP publishes about itself.
type MetadataInput struct {
	EntityID string
	SSOURL   string
	SLOURL   string
	// Certificates, newest first. More than one is published DURING ROTATION so
	// service providers can accept both while they update -- which is the whole
	// reason rotation is survivable at all.
	Certificates [][]byte
	NameIDFormat string
}

// Metadata renders the IdP metadata document a service provider imports.
//
// # Why more than one certificate
//
// A service provider pins whatever it finds here. If we publish exactly one
// certificate and then rotate the key, every SP breaks at the moment of the
// switch, and each has to be updated by hand before it works again -- a
// coordinated outage across every integration at once.
//
// Publishing the incoming certificate ALONGSIDE the current one lets SPs pick
// up both before anything changes, so rotation becomes: publish, wait for SPs to
// refresh, switch. That is the difference between key rotation being routine and
// being something nobody ever does.
//
// The document is deliberately NOT signed. Metadata signing exists, is specified,
// and is verified by almost nothing in practice; it is also the wrong control
// here, because an SP that fetches this over HTTPS from our domain already has
// the guarantee a signature would give it.
func Metadata(in MetadataInput) (string, error) {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDsig)
	ed.CreateAttr("entityID", in.EntityID)

	idp := ed.CreateElement("md:IDPSSODescriptor")
	idp.CreateAttr("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")
	// We always sign assertions, so this is a statement of fact rather than a
	// preference. An SP reading it knows to require a signature -- and an SP that
	// requires one cannot be downgraded by an unsigned assertion later.
	idp.CreateAttr("WantAuthnRequestsSigned", "false")

	for _, der := range in.Certificates {
		kd := idp.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		ki := kd.CreateElement("ds:KeyInfo")
		xd := ki.CreateElement("ds:X509Data")
		xd.CreateElement("ds:X509Certificate").SetText(CertificateB64(der))
	}

	if in.SLOURL != "" {
		for _, b := range []string{BindingRedirect, BindingPOST} {
			slo := idp.CreateElement("md:SingleLogoutService")
			slo.CreateAttr("Binding", b)
			slo.CreateAttr("Location", in.SLOURL)
		}
	}

	format := in.NameIDFormat
	if format == "" {
		format = NameIDFormatPersistent
	}
	idp.CreateElement("md:NameIDFormat").SetText(format)

	for _, b := range []string{BindingRedirect, BindingPOST} {
		sso := idp.CreateElement("md:SingleSignOnService")
		sso.CreateAttr("Binding", b)
		sso.CreateAttr("Location", in.SSOURL)
	}

	// Indentation is safe here, unlike in a signed assertion: nothing computes a
	// digest over this document, and an operator reads it by eye when an SP
	// import goes wrong.
	doc.Indent(2)
	return doc.WriteToString()
}
