package saml

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

func TestAnECPRequestIsReadFromItsSOAPBody(t *testing.T) {
	body := `<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Header/><S:Body>` +
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_e1" Version="2.0" IssueInstant="` +
		time.Now().UTC().Format(time.RFC3339) + `" AssertionConsumerServiceURL="https://sp.example.com/ecp" ` +
		`ProtocolBinding="` + BindingPAOS + `"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer>` +
		`</samlp:AuthnRequest></S:Body></S:Envelope>`
	in, err := ReadECPRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	r := in.Request
	if r.ID != "_e1" || r.Issuer != "https://sp.example.com/metadata" || r.ProtocolBinding != BindingPAOS ||
		r.AssertionConsumerServiceURL != "https://sp.example.com/ecp" {
		t.Errorf("read %+v", r)
	}
	if err := in.VerifySignature(""); err == nil {
		t.Error("an unsigned request was taken as signed")
	}
	for name, bad := range map[string]string{
		"not SOAP":        strings.Replace(body, "http://schemas.xmlsoap.org/soap/envelope/", "urn:other", 1),
		"a DOCTYPE":       `<!DOCTYPE x>` + body,
		"two bodies":      strings.Replace(body, "</S:Body>", "</S:Body><S:Body/>", 1),
		"no AuthnRequest": strings.Replace(body, "samlp:AuthnRequest", "samlp:LogoutRequest", 2),
	} {
		if _, err := ReadECPRequest([]byte(bad)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// The header the profile requires of the identity provider's answer
// (saml-profiles-2.0-os lines 1005-1012), and the response untouched beneath it.
func TestTheECPAnswerCarriesItsHeader(t *testing.T) {
	out := ECPEnvelope(`https://sp.example.com/ecp?a=1&b=2`, `<samlp:Response ID="_r"/>`)
	var env struct {
		Header struct {
			Response struct {
				MustUnderstand string `xml:"http://schemas.xmlsoap.org/soap/envelope/ mustUnderstand,attr"`
				Actor          string `xml:"http://schemas.xmlsoap.org/soap/envelope/ actor,attr"`
				ACS            string `xml:"AssertionConsumerServiceURL,attr"`
			} `xml:"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp Response"`
		} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`
	}
	if err := xml.Unmarshal([]byte(strings.Replace(out, "<samlp:Response", `<samlp:Response xmlns:samlp="urn:x"`, 1)), &env); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	h := env.Header.Response
	if h.MustUnderstand != "1" || h.Actor != "http://schemas.xmlsoap.org/soap/actor/next" ||
		h.ACS != "https://sp.example.com/ecp?a=1&b=2" {
		t.Errorf("header %+v", h)
	}
	if !strings.Contains(out, `<soap11:Body><samlp:Response ID="_r"/></soap11:Body>`) {
		t.Errorf("the response is not carried as it was:\n%s", out)
	}
}

func TestTheMetadataNamesTheECPService(t *testing.T) {
	_, certDER := testSigner(t)
	doc, err := Metadata(MetadataInput{EntityID: "https://auth.example.com/saml",
		SSOURL: "https://auth.example.com/saml/sso", ECPURL: "https://auth.example.com/saml/ecp",
		Certificates: [][]byte{certDER}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, `Binding="`+BindingSOAP+`" Location="https://auth.example.com/saml/ecp"`) {
		t.Errorf("no SOAP sign-on service:\n%s", doc)
	}
}

func TestAProvidersPAOSEndpointIsRead(t *testing.T) {
	signer := newPartner(t)
	key := newPartner(t)
	const entity = "https://sp.example.test/saml"
	doc := strings.Replace(spEntity(entity, key.cert, ""), "</md:SPSSODescriptor>",
		`<md:AssertionConsumerService index="9" Binding="`+BindingPAOS+`" Location="https://sp.example.test/ecp"/>`+
			"</md:SPSSODescriptor>", 1)
	got, err := ReadMetadata(MetadataSource{Document: signed(t, signer, doc), SignerPEM: signer.pem, EntityID: entity})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SP.ECPACSURLs) != 1 || got.SP.ECPACSURLs[0] != "https://sp.example.test/ecp" {
		t.Errorf("PAOS endpoints %v", got.SP.ECPACSURLs)
	}
}
