package saml

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestMetadataIsWellFormedAndComplete(t *testing.T) {
	_, certDER := testSigner(t)
	out, err := Metadata(MetadataInput{
		EntityID:     "https://auth.example.com/saml",
		SSOURL:       "https://auth.example.com/saml/sso",
		SLOURL:       "https://auth.example.com/saml/slo",
		Certificates: [][]byte{certDER},
	})
	if err != nil {
		t.Fatal(err)
	}

	// It must PARSE. Metadata a service provider cannot read is the most common
	// first-contact failure, and it is trivially checkable.
	var probe struct{}
	if err := xml.Unmarshal([]byte(out), &probe); err != nil {
		t.Fatalf("metadata is not well-formed XML: %v\n%s", err, out)
	}

	for _, want := range []string{
		`entityID="https://auth.example.com/saml"`,
		`<md:IDPSSODescriptor`,
		`<ds:X509Certificate>`,
		`Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"`,
		`Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`,
		`Location="https://auth.example.com/saml/sso"`,
		`<md:SingleLogoutService`,
		`nameid-format:persistent`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metadata is missing %s", want)
		}
	}
}

// TestMetadataPublishesEveryCertificate is what makes key rotation survivable:
// service providers must be able to pick up the next certificate BEFORE it
// starts being used, or every integration breaks at the moment of the switch.
func TestMetadataPublishesEveryCertificate(t *testing.T) {
	_, a := testSigner(t)
	_, b := testSigner(t)
	out, err := Metadata(MetadataInput{
		EntityID:     "https://auth.example.com/saml",
		SSOURL:       "https://auth.example.com/saml/sso",
		Certificates: [][]byte{a, b},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "<ds:X509Certificate>"); n != 2 {
		t.Errorf("published %d certificates, want 2: an SP cannot pre-load the "+
			"incoming key, so rotation would break every integration at once", n)
	}
}

func TestMetadataOmitsLogoutWhenThereIsNone(t *testing.T) {
	_, certDER := testSigner(t)
	out, _ := Metadata(MetadataInput{
		EntityID:     "https://auth.example.com/saml",
		SSOURL:       "https://auth.example.com/saml/sso",
		Certificates: [][]byte{certDER},
	})
	if strings.Contains(out, "SingleLogoutService") {
		t.Error("advertised a logout endpoint that does not exist; an SP would call it " +
			"and fail -- the same 'advertise only what works' rule as OIDC discovery")
	}
}
