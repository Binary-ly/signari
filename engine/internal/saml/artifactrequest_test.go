package saml

import (
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// The request half by artifact: this deployment holds the artifact and asks the
// service provider that issued it for the message.

// What this deployment sends reads back as the ArtifactResolve it is, signed by the key
// it was made with, which is the reader the artifact resolution service here uses.
func TestAnArtifactResolveSentIsSignedAndReadable(t *testing.T) {
	key, certDER := testSigner(t)
	envelope, id, err := BuildArtifactResolve(ArtifactResolveInput{
		Issuer: "https://auth.example.com/saml", Destination: "https://sp.example.com/ars",
		Artifact: "AAQAAA==", Now: time.Now(),
	}, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ReadArtifactResolve([]byte(envelope))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != id || r.Issuer != "https://auth.example.com/saml" || r.Artifact != "AAQAAA==" ||
		r.Destination != "https://sp.example.com/ars" {
		t.Fatalf("read back %+v, id %s", r, id)
	}
	if err := r.VerifySignature(certPEM(certDER)); err != nil {
		t.Fatalf("its own signature: %v", err)
	}
}

// signedAuthnRequest is an AuthnRequest a service provider signed on its own, as it
// would before handing it out by artifact.
func signedAuthnRequest(t *testing.T, key *rsa.PrivateKey, certDER []byte, id string) string {
	t.Helper()
	doc := etree.NewDocument()
	el := doc.CreateElement("samlp:AuthnRequest")
	el.CreateAttr("xmlns:samlp", nsProtocol)
	el.CreateAttr("xmlns:saml", nsAssertion)
	el.CreateAttr("ID", id)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	el.CreateElement("saml:Issuer").SetText("https://sp.example.com/metadata")
	signed, err := signElement(el, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := moveSignatureAfterIssuer(signed); err != nil {
		t.Fatal(err)
	}
	doc.SetRoot(signed)
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The message comes back out as a document of its own whose signature still verifies,
// when the provider declared the namespaces it uses only on the ArtifactResponse
// around it, and the answer's own signature is told from a forged one.
func TestAnArtifactResponseGivesBackTheMessageItCarries(t *testing.T) {
	rsaKey, certDER := testSigner(t)
	inner := signedAuthnRequest(t, rsaKey, certDER, "_authn42")

	// The answer as a provider might write it: the request's own declarations moved
	// up to the ArtifactResponse, as a serialiser dropping redundant ones does.
	moved := inner
	for _, decl := range []string{` xmlns:samlp="` + nsProtocol + `"`, ` xmlns:saml="` + nsAssertion + `"`} {
		before := moved
		if moved = strings.Replace(moved, decl, "", 1); moved == before {
			t.Fatalf("the request does not declare%s where this test expects it:\n%s", decl, inner)
		}
	}
	answer := SOAPEnvelope(`<samlp:ArtifactResponse xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion +
		`" ID="_ar1" InResponseTo="_resolve9" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) +
		`"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="` +
		StatusSuccess + `"/></samlp:Status>` + moved + `</samlp:ArtifactResponse>`)

	r, err := ReadArtifactResponse([]byte(answer))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "_ar1" || r.InResponseTo != "_resolve9" || r.Issuer != "https://sp.example.com/metadata" ||
		r.StatusCode != StatusSuccess {
		t.Fatalf("read %+v", r)
	}
	if err := VerifyEmbeddedSignature(r.Message, certPEM(certDER), "AuthnRequest", "_authn42"); err != nil {
		t.Fatalf("the request lifted out of the answer no longer verifies: %v\n%s", err, r.Message)
	}
	_, otherCert := testSigner(t)
	if err := VerifyEmbeddedSignature(r.Message, certPEM(otherCert), "AuthnRequest", "_authn42"); err == nil {
		t.Error("the lifted request verified against a certificate that did not sign it")
	}

	// A provider that signs its answer as well, around the request it signed: two
	// signatures in the document, which is read all the same, and the request lifted
	// out of it has only its own.
	signedAnswer, err := BuildArtifactResponse(ArtifactResponseInput{Issuer: "https://sp.example.com/metadata",
		InResponseTo: "_resolve9", Now: time.Now()}, inner, rsaKey, certDER)
	if err != nil {
		t.Fatal(err)
	}
	r, err = ReadArtifactResponse([]byte(signedAnswer))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEmbeddedSignature(r.Message, certPEM(certDER), "AuthnRequest", "_authn42"); err != nil {
		t.Fatalf("the request lifted out of a signed answer: %v", err)
	}
	tampered := strings.Replace(string(r.Message), "https://sp.example.com/metadata", "https://evil.example.com/metadata", 1)
	if tampered == string(r.Message) {
		t.Fatal("the lifted request does not name its issuer where this test expects")
	}
	if VerifyEmbeddedSignature([]byte(tampered), certPEM(certDER), "AuthnRequest", "_authn42") == nil {
		t.Error("a request changed after it was signed verified")
	}
}

// An answer with nothing in it is how a provider says the artifact was never its, was
// given out already, or is not for this deployment, and reads as no message.
func TestAnArtifactResponseWithNoMessageIsNoMessage(t *testing.T) {
	answer := SOAPEnvelope(`<samlp:ArtifactResponse xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion +
		`" ID="_ar2" InResponseTo="_r" Version="2.0" IssueInstant="2026-11-05T00:00:00Z"><saml:Issuer>sp</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status></samlp:ArtifactResponse>`)
	r, err := ReadArtifactResponse([]byte(answer))
	if err != nil {
		t.Fatal(err)
	}
	if r.Message != nil {
		t.Errorf("an empty answer carried %s", r.Message)
	}
	two := strings.Replace(answer, "</samlp:Status>", `</samlp:Status><samlp:AuthnRequest ID="a"/><samlp:AuthnRequest ID="b"/>`, 1)
	if _, err := ReadArtifactResponse([]byte(two)); err == nil {
		t.Error("an answer carrying two messages was read")
	}
	noIssuer := strings.Replace(answer, "<saml:Issuer>sp</saml:Issuer>", "", 1)
	if _, err := ReadArtifactResponse([]byte(noIssuer)); err == nil {
		t.Error("an answer naming no Issuer was read")
	}
}
