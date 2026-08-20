package saml

import (
	"crypto"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// signElementSHA1 is signElement with SHA-1, for probing what we ACCEPT.
func signElementSHA1(el *etree.Element, key *rsa.PrivateKey, certDER []byte) (*etree.Element, error) {
	ctx := &dsig.SigningContext{
		Hash:          crypto.SHA1,
		KeyStore:      staticKeyStore{key: key, cert: certDER},
		IdAttribute:   "ID",
		Prefix:        "ds",
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}
	if err := ctx.SetSignatureMethod(dsig.RSASHA1SignatureMethod); err != nil {
		return nil, err
	}
	return ctx.SignEnveloped(el)
}

// An inbound assertion signed with RSA-SHA1 must be refused.
//
// NIST SP 800-131A disallows SHA-1 for digital signature generation and
// deprecates it for verification. The restriction is OURS: goxmldsig registers
// RSASHA1SignatureMethod in its algorithm map and NewDefaultValidationContext
// does not exclude it, so an implementation that simply uses the library's
// default accepts SHA-1 signatures without ever deciding to.
//
// Asserted rather than logged, because a refusal that exists only in a
// dependency's configuration is one dependency upgrade away from disappearing.
func TestInboundRSASHA1SignaturesAreRefused(t *testing.T) {
	u := newUpstream(t)

	// A fresh element per signature. signElement and signElementSHA1 both APPEND
	// a ds:Signature child to what they are given, so reusing one across both
	// calls silently signs a document that already carries a signature — which
	// fails for a reason that has nothing to do with the algorithm.
	fresh := func() *etree.Element {
		d := etree.NewDocument()
		r := d.CreateElement("Assertion")
		r.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:assertion")
		r.CreateAttr("ID", "_probe")
		r.CreateElement("Issuer").SetText("https://upstream-idp.test")
		return r
	}

	signed, err := signElementSHA1(fresh(), u.key, u.certDER)
	if err != nil {
		t.Fatalf("could not build an RSA-SHA1 signature: %v", err)
	}

	// Round-tripped through bytes, the way a real message arrives. Copying an
	// element between documents loses the namespace context canonicalisation
	// depends on, which fails the signature for a reason unrelated to what is
	// under test.
	probe := reparse(t, signed)
	out, verr := verifySignedElement(probe, probe.Root(), u.certPEM, "Assertion", "_probe")

	if verr == nil && out != nil {
		t.Fatal("an RSA-SHA1 inbound signature verified. SHA-1 is broken for " +
			"collisions and NIST SP 800-131A deprecates it for verification; " +
			"goxmldsig's default validation context accepts it, so this refusal " +
			"has to be ours and has to stay ours")
	}
	// And the refusal must name the algorithm, because the operator's fix is on
	// the other side of the federation and they need to know what to ask for.
	if !strings.Contains(verr.Error(), "rsa-sha1") {
		t.Errorf("the refusal does not name the algorithm: %v", verr)
	}

	// The counterpart: RSA-SHA256 must still verify, or this is not a
	// restriction, it is an outage.
	good, err := signElement(fresh(), u.key, u.certDER)
	if err != nil {
		t.Fatal(err)
	}
	okDoc := reparse(t, good)
	if _, err := verifySignedElement(okDoc, okDoc.Root(), u.certPEM, "Assertion", "_probe"); err != nil {
		t.Errorf("an RSA-SHA256 signature was refused: %v", err)
	}
}

// reparse serialises a signed element and reads it back, as an inbound message is.
func reparse(t *testing.T, el *etree.Element) *etree.Document {
	t.Helper()
	out := etree.NewDocument()
	out.SetRoot(el)
	raw, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	back := etree.NewDocument()
	if err := back.ReadFromString(raw); err != nil {
		t.Fatal(err)
	}
	return back
}
