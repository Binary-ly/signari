package saml

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// VerifyEmbeddedSignature checks the XML signature on a document that arrived by
// the HTTP-POST binding.
//
// # Why this is not simply a call to goxmldsig
//
// goxmldsig verifies the cryptography correctly. It does not make the policy
// decisions that turn "a valid signature exists in this document" into "THIS
// document is authentic", and the gap between those two statements is signature
// wrapping -- the single most common way a SAML implementation is bypassed.
//
// Three of its behaviours are safe in isolation and unsafe as a whole:
//
//   - findSignature TRAVERSES the tree. A signature nested anywhere inside the
//     document can satisfy it, so an attacker may keep a genuine signed fragment
//     and graft their own content around it.
//   - a Reference URI of "" is accepted, meaning "the whole document" -- which is
//     not a statement about the element we parsed.
//   - RSA-SHA1 is an accepted signature method. Chosen-prefix collisions against
//     SHA-1 are practical, and the redirect binding in this package already
//     refuses it. Two bindings with different cryptographic policies is a hole in
//     whichever one is weaker.
//
// So the structure is checked here FIRST, and only a document with exactly one
// signature, in the one position a legitimate signer puts it, referring to the
// element we actually read, is handed over for cryptographic verification.
//
// wantTag is the expected root element ("AuthnRequest", "LogoutRequest"), and
// wantID is the ID already parsed out of it -- passed in rather than re-read, so
// that the element verified and the element acted on are provably the same one.
func VerifyEmbeddedSignature(raw []byte, certPEM, wantTag, wantID string) error {
	// The comment and DOCTYPE rules apply here too. This document is about to be
	// parsed a second time, by a different parser, and any construct on which two
	// parsers can disagree is exactly what must not reach either of them.
	if err := scanForUnsafeConstructs(raw); err != nil {
		return err
	}
	if certPEM == "" {
		return fmt.Errorf("%s signatures are required for this service provider but no "+
			"signing certificate is registered for it, so no signature could ever be "+
			"verified; register one with `signari saml add-sp -sp-cert`", wantTag)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return fmt.Errorf("the %s did not parse as XML: %w", wantTag, err)
	}
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("the document is empty")
	}
	if root.Tag != wantTag {
		return fmt.Errorf("the root element is %q, expected %q", root.Tag, wantTag)
	}

	if err := checkSignaturePlacement(doc, root, wantID); err != nil {
		return err
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return err
	}
	store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(&store)
	// Stated rather than left to the default, because the whole placement check
	// above is written in terms of the ID attribute: if these two ever disagree,
	// the structure verified and the structure checked are different things.
	ctx.IdAttribute = "ID"

	validated, err := ctx.Validate(root)
	if err != nil {
		return fmt.Errorf("the %s signature did not verify against the certificate "+
			"registered for this service provider: %w", wantTag, err)
	}

	// The element goxmldsig returns is the one it actually verified. Confirming it
	// is still the element we read closes the loop: if any of the checks above
	// were somehow satisfied by a different subtree, the identity comparison here
	// is what notices.
	if got := validated.SelectAttrValue("ID", ""); got != wantID {
		return fmt.Errorf("the signature covers an element with ID %q, but the %s "+
			"being processed has ID %q", got, wantTag, wantID)
	}
	if validated.Tag != wantTag {
		return fmt.Errorf("the signature covers a %q element, not the %s", validated.Tag, wantTag)
	}
	return nil
}

// checkSignaturePlacement enforces the structural rules before any cryptography
// happens.
//
// Every rule here exists because a real bypass satisfied the version without it.
func checkSignaturePlacement(doc *etree.Document, root *etree.Element, wantID string) error {
	// The ID we are told to expect must actually be this element's ID. A document
	// whose root carries no ID cannot be referred to by a signature at all, and
	// goxmldsig would then happily accept a Reference URI of "".
	rootID := root.SelectAttrValue("ID", "")
	if rootID == "" {
		return fmt.Errorf("the root element has no ID attribute, so no signature can " +
			"refer to it unambiguously")
	}
	if rootID != wantID {
		return fmt.Errorf("the root element ID %q does not match the parsed ID %q",
			rootID, wantID)
	}

	// No duplicate IDs anywhere. Two elements with the same ID is the precondition
	// for every wrapping attack: the verifier resolves the reference to one of
	// them and the application reads the other.
	seen := map[string]int{}
	for _, el := range doc.FindElements("//*") {
		if id := el.SelectAttrValue("ID", ""); id != "" {
			seen[id]++
			if seen[id] > 1 {
				return fmt.Errorf("two or more elements carry the ID %q; a document with "+
					"duplicate IDs is refused, because the signature and the parser can "+
					"resolve them differently", id)
			}
		}
	}

	// Exactly one Signature element in the WHOLE document, matched on local name
	// so a different namespace prefix cannot hide one.
	sigs := doc.FindElements("//Signature")
	switch {
	case len(sigs) == 0:
		return fmt.Errorf("the request is not signed, and this service provider is " +
			"configured to require signed AuthnRequests")
	case len(sigs) > 1:
		return fmt.Errorf("the document contains %d Signature elements; only one is "+
			"accepted, because choosing between them is the attacker's decision to make",
			len(sigs))
	}
	sig := sigs[0]

	// And it must be a direct child of the root. This is the rule goxmldsig does
	// not have: a signature found deeper in the tree may be perfectly valid over
	// some fragment while the content actually acted on is unsigned.
	if sig.Parent() != root {
		return fmt.Errorf("the Signature is not a direct child of the %s; an enveloped "+
			"signature elsewhere in the document proves nothing about the request itself",
			root.Tag)
	}

	signedInfo := sig.FindElement("SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("the Signature has no SignedInfo")
	}

	// Exactly one Reference, naming the root by its ID.
	refs := signedInfo.FindElements("Reference")
	if len(refs) != 1 {
		return fmt.Errorf("the Signature has %d Reference elements; exactly one, "+
			"covering the whole request, is accepted", len(refs))
	}
	uri := refs[0].SelectAttrValue("URI", "")
	if uri != "#"+rootID {
		// Including the empty case: "" means "the whole document" and is refused
		// rather than interpreted, because what "the document" contains is the
		// thing in dispute.
		return fmt.Errorf("the Signature covers %q, not the request itself (#%s)", uri, rootID)
	}

	// SHA-1 refused, on both the signature and the digest, matching the redirect
	// binding's policy.
	if m := signedInfo.FindElement("SignatureMethod"); m != nil {
		if alg := m.SelectAttrValue("Algorithm", ""); strings.Contains(strings.ToLower(alg), "sha1") {
			return fmt.Errorf("the request is signed with %s, which is refused; "+
				"configure the service provider to use rsa-sha256", alg)
		}
	}
	if d := refs[0].FindElement("DigestMethod"); d != nil {
		if alg := d.SelectAttrValue("Algorithm", ""); strings.Contains(strings.ToLower(alg), "sha1") {
			return fmt.Errorf("the request digest is %s, which is refused; "+
				"configure the service provider to use sha256", alg)
		}
	}
	return nil
}
