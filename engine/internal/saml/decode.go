// Package saml implements a SAML 2.0 identity provider.
//
// # Reading the advisories before writing the code
//
// The published advisories for the three most-used Go SAML libraries were read
// rather than recalled. Across crewjam/saml, gosaml2 and goxmldsig there are six
// distinct signature-validation or authentication bypasses, plus deflate
// decompression bombs and one case of acting on an UNSIGNED LogoutRequest.
//
// None of them is a cryptographic break. Every one is a parsing or policy
// decision, and every one is defended against here explicitly rather than
// assumed away:
//
//	signature wrapping          verify the element we READ, never "something signed"
//	comment truncation          refuse comments outright (see below)
//	deflate bomb                bounded inflate, refuse before allocating
//	unsigned LogoutRequest      no certificate on file means logout is refused
//	external entities           Go rejects these; proven by test, not assumed
//	RelayState injection        opaque, size-bounded, never interpreted
//
// # Why comments are refused
//
// Go's XML parser concatenates the text either side of a comment, so
//
//	<Issuer>admin<!---->@evil.test</Issuer>
//
// parses as `admin@evil.test`. Exclusive canonicalisation -- what the signature
// is computed over -- DROPS comments, and other parsers keep only the first text
// node. So the bytes that were signed, the value we read, and the value the peer
// read can all differ, which is precisely CVE-2017-11427 and its siblings.
//
// Rather than trying to make our parse agree with every other implementation's,
// inbound documents containing comments are rejected. No legitimate service
// provider puts a comment in an AuthnRequest, and it removes the entire class
// rather than one instance of it.
package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const (
	// maxEncoded bounds the message BEFORE any decoding. A SAML AuthnRequest is
	// one to two kilobytes; anything approaching this is not a real request.
	maxEncoded = 64 << 10
	// maxInflated bounds the result of decompression. The HTTP-Redirect binding
	// carries raw DEFLATE, and a few hundred bytes of it expand to gigabytes --
	// which is how both crewjam/saml and gosaml2 were taken down (GHSA-5mqj-xc49-246p,
	// GHSA-6gc3-crp7-25w5). The bound is enforced DURING the read, so the memory
	// is never allocated in the first place.
	maxInflated = 256 << 10
)

// DecodeRedirect decodes a SAMLRequest/SAMLResponse from the HTTP-Redirect
// binding: base64 of a raw DEFLATE stream, carried in a query parameter.
func DecodeRedirect(param string) ([]byte, error) {
	if len(param) > maxEncoded {
		return nil, fmt.Errorf("SAML message is %d bytes encoded, over the %d limit",
			len(param), maxEncoded)
	}
	raw, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		return nil, fmt.Errorf("SAML message is not valid base64: %w", err)
	}
	return inflateBounded(bytes.NewReader(raw))
}

// DecodePOST decodes a SAMLRequest/SAMLResponse from the HTTP-POST binding:
// base64 only, no compression.
func DecodePOST(param string) ([]byte, error) {
	if len(param) > maxEncoded {
		return nil, fmt.Errorf("SAML message is %d bytes encoded, over the %d limit",
			len(param), maxEncoded)
	}
	raw, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		return nil, fmt.Errorf("SAML message is not valid base64: %w", err)
	}
	if len(raw) > maxInflated {
		return nil, fmt.Errorf("SAML message is %d bytes, over the %d limit", len(raw), maxInflated)
	}
	return raw, nil
}

// inflateBounded decompresses with a hard ceiling.
//
// io.LimitReader is the load-bearing part: it stops the decompressor at the
// bound instead of letting it allocate first and checking afterwards. Reading
// one byte PAST the limit is what distinguishes "exactly at the limit" from
// "truncated here", so an oversized stream is reported rather than silently
// clipped into a document that parses.
func inflateBounded(r io.Reader) ([]byte, error) {
	fr := flate.NewReader(r)
	defer func() { _ = fr.Close() }()

	out, err := io.ReadAll(io.LimitReader(fr, maxInflated+1))
	if err != nil {
		return nil, fmt.Errorf("SAML message did not decompress: %w", err)
	}
	if len(out) > maxInflated {
		return nil, fmt.Errorf("SAML message expands past the %d byte limit; "+
			"refusing it rather than allocating for it", maxInflated)
	}
	return out, nil
}

// Unmarshal parses a SAML document into v, refusing constructs that let the
// signed bytes and the parsed value disagree.
//
// The scan happens BEFORE unmarshalling, over the raw token stream, so that a
// rejected construct is never handed to application code at all.
func Unmarshal(doc []byte, v any) error {
	if err := scanForUnsafeConstructs(doc); err != nil {
		return err
	}
	dec := xml.NewDecoder(bytes.NewReader(doc))
	// Explicit, though Go's default is already nil: a non-nil Entity map would
	// reintroduce entity expansion. Stated so that changing it is a deliberate
	// act rather than a plausible-looking edit.
	dec.Entity = nil
	dec.Strict = true
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("SAML document did not parse: %w", err)
	}
	return nil
}

// scanForUnsafeConstructs walks the token stream and refuses comments and
// document type declarations.
func scanForUnsafeConstructs(doc []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	dec.Entity = nil
	dec.Strict = true

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("SAML document did not parse: %w", err)
		}
		switch t := tok.(type) {
		case xml.Comment:
			// The comment-truncation class. See the package comment.
			return fmt.Errorf("SAML document contains an XML comment, which is refused: " +
				"canonicalisation drops comments before signing while parsers keep the " +
				"text around them, so the signed bytes and the parsed value can differ " +
				"(CVE-2017-11427 and relatives)")
		case xml.Directive:
			// <!DOCTYPE ...>. Go will not expand external entities, but a document
			// carrying a DTD at all is either an attack or a broken implementation,
			// and there is nothing to gain by accepting one.
			if d := strings.TrimSpace(string(t)); strings.HasPrefix(strings.ToUpper(d), "DOCTYPE") {
				return fmt.Errorf("SAML document contains a DOCTYPE declaration, which is refused")
			}
		}
	}
}
