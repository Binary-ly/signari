package oid4vp

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// An ISO mdoc presented over OID4VP (specs/oid4vp.txt:3079-3400), verified as ISO/IEC
// 18013-5:2021 has a reader do it (9.3.1, specs/iso-iec-18013-5-2021.pdf page 65): the
// document signer certificate to the operator's IACA roots, the issuer's signature over
// the mobile security object, the digest of every element returned, the document type,
// the validity of the MSO, and the device's signature over this request's
// SessionTranscript, which is what binds the presentation to this verifier and nonce.
//
// Clause and page references below are to that PDF: the standard's page n is the PDF's
// page n+6.

// FormatMdoc is the credential format identifier for an mdoc (specs/oid4vp.txt:3081).
const FormatMdoc = "mso_mdoc"

// MdocDocType is the mDL's document type (18013-5 7.1, page 21).
const MdocDocType = "org.iso.18013.5.1.mDL"

// oidMdlDS is id-mdl-kp-mdlDS, the extended key usage a document signer certificate
// carries (18013-5 B.1.1, page 69; Table B.3, page 77).
var oidMdlDS = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}

// mdocDecMode refuses a map with a key twice: two values for one element, of which a
// decoder would keep one and a person reading the credential perhaps the other.
var mdocDecMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  32,
		MaxArrayElements: 4096,
		MaxMapPairs:      4096,
		TimeTag:          cbor.DecTagRequired,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// The device retrieval response, 18013-5 8.3.2.1.2.2 (pages 36-38). Each item is kept
// as it arrived where a digest or a signature is over its bytes.
type deviceResponse struct {
	Version   string         `cbor:"version"`
	Documents []mdocDocument `cbor:"documents"`
	Status    *uint64        `cbor:"status"`
}

type mdocDocument struct {
	DocType      string `cbor:"docType"`
	IssuerSigned struct {
		NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
		IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"`
	} `cbor:"issuerSigned"`
	DeviceSigned struct {
		NameSpaces cbor.RawMessage `cbor:"nameSpaces"`
		DeviceAuth struct {
			DeviceSignature cbor.RawMessage `cbor:"deviceSignature"`
			DeviceMac       cbor.RawMessage `cbor:"deviceMac"`
		} `cbor:"deviceAuth"`
	} `cbor:"deviceSigned"`
}

type issuerSignedItem struct {
	DigestID          uint64          `cbor:"digestID"`
	Random            []byte          `cbor:"random"`
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"`
}

// The mobile security object, 18013-5 9.1.2.4 (pages 56-57).
type mobileSecurityObject struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   struct {
		DeviceKey         cbor.RawMessage `cbor:"deviceKey"`
		KeyAuthorizations *struct {
			NameSpaces   []string            `cbor:"nameSpaces"`
			DataElements map[string][]string `cbor:"dataElements"`
		} `cbor:"keyAuthorizations"`
	} `cbor:"deviceKeyInfo"`
	DocType      string `cbor:"docType"`
	ValidityInfo struct {
		Signed     time.Time `cbor:"signed"`
		ValidFrom  time.Time `cbor:"validFrom"`
		ValidUntil time.Time `cbor:"validUntil"`
	} `cbor:"validityInfo"`
}

// verifyMdoc checks one presentation, a base64url DeviceResponse
// (specs/oid4vp.txt:3186-3192), against e.
func verifyMdoc(presentation string, e Expect) (*Presented, error) {
	if e.MdocRoots == nil {
		return nil, errors.New("this verifier believes no IACA, so no mdoc can be checked")
	}
	raw, err := base64.RawURLEncoding.DecodeString(presentation)
	if err != nil {
		return nil, fmt.Errorf("the presentation is not base64url: %w", err)
	}
	var resp deviceResponse
	if err := mdocDecMode.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("the presentation is not a DeviceResponse: %w", err)
	}
	// "in the current version of this document its value shall be "1.0"" (page 37), and
	// a later minor version is read the same way (8.1, page 29).
	if !majorOne(resp.Version) {
		return nil, fmt.Errorf("a DeviceResponse of version %q", resp.Version)
	}
	// "If the mdoc returns a status code different from 0, it shall not return any
	// documents" (8.3.2.1.2.3, page 38).
	if resp.Status == nil || *resp.Status != 0 {
		return nil, errors.New("the DeviceResponse does not say OK")
	}
	if len(resp.Documents) != 1 {
		return nil, fmt.Errorf("the DeviceResponse holds %d documents, and one was asked", len(resp.Documents))
	}
	doc := resp.Documents[0]
	if doc.DocType != e.Ask.DocType {
		return nil, fmt.Errorf("a document of type %q, and %q was asked", doc.DocType, e.Ask.DocType)
	}

	issuerAuth, err := decodeSign1(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("issuerAuth: %w", err)
	}
	// 9.3.1 step 1: the certificate in the MSO header, validated as 9.3.3 says.
	signer, err := verifyDocumentSigner(issuerAuth, e)
	if err != nil {
		return nil, err
	}
	// Step 2: the issuer's signature, with that certificate's key.
	if err := issuerAuth.verify(signer.PublicKey, nil); err != nil {
		return nil, fmt.Errorf("the issuer's signature: %w", err)
	}
	// The payload is MobileSecurityObjectBytes, #6.24(bstr .cbor MobileSecurityObject).
	msoBytes, err := unwrap24(issuerAuth.Payload)
	if err != nil {
		return nil, fmt.Errorf("the mobile security object: %w", err)
	}
	var mso mobileSecurityObject
	if err := mdocDecMode.Unmarshal(msoBytes, &mso); err != nil {
		return nil, fmt.Errorf("the mobile security object: %w", err)
	}
	if !majorOne(mso.Version) {
		return nil, fmt.Errorf("a mobile security object of version %q", mso.Version)
	}
	// Step 4: the document type the issuer signed is the one presented.
	if mso.DocType != doc.DocType {
		return nil, fmt.Errorf("the issuer signed a %q and the document says %q", mso.DocType, doc.DocType)
	}
	// Step 5: the validity.
	if err := mdocValidity(mso, signer, e.Now); err != nil {
		return nil, err
	}
	// Step 3: every element returned, held to its digest.
	claims, err := issuerSignedClaims(doc, mso)
	if err != nil {
		return nil, err
	}

	// mdoc authentication, 9.1.3: the device's signature over this request.
	if err := verifyDeviceAuth(doc, mso, e); err != nil {
		return nil, err
	}

	for _, p := range e.Ask.Claims {
		if _, err := Select(claims, p); err != nil {
			return nil, err
		}
	}
	return &Presented{Issuer: mdocIssuer(doc.DocType, signer), VCT: doc.DocType, Claims: claims}, nil
}

// majorOne is a version this verifier reads: "1.0", or a later minor version of 1.
func majorOne(v string) bool {
	major, _, _ := strings.Cut(v, ".")
	return major == "1"
}

// unwrap24 opens #6.24(bstr .cbor X), the encoded CBOR data item (specs/rfc8949.txt:1189-1200).
func unwrap24(raw []byte) ([]byte, error) {
	var tag cbor.RawTag
	if err := mdocDecMode.Unmarshal(raw, &tag); err != nil || tag.Number != 24 {
		return nil, errors.New("not an encoded CBOR data item (tag 24)")
	}
	var inner []byte
	if err := mdocDecMode.Unmarshal(tag.Content, &inner); err != nil {
		return nil, errors.New("tag 24 holds something other than a byte string")
	}
	return inner, nil
}

// verifyDocumentSigner validates the document signer certificate, the first in the
// issuer signature's x5chain (18013-5 B.1.1, page 68), as 9.3.3 says (page 66): RFC 5280
// basic path validation to an IACA the operator believes, and the IACA's countryName,
// and stateOrProvinceName where both have one, the same in the signer's subject. The
// certificate is the document signer profile's (Table B.3, pages 75-77): the mdlDS
// extended key usage and a digital-signature key usage. A CRL it names is read.
func verifyDocumentSigner(issuerAuth *coseSign1, e Expect) (*x509.Certificate, error) {
	ders, err := issuerAuth.x5chain()
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("a certificate in x5chain: %w", err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	// Any extended key usage in the path, as no profile names one Go knows; the signer's
	// own is checked by hand below.
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: e.MdocRoots, Intermediates: intermediates,
		CurrentTime: e.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, fmt.Errorf("the document signer certificate: %w", err)
	}
	mdlDS := false
	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(oidMdlDS) {
			mdlDS = true
		}
	}
	if !mdlDS {
		return nil, errors.New("the signer certificate is not a document signer's: no mdlDS extended key usage")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("the signer certificate's key usage does not allow a digital signature")
	}
	chain := chains[0]
	iaca := chain[len(chain)-1]
	if len(iaca.Subject.Country) != 1 || len(leaf.Subject.Country) != 1 ||
		iaca.Subject.Country[0] != leaf.Subject.Country[0] {
		return nil, fmt.Errorf("the signer's country %v is not its IACA's %v", leaf.Subject.Country, iaca.Subject.Country)
	}
	if len(iaca.Subject.Province) > 0 && len(leaf.Subject.Province) > 0 &&
		strings.Join(iaca.Subject.Province, ",") != strings.Join(leaf.Subject.Province, ",") {
		return nil, fmt.Errorf("the signer's state %v is not its IACA's %v", leaf.Subject.Province, iaca.Subject.Province)
	}
	// B.1.4 makes the IACA's state the signer's too: "If this element is present in the
	// IACA root certificate, this element shall be present" (Table B.3, page 75).
	if len(iaca.Subject.Province) > 0 && len(leaf.Subject.Province) == 0 {
		return nil, fmt.Errorf("the IACA is for %v and the signer names no state", iaca.Subject.Province)
	}
	if err := checkChainRevocation(chain, e.Fetch, e.Now); err != nil {
		return nil, err
	}
	return leaf, nil
}

// mdocValidity is 9.3.1 step 5 (page 65): the MSO was signed while its signer's
// certificate was valid, it is valid from now or before, and until now or after.
func mdocValidity(mso mobileSecurityObject, signer *x509.Certificate, now time.Time) error {
	v := mso.ValidityInfo
	if v.Signed.IsZero() || v.ValidFrom.IsZero() || v.ValidUntil.IsZero() {
		return errors.New("the mobile security object's validity is incomplete")
	}
	if v.Signed.Before(signer.NotBefore) || v.Signed.After(signer.NotAfter) {
		return fmt.Errorf("the mobile security object was signed at %s, outside its signer's certificate",
			v.Signed.UTC().Format(time.RFC3339))
	}
	if now.Add(clockSkew).Before(v.ValidFrom) {
		return fmt.Errorf("the credential is not valid until %s", v.ValidFrom.UTC().Format(time.RFC3339))
	}
	if now.Add(-clockSkew).After(v.ValidUntil) {
		return fmt.Errorf("the credential was valid until %s", v.ValidUntil.UTC().Format(time.RFC3339))
	}
	return nil
}

// digestOf is the MSO's digest algorithm (18013-5 9.1.2.5 and Table 21, page 58).
func digestOf(name string) (crypto.Hash, error) {
	switch name {
	case "SHA-256":
		return crypto.SHA256, nil
	case "SHA-384":
		return crypto.SHA384, nil
	case "SHA-512":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("a digest algorithm %q, which is not SHA-256, SHA-384 or SHA-512", name)
}

// issuerSignedClaims reads every IssuerSignedItem returned, each held to the digest the
// MSO has for its namespace and digestID (9.3.1 step 3), over its IssuerSignedItemBytes
// as they arrived, tag included (9.1.2.5, page 58). It returns the elements as
// namespace -> identifier -> value, which a claims path of two strings selects
// (specs/oid4vp.txt:1175-1192).
func issuerSignedClaims(doc mdocDocument, mso mobileSecurityObject) (map[string]any, error) {
	h, err := digestOf(mso.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	for ns, items := range doc.IssuerSigned.NameSpaces {
		digests, ok := mso.ValueDigests[ns]
		if !ok {
			return nil, fmt.Errorf("the issuer signed no digests for namespace %q", ns)
		}
		elements := map[string]any{}
		for _, raw := range items {
			inner, err := unwrap24(raw)
			if err != nil {
				return nil, fmt.Errorf("an element of %q: %w", ns, err)
			}
			var item issuerSignedItem
			if err := mdocDecMode.Unmarshal(inner, &item); err != nil {
				return nil, fmt.Errorf("an element of %q is not an IssuerSignedItem: %w", ns, err)
			}
			want, ok := digests[item.DigestID]
			if !ok {
				return nil, fmt.Errorf("%s/%s names digest %d, which the issuer did not sign", ns,
					item.ElementIdentifier, item.DigestID)
			}
			d := h.New()
			d.Write(raw)
			if !bytes.Equal(d.Sum(nil), want) {
				return nil, fmt.Errorf("%s/%s is not what the issuer signed", ns, item.ElementIdentifier)
			}
			// "This value ... shall have a minimum length of 16 bytes" (9.1.2.5, page 58):
			// shorter, the digest of a guessable element can be tried.
			if len(item.Random) < 16 {
				return nil, fmt.Errorf("%s/%s carries %d bytes of random, and 16 are the least", ns,
					item.ElementIdentifier, len(item.Random))
			}
			// "The mdoc shall not include two or more IssuerSignedItem elements with the same
			// DataElementIdentifier in a single NameSpace" (page 38).
			if _, twice := elements[item.ElementIdentifier]; twice {
				return nil, fmt.Errorf("%s/%s is returned twice", ns, item.ElementIdentifier)
			}
			var value any
			if err := mdocDecMode.Unmarshal(item.ElementValue, &value); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", ns, item.ElementIdentifier, err)
			}
			elements[item.ElementIdentifier] = mdocValue(value)
		}
		claims[ns] = elements
	}
	return claims, nil
}

// mdocValue turns a decoded element into what the rest of the sign-in reads, as a JSON
// credential's would be: a date (tdate, tag 0, or full-date, tag 1004) as its text,
// bytes as base64url, a map's keys as text.
func mdocValue(v any) any {
	switch x := v.(type) {
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	case cbor.Tag:
		if s, ok := x.Content.(string); ok {
			return s
		}
		return mdocValue(x.Content)
	case []byte:
		return base64.RawURLEncoding.EncodeToString(x)
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[fmt.Sprint(k)] = mdocValue(val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = mdocValue(val)
		}
		return out
	}
	return v
}

// verifyDeviceAuth is mdoc authentication (9.1.3.4, pages 59-60): the device key the
// issuer signed into the MSO has signed DeviceAuthenticationBytes, made here from this
// request's SessionTranscript, the document type and the DeviceNameSpacesBytes as they
// arrived. A MAC needs a reader key agreed with the device, which a request over OID4VP
// does not carry here, so only a signature is accepted.
func verifyDeviceAuth(doc mdocDocument, mso mobileSecurityObject, e Expect) error {
	if len(doc.DeviceSigned.DeviceAuth.DeviceMac) > 0 {
		return errors.New("the device authenticated with a MAC, which this verifier cannot check; a signature is needed")
	}
	if len(doc.DeviceSigned.DeviceAuth.DeviceSignature) == 0 {
		return errors.New("the document carries no device signature")
	}
	if len(doc.DeviceSigned.NameSpaces) == 0 {
		return errors.New("the document has no DeviceNameSpaces, which is mandatory even when empty")
	}
	if err := deviceElementsAuthorized(doc.DeviceSigned.NameSpaces, mso); err != nil {
		return err
	}
	key, err := coseKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return err
	}
	sig, err := decodeSign1(doc.DeviceSigned.DeviceAuth.DeviceSignature)
	if err != nil {
		return fmt.Errorf("deviceSignature: %w", err)
	}
	transcript, err := SessionTranscript(e)
	if err != nil {
		return err
	}
	// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType,
	// DeviceNameSpacesBytes], and the detached content is its #6.24 encoding (page 59).
	auth, err := cbor.Marshal([]any{"DeviceAuthentication", transcript, doc.DocType,
		cbor.RawMessage(doc.DeviceSigned.NameSpaces)})
	if err != nil {
		return err
	}
	authBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: auth})
	if err != nil {
		return err
	}
	if err := sig.verify(key, authBytes); err != nil {
		return fmt.Errorf("the device's signature over this request: %w", err)
	}
	return nil
}

// deviceElementsAuthorized holds every element the device signed itself to the
// KeyAuthorizations the issuer gave its key (9.1.3.4, page 60: "If data elements are
// present in DeviceNameSpaces, an mdoc reader shall verify whether the KeyAuthorizations
// structure contains the proper authorization"). Such elements are checked, and none is
// used: the sign-in reads only what the issuer signed.
func deviceElementsAuthorized(raw cbor.RawMessage, mso mobileSecurityObject) error {
	inner, err := unwrap24(raw)
	if err != nil {
		return fmt.Errorf("DeviceNameSpacesBytes: %w", err)
	}
	var signed map[string]map[string]cbor.RawMessage
	if err := mdocDecMode.Unmarshal(inner, &signed); err != nil {
		return fmt.Errorf("DeviceNameSpaces: %w", err)
	}
	auth := mso.DeviceKeyInfo.KeyAuthorizations
	for ns, elements := range signed {
		for el := range elements {
			if auth == nil || !(contains(auth.NameSpaces, ns) || contains(auth.DataElements[ns], el)) {
				return fmt.Errorf("the device signed %s/%s, which its key is not authorized to", ns, el)
			}
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// SessionTranscript is the one for this request (specs/oid4vp.txt:3198-3204,
// :3340-3346): [null, null, Handover], where the Handover is OpenID4VPHandover for a
// request by redirect and OpenID4VPDCAPIHandover for one through the Digital Credentials
// API, each ["<name>", SHA-256 of the CBOR of its info] (:3206-3236, :3352-3375). The
// info is the client_id, nonce, the thumbprint of the key an encrypted answer was
// encrypted to (null otherwise) and the response_uri; through the API, the origin
// unprefixed, the nonce and the thumbprint.
func SessionTranscript(e Expect) ([]any, error) {
	var thumb any
	if e.EncryptedTo != nil {
		t, err := e.EncryptedTo.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("the response key's thumbprint: %w", err)
		}
		thumb = t
	}
	name, info := "OpenID4VPHandover", []any{e.ClientID, e.Nonce, thumb, e.ResponseURI}
	if e.Origin != "" {
		name, info = "OpenID4VPDCAPIHandover", []any{e.Origin, e.Nonce, thumb}
	}
	encoded, err := cbor.Marshal(info)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	return []any{nil, nil, []any{name, sum[:]}}, nil
}

// mdocIssuer names who issued a document, for the subject: its type and the issuing
// country, with the state where the IACA is a state's. A document number is unique
// within that, not across countries.
func mdocIssuer(docType string, signer *x509.Certificate) string {
	who := strings.Join(signer.Subject.Country, "")
	if len(signer.Subject.Province) > 0 {
		who += "-" + strings.Join(signer.Subject.Province, ",")
	}
	return "mdoc:" + docType + ":" + who
}
