package saml

import (
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Reading a partner's metadata instead of typing it (8.01).
//
// A metadata document names where assertions are delivered and which keys are
// believed, so it is a security decision in a file, and the shape of the code is
// the shape of ConsumeResponse: the document is scanned for constructs two
// parsers can disagree on, then its signature is verified, and everything read
// after that comes from the element the verifier returned.
//
// An aggregate holds thousands of entities. One is chosen by its entity ID and
// never by its position: "the first one" is a choice made by whoever ordered the
// file.

// MetadataLimit is the most of a metadata document that is read.
const MetadataLimit = 16 << 20

const protocolSAML2 = "urn:oasis:names:tc:SAML:2.0:protocol"

// The errors a caller may want to tell apart from a document that is merely
// wrong.
var (
	// ErrMetadataUnsigned is a document with no signature where one was required.
	ErrMetadataUnsigned = errors.New("the metadata carries no signature")
	// ErrMetadataTrust is a request that says nothing about who to believe.
	ErrMetadataTrust = errors.New("give the certificate the metadata is signed with, or say by name " +
		"that it is unsigned: unsigned metadata is believed because of where it came from, and only " +
		"whoever is reading this can vouch for that")
)

// MetadataSource is a document and how far to believe it.
type MetadataSource struct {
	Document []byte
	// EntityID chooses the entity. An aggregate needs it; for a single entity it
	// is a check, and empty takes whatever the document describes.
	EntityID string
	// SignerPEM is the certificate the document must be signed with: the
	// federation's or the partner's, held out of band, because a document must
	// not vouch for its own signature.
	SignerPEM string
	// Unsigned takes the document on the strength of where it came from, without
	// any signature check. Exactly one of this and SignerPEM.
	Unsigned bool
	Now      time.Time
}

// ServiceProviderMetadata is what a service provider says of itself.
type ServiceProviderMetadata struct {
	// ACSURLs are where assertions go, the default first.
	ACSURLs []string
	// SLOURL is empty when it takes no logout.
	SLOURL, SLOBinding string
	// SOAPLogoutURL is where it is told of a logout with no browser, the signature
	// being this deployment's to make, so no certificate of its own is needed.
	SOAPLogoutURL string
	// SigningCertPEM holds every certificate it signs with.
	SigningCertPEM string
	// EncryptionCertPEM is a key it offers for encrypted assertions, which it is
	// for the operator to accept, since one a provider cannot read with the
	// algorithm in use here stops every sign-in to it.
	EncryptionCertPEM  string
	WantSignedRequests bool
	NameIDFormat       string
}

// IdentityProviderMetadata is what an upstream identity provider says of itself.
type IdentityProviderMetadata struct {
	SSOURL         string
	SigningCertPEM string
	NameIDFormat   string
	// SLOURL is where a sign-out here goes on to, empty when it has nowhere on
	// the redirect binding, which is how one reaches an upstream.
	SLOURL string
}

// EntityMetadata is one entity read from a document that passed.
type EntityMetadata struct {
	EntityID string
	// One or both, by the roles it declares for SAML 2.0.
	SP  *ServiceProviderMetadata
	IdP *IdentityProviderMetadata
	// Notes say what was left out and why, for whoever imported it.
	Notes []string
}

// ReadMetadata verifies a document and reads one entity out of it.
func ReadMetadata(src MetadataSource) (*EntityMetadata, error) {
	if len(src.Document) > MetadataLimit {
		return nil, fmt.Errorf("the metadata is %d bytes, more than the %d this reads", len(src.Document), MetadataLimit)
	}
	if (src.SignerPEM == "") == !src.Unsigned {
		return nil, ErrMetadataTrust
	}
	if err := scanForUnsafeConstructs(src.Document); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(src.Document); err != nil {
		return nil, fmt.Errorf("parsing the metadata: %w", err)
	}
	root := doc.Root()
	if root == nil || (root.Tag != "EntityDescriptor" && root.Tag != "EntitiesDescriptor") ||
		root.NamespaceURI() != nsMetadata {
		return nil, fmt.Errorf("not SAML metadata: the document has no EntityDescriptor or EntitiesDescriptor at its root")
	}

	// Nothing above read a value out of the document. Everything below reads
	// from trusted, which for a signed document is the element the verifier
	// returned and not the tree it was given.
	trusted := root
	if src.SignerPEM != "" {
		if len(doc.FindElements("//Signature")) == 0 {
			return nil, ErrMetadataUnsigned
		}
		verified, err := verifySignedElement(doc, root, src.SignerPEM, root.Tag, root.SelectAttrValue("ID", ""))
		if err != nil {
			return nil, fmt.Errorf("the metadata's signature: %w", err)
		}
		trusted = verified
	}

	now := src.Now
	if now.IsZero() {
		now = time.Now()
	}
	entity, err := chooseEntity(trusted, src.EntityID, now)
	if err != nil {
		return nil, err
	}
	out := &EntityMetadata{EntityID: entity.SelectAttrValue("entityID", "")}
	if out.EntityID == "" {
		return nil, fmt.Errorf("the entity has no entityID")
	}
	if sp, err := soleRole(entity, "SPSSODescriptor"); err != nil {
		return nil, err
	} else if sp != nil {
		if out.SP, err = readServiceProvider(sp, now, &out.Notes); err != nil {
			return nil, err
		}
	}
	if idp, err := soleRole(entity, "IDPSSODescriptor"); err != nil {
		return nil, err
	} else if idp != nil {
		if out.IdP, err = readIdentityProvider(idp, now, &out.Notes); err != nil {
			return nil, err
		}
	}
	if out.SP == nil && out.IdP == nil {
		return nil, fmt.Errorf("%q declares no SAML 2.0 service provider or identity provider", out.EntityID)
	}
	return out, nil
}

// chooseEntity finds the one entity asked for.
func chooseEntity(root *etree.Element, want string, now time.Time) (*etree.Element, error) {
	if err := stillValid(root, now); err != nil {
		return nil, err
	}
	if root.Tag == "EntityDescriptor" {
		if got := root.SelectAttrValue("entityID", ""); want != "" && got != want {
			return nil, fmt.Errorf("the metadata describes %q, not %q", got, want)
		}
		return root, nil
	}
	var all, match []*etree.Element
	if err := collectEntities(root, now, &all); err != nil {
		return nil, err
	}
	for _, e := range all {
		if e.SelectAttrValue("entityID", "") == want {
			match = append(match, e)
		}
	}
	switch {
	case want == "":
		return nil, fmt.Errorf("the metadata describes %d entities: name the one you mean, since the "+
			"order of a file is not a choice", len(all))
	case len(match) == 0:
		return nil, fmt.Errorf("the metadata describes %d entities and %q is not one of them", len(all), want)
	case len(match) > 1:
		return nil, fmt.Errorf("the metadata describes %q %d times, and choosing between them is not ours to do",
			want, len(match))
	}
	if err := stillValid(match[0], now); err != nil {
		return nil, err
	}
	return match[0], nil
}

// collectEntities walks an aggregate, whose groups can nest.
func collectEntities(group *etree.Element, now time.Time, into *[]*etree.Element) error {
	for _, child := range group.ChildElements() {
		switch child.Tag {
		case "EntityDescriptor":
			*into = append(*into, child)
		case "EntitiesDescriptor":
			if err := stillValid(child, now); err != nil {
				return err
			}
			if err := collectEntities(child, now, into); err != nil {
				return err
			}
		}
	}
	return nil
}

// stillValid refuses what its own author said to stop believing. A signature
// proves who wrote a document and not when, so an old signed one naming an old
// key is otherwise a replay.
func stillValid(el *etree.Element, now time.Time) error {
	v := el.SelectAttrValue("validUntil", "")
	if v == "" {
		return nil
	}
	until, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return fmt.Errorf("the metadata's validUntil %q is not a time", v)
	}
	if now.After(until) {
		return fmt.Errorf("the metadata says it stopped being valid at %s", until.UTC().Format(time.RFC3339))
	}
	return nil
}

// soleRole is the descriptor for one role, for SAML 2.0.
func soleRole(entity *etree.Element, tag string) (*etree.Element, error) {
	var found []*etree.Element
	for _, d := range entity.SelectElements(tag) {
		if slices.Contains(strings.Fields(d.SelectAttrValue("protocolSupportEnumeration", "")), protocolSAML2) {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("the entity has %d %s elements for SAML 2.0; one is read, and which is not ours to choose",
		len(found), tag)
}

func readServiceProvider(d *etree.Element, now time.Time, notes *[]string) (*ServiceProviderMetadata, error) {
	sp := &ServiceProviderMetadata{}
	var err error
	if sp.ACSURLs, err = assertionConsumers(d, notes); err != nil {
		return nil, err
	}
	if sp.SigningCertPEM, err = certificates(d, "signing", now, notes); err != nil {
		return nil, err
	}
	if sp.EncryptionCertPEM, err = encryptionKey(d, now, notes); err != nil {
		return nil, err
	}
	sp.WantSignedRequests = xmlTrue(d.SelectAttrValue("AuthnRequestsSigned", ""))
	if sp.WantSignedRequests && sp.SigningCertPEM == "" {
		return nil, fmt.Errorf("the service provider says it signs its requests and publishes no certificate " +
			"they could be verified with")
	}
	if sp.SigningCertPEM != "" {
		sp.SLOURL, sp.SLOBinding = logoutService(d, notes)
	} else if len(d.SelectElements("SingleLogoutService")) > 0 {
		*notes = append(*notes, "single logout left out: a logout request is acted on only when signed, and "+
			"the metadata publishes no signing certificate")
	}
	for _, s := range d.SelectElements("SingleLogoutService") {
		if s.SelectAttrValue("Binding", "") != BindingSOAP {
			continue
		}
		if loc := s.SelectAttrValue("Location", ""); strings.HasPrefix(loc, "https://") {
			sp.SOAPLogoutURL = loc
			break
		} else {
			*notes = append(*notes, fmt.Sprintf("left out %s: a logout URL has to be https", loc))
		}
	}
	sp.NameIDFormat = nameIDFormat(d, "persistent", "emailAddress", "transient")
	return sp, nil
}

func readIdentityProvider(d *etree.Element, now time.Time, notes *[]string) (*IdentityProviderMetadata, error) {
	idp := &IdentityProviderMetadata{}
	var err error
	if idp.SigningCertPEM, err = certificates(d, "signing", now, notes); err != nil {
		return nil, err
	}
	if url, binding := logoutService(d, notes); binding == "HTTP-Redirect" {
		idp.SLOURL = url
	} else if url != "" {
		*notes = append(*notes, "left out its logout URL, which takes only HTTP-POST: a sign-out reaches an upstream as a redirect")
	}
	if idp.SigningCertPEM == "" {
		return nil, fmt.Errorf("the identity provider publishes no signing certificate that is still valid, so " +
			"there would be nothing to verify an assertion with")
	}
	for _, s := range d.SelectElements("SingleSignOnService") {
		// A sign-in reaches an upstream as a redirect.
		if s.SelectAttrValue("Binding", "") == BindingRedirect {
			idp.SSOURL = s.SelectAttrValue("Location", "")
			break
		}
	}
	if idp.SSOURL == "" {
		return nil, fmt.Errorf("the identity provider has no SingleSignOnService on the HTTP-Redirect binding, " +
			"which is the one a sign-in here is sent by")
	}
	// transient is left out as it is at registration: an account linked to one
	// would be abandoned the moment it was created.
	idp.NameIDFormat = nameIDFormat(d, "persistent", "emailAddress", "unspecified")
	return idp, nil
}

// assertionConsumers are the https HTTP-POST endpoints, the default first: the
// one marked as default, and otherwise the lowest index.
func assertionConsumers(d *etree.Element, notes *[]string) ([]string, error) {
	type endpoint struct {
		url       string
		index     int
		isDefault bool
	}
	var usable []endpoint
	for _, a := range d.SelectElements("AssertionConsumerService") {
		loc := a.SelectAttrValue("Location", "")
		binding := a.SelectAttrValue("Binding", "")
		switch {
		case binding != BindingPOST:
			*notes = append(*notes, fmt.Sprintf("left out %s: it is not on the HTTP-POST binding", loc))
			continue
		case !strings.HasPrefix(loc, "https://"):
			*notes = append(*notes, fmt.Sprintf("left out %s: an assertion is a credential, and that is not https", loc))
			continue
		}
		index, err := strconv.Atoi(a.SelectAttrValue("index", "0"))
		if err != nil {
			return nil, fmt.Errorf("an AssertionConsumerService has the index %q", a.SelectAttrValue("index", ""))
		}
		usable = append(usable, endpoint{loc, index, xmlTrue(a.SelectAttrValue("isDefault", ""))})
	}
	if len(usable) == 0 {
		return nil, fmt.Errorf("the service provider has no https AssertionConsumerService on the HTTP-POST binding")
	}
	slices.SortStableFunc(usable, func(a, b endpoint) int {
		if a.isDefault != b.isDefault {
			if a.isDefault {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.index, b.index)
	})
	var urls []string
	for _, e := range usable {
		if !slices.Contains(urls, e.url) {
			urls = append(urls, e.url)
		}
	}
	return urls, nil
}

// logoutService is the https logout endpoint, on the redirect binding if it has
// one, named as a registration names it.
func logoutService(d *etree.Element, notes *[]string) (url, binding string) {
	for _, want := range []struct{ full, short string }{
		{BindingRedirect, "HTTP-Redirect"}, {BindingPOST, "HTTP-POST"},
	} {
		for _, s := range d.SelectElements("SingleLogoutService") {
			if s.SelectAttrValue("Binding", "") != want.full {
				continue
			}
			loc := s.SelectAttrValue("Location", "")
			if strings.HasPrefix(loc, "https://") {
				return loc, want.short
			}
			*notes = append(*notes, fmt.Sprintf("left out %s: a logout URL has to be https", loc))
		}
	}
	return "", ""
}

// certificates is every usable certificate for a use, as PEM. A key with no use
// stated serves both. An expired one is dropped, since no signature it made
// would verify.
func certificates(d *etree.Element, use string, now time.Time, notes *[]string) (string, error) {
	var out strings.Builder
	var seen []string
	for _, key := range d.SelectElements("KeyDescriptor") {
		if u := key.SelectAttrValue("use", ""); u != "" && u != use {
			continue
		}
		for _, c := range key.FindElements("./KeyInfo/X509Data/X509Certificate") {
			cert, err := certificateText(c.Text())
			if err != nil {
				return "", err
			}
			if slices.Contains(seen, string(cert.Raw)) {
				continue
			}
			seen = append(seen, string(cert.Raw))
			if now.After(cert.NotAfter) {
				*notes = append(*notes, fmt.Sprintf("left out a %s certificate that expired on %s", use,
					cert.NotAfter.Format("2006-01-02")))
				continue
			}
			out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
	}
	return out.String(), nil
}

// encryptionKey is a key offered for encryption alone. One with no stated use is
// the signing key as well, and a provider's two keys are kept apart here. RSA of
// at least 2048 bits is what assertions can be encrypted to.
func encryptionKey(d *etree.Element, now time.Time, notes *[]string) (string, error) {
	for _, key := range d.SelectElements("KeyDescriptor") {
		if key.SelectAttrValue("use", "") != "encryption" {
			continue
		}
		for _, c := range key.FindElements("./KeyInfo/X509Data/X509Certificate") {
			cert, err := certificateText(c.Text())
			if err != nil {
				return "", err
			}
			pub, isRSA := cert.PublicKey.(*rsa.PublicKey)
			if now.After(cert.NotAfter) || !isRSA || pub.N.BitLen() < 2048 {
				*notes = append(*notes, "left out an encryption key: expired, or not RSA of at least 2048 bits")
				continue
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), nil
		}
	}
	return "", nil
}

func certificateText(text string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		return nil, fmt.Errorf("a certificate in the metadata is not base64: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("a certificate in the metadata does not parse: %w", err)
	}
	return cert, nil
}

// nameIDFormat is the first format listed that a registration here can hold.
func nameIDFormat(d *etree.Element, allowed ...string) string {
	for _, f := range d.SelectElements("NameIDFormat") {
		text := strings.TrimSpace(f.Text())
		short := text[strings.LastIndex(text, ":")+1:]
		if slices.Contains(allowed, short) {
			return short
		}
	}
	return ""
}

func xmlTrue(v string) bool { return v == "true" || v == "1" }

// FetchMetadata reads a document from where its partner publishes it. https
// only: a URL a refresh goes back to is a URL believed each time, and the client
// is the caller's so it is the one that refuses a private address.
func FetchMetadata(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("metadata is read over https, and %q is not", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("the metadata URL: %w", err)
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading the metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading the metadata: %s answered %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MetadataLimit+1))
	if err != nil {
		return nil, fmt.Errorf("reading the metadata: %w", err)
	}
	return body, nil
}
