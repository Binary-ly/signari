package oid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/sdjwt"
)

// pki is an issuer's certificate authority: a root the operator holds, an intermediate
// under it, and the issuer's own certificate under that, whose key is the fixture's
// issuer key.
type pki struct {
	t                 *testing.T
	rootKey, interKey *ecdsa.PrivateKey
	root, inter, leaf *x509.Certificate
	serial            int64
}

const (
	interCRL = "http://crl.issuer.example/intermediate.crl"
	rootCRL  = "http://crl.issuer.example/root.crl"
)

func (p *pki) issue(tmpl *x509.Certificate, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	p.t.Helper()
	p.serial++
	tmpl.SerialNumber = big.NewInt(p.serial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		p.t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	return c
}

func ca(name string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
}

// newPKI makes the chain, the issuer's certificate naming it as leaf edits it.
func newPKI(t *testing.T, issuerKey *ecdsa.PrivateKey, leaf func(*x509.Certificate)) *pki {
	t.Helper()
	p := &pki{t: t, rootKey: genKey(t), interKey: genKey(t)}
	p.root = p.issue(ca("Issuer Root"), nil, p.rootKey.Public(), p.rootKey)
	interTmpl := ca("Issuer Intermediate")
	interTmpl.CRLDistributionPoints = []string{rootCRL}
	p.inter = p.issue(interTmpl, p.root, p.interKey.Public(), p.rootKey)
	u, _ := url.Parse(testIssuer)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Issuer"}, URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, CRLDistributionPoints: []string{interCRL}}
	if leaf != nil {
		leaf(tmpl)
	}
	p.leaf = p.issue(tmpl, p.inter, issuerKey.Public(), p.interKey)
	return p
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return pool
}

// crl is a CRL by the intermediate (or the root, for the intermediate's), listing serials.
func (p *pki) crl(byRoot bool, serials []*big.Int, edit func(*x509.RevocationList)) []byte {
	p.t.Helper()
	issuer, key := p.inter, p.interKey
	if byRoot {
		issuer, key = p.root, p.rootKey
	}
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour)}
	for _, s := range serials {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now().Add(-time.Minute)})
	}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		p.t.Fatal(err)
	}
	return der
}

// crlHost serves the two CRLs.
type crlHost struct {
	t           *testing.T
	inter, root func() []byte
	asked       []string
	err         error
}

func (h *crlHost) fetch(uri, accept string) ([]byte, string, error) {
	h.asked = append(h.asked, uri)
	if accept != CRLMedia {
		h.t.Errorf("a CRL was asked for as %q", accept)
	}
	if h.err != nil {
		return nil, "", h.err
	}
	switch uri {
	case interCRL:
		return h.inter(), CRLMedia, nil
	case rootCRL:
		return h.root(), CRLMedia, nil
	}
	return nil, "", errors.New("not found")
}

// clean serves two CRLs that list nobody.
func (p *pki) clean() *crlHost {
	return &crlHost{t: p.t, inter: func() []byte { return p.crl(false, nil, nil) },
		root: func() []byte { return p.crl(true, nil, nil) }}
}

func x5c(certs ...*x509.Certificate) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return out
}

// chainCredential is the fixture's credential signed by signer with chain in x5c.
func (f *fixture) chainCredential(chain []string, signer crypto.Signer, edit func(map[string]any)) string {
	f.t.Helper()
	payload, ds, err := sdjwt.Payload(f.always, f.selected)
	if err != nil {
		f.t.Fatal(err)
	}
	payload["cnf"] = map[string]any{"jwk": jose.JSONWebKey{Key: f.holderKey.Public()}}
	if edit != nil {
		edit(payload)
	}
	opts := (&jose.SignerOptions{}).WithType("dc+sd-jwt")
	if chain != nil {
		opts = opts.WithHeader("x5c", chain)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signer}, opts)
	if err != nil {
		f.t.Fatal(err)
	}
	b, _ := json.Marshal(payload)
	obj, err := s.Sign(b)
	if err != nil {
		f.t.Fatal(err)
	}
	jwt, _ := obj.CompactSerialize()
	return token("person", f.present(credential{jwt: jwt, disclosures: ds}, both, nil, nil))
}

// byChain is what the verifier expects when it believes the test issuer by certificate.
func (f *fixture) byChain(p *pki, h *crlHost) Expect {
	e := f.expect()
	e.Issuers = nil
	e.Anchors = map[string]*x509.CertPool{testIssuer: p.pool()}
	if h != nil {
		e.Fetch = h.fetch
	}
	return e
}

func TestAnIssuerBelievedByItsCertificateIsCheckedAlongTheChain(t *testing.T) {
	f := newFixture(t)
	p := newPKI(t, f.issuerKey, nil)
	h := p.clean()
	got, err := Verify(f.chainCredential(x5c(p.leaf, p.inter), f.issuerKey, nil), f.byChain(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != testIssuer {
		t.Errorf("issuer %q", got.Issuer)
	}
	// Both certificates below the root, each against its own issuer's CRL, once each.
	if len(h.asked) != 2 || h.asked[0] != interCRL || h.asked[1] != rootCRL {
		t.Errorf("the CRLs asked for were %v", h.asked)
	}

	// An issuer that is a host and nothing more may be named by that host.
	dns := newPKI(t, f.issuerKey, func(c *x509.Certificate) {
		c.URIs = nil
		c.DNSNames = []string{"issuer.example"}
	})
	if _, err := Verify(f.chainCredential(x5c(dns.leaf, dns.inter), f.issuerKey, nil), f.byChain(dns, dns.clean())); err != nil {
		t.Errorf("a certificate naming the issuer's host: %v", err)
	}

	// An issuer's certificate need not be a server's: one whose extended key usage is
	// some ecosystem's own (here the mDL document signer's) still vouches.
	docSigner := newPKI(t, f.issuerKey, func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 2}}
	})
	if _, err := Verify(f.chainCredential(x5c(docSigner.leaf, docSigner.inter), f.issuerKey, nil),
		f.byChain(docSigner, docSigner.clean())); err != nil {
		t.Errorf("a certificate with its own extended key usage: %v", err)
	}

	// Certificates that name no CRL are left to the operator: nothing is fetched.
	quiet := newPKI(t, f.issuerKey, nil)
	noCRL := &crlHost{t: t, err: errors.New("nothing should be fetched")}
	quietInter := quiet.issue(ca("Issuer Intermediate"), quiet.root, quiet.interKey.Public(), quiet.rootKey)
	quietLeaf := quiet.issue(&x509.Certificate{Subject: pkix.Name{CommonName: "Issuer"}, URIs: quiet.leaf.URIs,
		KeyUsage: x509.KeyUsageDigitalSignature}, quietInter, f.issuerKey.Public(), quiet.interKey)
	if _, err := Verify(f.chainCredential(x5c(quietLeaf, quietInter), f.issuerKey, nil), f.byChain(quiet, noCRL)); err != nil {
		t.Errorf("a chain that names no CRL: %v", err)
	}
	if len(noCRL.asked) != 0 {
		t.Errorf("fetched %v for a chain that names no CRL", noCRL.asked)
	}
}

func TestACredentialWhoseCertificateDoesNotHoldIsRefused(t *testing.T) {
	f := newFixture(t)
	p := newPKI(t, f.issuerKey, nil)
	stranger := newPKI(t, f.issuerKey, nil)
	other := genKey(t)
	withPath := "https://issuer.example/pid"

	cases := []struct {
		name string
		vp   string
		e    Expect
		want string
	}{
		{name: "no x5c", vp: f.chainCredential(nil, f.issuerKey, nil), e: f.byChain(p, p.clean()),
			want: "carries no x5c"},
		{name: "a chain to somebody else's root", vp: f.chainCredential(x5c(stranger.leaf, stranger.inter), f.issuerKey, nil),
			e: f.byChain(p, p.clean()), want: "does not lead to a root"},
		{name: "the intermediate left out", vp: f.chainCredential(x5c(p.leaf), f.issuerKey, nil),
			e: f.byChain(p, p.clean()), want: "does not lead to a root"},
		{name: "signed by a key that is not the certificate's", vp: f.chainCredential(x5c(p.leaf, p.inter), other, nil),
			e: f.byChain(p, p.clean()), want: "signature does not verify"},
		{name: "a certificate for another issuer",
			vp: f.chainCredential(x5c(newPKIUnder(t, p, f.issuerKey, func(c *x509.Certificate) {
				u, _ := url.Parse("https://other.example")
				c.URIs = []*url.URL{u}
			}), p.inter), f.issuerKey, nil),
			e: f.byChain(p, p.clean()), want: "does not name its issuer"},
		{name: "a host naming an issuer at a path",
			vp: f.chainCredential(x5c(newPKIUnder(t, p, f.issuerKey, func(c *x509.Certificate) {
				c.URIs, c.DNSNames = nil, []string{"issuer.example"}
			}), p.inter), f.issuerKey, func(m map[string]any) { m["iss"] = withPath }),
			e: func() Expect {
				e := f.byChain(p, p.clean())
				e.Anchors = map[string]*x509.CertPool{withPath: p.pool()}
				return e
			}(), want: "does not name its issuer"},
		{name: "a wildcard",
			vp: f.chainCredential(x5c(newPKIUnder(t, p, f.issuerKey, func(c *x509.Certificate) {
				c.URIs, c.DNSNames = nil, []string{"*.example"}
			}), p.inter), f.issuerKey, nil),
			e: f.byChain(p, p.clean()), want: "does not name its issuer"},
		{name: "a wildcard, even for an issuer spelt with one",
			vp: f.chainCredential(x5c(newPKIUnder(t, p, f.issuerKey, func(c *x509.Certificate) {
				c.URIs, c.DNSNames = nil, []string{"*.example"}
			}), p.inter), f.issuerKey, func(m map[string]any) { m["iss"] = "https://*.example" }),
			e: func() Expect {
				e := f.byChain(p, p.clean())
				e.Anchors = map[string]*x509.CertPool{"https://*.example": p.pool()}
				return e
			}(), want: "does not name its issuer"},
		{name: "a key not for signatures",
			vp: f.chainCredential(x5c(newPKIUnder(t, p, f.issuerKey, func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageKeyAgreement
			}), p.inter), f.issuerKey, nil),
			e: f.byChain(p, p.clean()), want: "not for digital signatures"},
		{name: "an expired certificate",
			vp: f.chainCredential(x5c(newPKIUnder(t, p, f.issuerKey, func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
			}), p.inter), f.issuerKey, nil),
			e: f.byChain(p, p.clean()), want: "does not lead to a root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(c.vp, c.e)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
}

// newPKIUnder is another issuer certificate under p's intermediate, edited.
func newPKIUnder(t *testing.T, p *pki, key *ecdsa.PrivateKey, edit func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	u, _ := url.Parse(testIssuer)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Issuer"}, URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, CRLDistributionPoints: []string{interCRL}}
	edit(tmpl)
	return p.issue(tmpl, p.inter, key.Public(), p.interKey)
}

// SD-JWT VC section 6.2: for any iss, an attacker cannot choose how it is checked
// (specs/sdjwtvc.txt:2141-2145). An issuer held by its keys is checked with them, so a
// credential naming it and carrying a chain that would validate is refused.
func TestACredentialCannotChooseHowItsIssuerIsChecked(t *testing.T) {
	f := newFixture(t)
	forger := genKey(t)
	p := newPKI(t, forger, nil)
	e := f.byChain(p, p.clean())
	e.Issuers = f.issuers
	_, err := Verify(f.chainCredential(x5c(p.leaf, p.inter), forger, nil), e)
	if err == nil || !strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("a pinned issuer's credential was checked by the chain it carried: %v", err)
	}
}

func TestARevokedOrUnreadableCertificateRefuses(t *testing.T) {
	f := newFixture(t)
	p := newPKI(t, f.issuerKey, nil)
	vp := f.chainCredential(x5c(p.leaf, p.inter), f.issuerKey, nil)
	clean := func() []byte { return p.crl(false, nil, nil) }
	cleanRoot := func() []byte { return p.crl(true, nil, nil) }
	idp := asn1.ObjectIdentifier{2, 5, 29, 28}

	cases := []struct {
		name string
		host *crlHost
		want string
	}{
		{name: "the issuer's certificate revoked",
			host: &crlHost{inter: func() []byte { return p.crl(false, []*big.Int{p.leaf.SerialNumber}, nil) }, root: cleanRoot},
			want: "was revoked"},
		{name: "the intermediate revoked",
			host: &crlHost{inter: clean, root: func() []byte { return p.crl(true, []*big.Int{p.inter.SerialNumber}, nil) }},
			want: "was revoked"},
		{name: "the CRL unreadable", host: &crlHost{err: errors.New("connection refused")}, want: "could not be told"},
		{name: "the CRL not a CRL", host: &crlHost{inter: func() []byte { return []byte("<html>") }, root: cleanRoot},
			want: "does not parse"},
		{name: "the CRL from another authority",
			host: &crlHost{inter: func() []byte { return p.crl(true, nil, nil) }, root: cleanRoot},
			want: "not from the certificate's issuer"},
		{name: "the CRL under the issuer's name and another key",
			host: &crlHost{inter: func() []byte {
				impostorKey := genKey(t)
				impostor := p.issue(ca("Issuer Intermediate"), nil, impostorKey.Public(), impostorKey)
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2),
					ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour)}, impostor, impostorKey)
				if err != nil {
					t.Fatal(err)
				}
				return der
			}, root: cleanRoot},
			want: "not signed by the certificate's issuer"},
		{name: "the CRL past its next update",
			host: &crlHost{inter: func() []byte {
				return p.crl(false, nil, func(l *x509.RevocationList) {
					l.ThisUpdate, l.NextUpdate = time.Now().Add(-3*time.Hour), time.Now().Add(-2*time.Hour)
				})
			}, root: cleanRoot},
			want: "not current"},
		{name: "a CRL scoped by an issuing distribution point",
			host: &crlHost{inter: func() []byte {
				return p.crl(false, nil, func(l *x509.RevocationList) {
					l.ExtraExtensions = []pkix.Extension{{Id: idp, Critical: true, Value: []byte{0x30, 0x00}}}
				})
			}, root: cleanRoot},
			want: "critical extension"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.host.t = t
			_, err := Verify(vp, f.byChain(p, c.host))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
	// No way to read a CRL the chain names is no way to tell.
	if _, err := Verify(vp, f.byChain(p, nil)); err == nil || !strings.Contains(err.Error(), "no way to read it") {
		t.Fatalf("with nothing to fetch with: %v", err)
	}
}

// The issuer's status list is believed by the key its certificate vouches for, the
// same key as the credential's (specs/token-status-list.txt:949-951).
func TestAnIssuerBelievedByCertificateKeepsItsStatusListWithTheSameKey(t *testing.T) {
	f := newFixture(t)
	p := newPKI(t, f.issuerKey, nil)
	crls := p.clean()
	signer := f.issuerKey
	list := &statusHost{f: f, contentType: StatusTokenMedia, token: func() string {
		return signJSON(t, signer, "statuslist+jwt", "", map[string]any{"sub": testStatusURI, "iat": f.now.Unix(),
			"exp": f.now.Add(time.Hour).Unix(), "status_list": map[string]any{"bits": 2, "lst": statusList(t, 2, 64,
				map[int]byte{5: statusInvalid})}})
	}}
	e := f.byChain(p, nil)
	e.Fetch = func(uri, accept string) ([]byte, string, error) {
		if uri == testStatusURI {
			return list.fetch(uri, accept)
		}
		return crls.fetch(uri, accept)
	}
	vp := func(idx int) string {
		return f.chainCredential(x5c(p.leaf, p.inter), f.issuerKey, func(m map[string]any) {
			m["status"] = map[string]any{"status_list": map[string]any{"idx": idx, "uri": testStatusURI}}
		})
	}
	if _, err := Verify(vp(4), e); err != nil {
		t.Fatalf("a valid place: %v", err)
	}
	if _, err := Verify(vp(5), e); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked place: %v", err)
	}
	signer = genKey(t)
	if _, err := Verify(vp(4), e); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a list signed by a key the certificate does not vouch for: %v", err)
	}
}

func TestRootsAreCertificateAuthorities(t *testing.T) {
	f := newFixture(t)
	p := newPKI(t, f.issuerKey, nil)
	asPEM := func(certs ...*x509.Certificate) string {
		var b strings.Builder
		for _, c := range certs {
			b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
		return b.String()
	}
	if roots, err := ParseRoots(asPEM(p.root, p.inter)); err != nil || len(roots) != 2 {
		t.Fatalf("two authorities: %v %d", err, len(roots))
	}
	for name, text := range map[string]string{
		"a leaf":     asPEM(p.root, p.leaf),
		"nothing":    "",
		"a key":      string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})),
		"text after": asPEM(p.root) + "trailing",
		"a block cut short between two": strings.Replace(asPEM(p.root), "-----END CERTIFICATE-----", "", 1) +
			asPEM(p.inter),
		"not PEM at all": "MIIB...",
	} {
		if _, err := ParseRoots(text); err == nil {
			t.Errorf("%s was taken as roots", name)
		}
	}
	for _, iss := range []string{"issuer.example", "/pid", ""} {
		if CanBeNamedByCertificate(iss) == nil {
			t.Errorf("%q was taken as something a certificate can name", iss)
		}
	}
	for _, iss := range []string{testIssuer, "https://issuer.example/pid", "urn:example:issuer"} {
		if err := CanBeNamedByCertificate(iss); err != nil {
			t.Errorf("%q: %v", iss, err)
		}
	}
}
