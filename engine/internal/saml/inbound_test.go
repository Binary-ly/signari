package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// A test upstream IdP: a key, a certificate, and the ability to mint a response
// that our consumer should accept -- so that every failure case below differs
// from a working one by exactly the thing being tested.
type upstream struct {
	key     *rsa.PrivateKey
	certDER []byte
	certPEM string
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "upstream-idp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &upstream{
		key:     key,
		certDER: der,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

type respOpts struct {
	inResponseTo   string
	audience       string
	destination    string
	notBefore      time.Time
	notOnOrAfter   time.Time
	issuer         string
	nameID         string
	nameIDFormat   string
	signAssertion  bool
	signResponse   bool
	omitConditions bool
	omitAudience   bool
	email          string
}

func (u *upstream) response(t *testing.T, o respOpts) []byte {
	t.Helper()
	now := time.Now()
	if o.notBefore.IsZero() {
		o.notBefore = now.Add(-time.Minute)
	}
	if o.notOnOrAfter.IsZero() {
		o.notOnOrAfter = now.Add(5 * time.Minute)
	}
	if o.issuer == "" {
		o.issuer = "https://upstream.test/idp"
	}
	if o.nameID == "" {
		o.nameID = "alice@corp.test"
	}
	if o.nameIDFormat == "" {
		o.nameIDFormat = FullNameIDFormat("emailAddress")
	}

	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	resp.CreateAttr("ID", "_resp-"+fmt.Sprint(now.UnixNano()))
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", now.UTC().Format(time.RFC3339))
	if o.destination != "" {
		resp.CreateAttr("Destination", o.destination)
	}
	if o.inResponseTo != "" {
		resp.CreateAttr("InResponseTo", o.inResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(o.issuer)
	st := resp.CreateElement("samlp:Status")
	st.CreateElement("samlp:StatusCode").
		CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	a := resp.CreateElement("saml:Assertion")
	// Declared on the assertion itself, as real identity providers do: an
	// assertion is signed and canonicalised as a standalone element, and a prefix
	// inherited from the response is not in scope when that happens.
	a.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	a.CreateAttr("ID", "_assert-"+fmt.Sprint(now.UnixNano()))
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", now.UTC().Format(time.RFC3339))
	a.CreateElement("saml:Issuer").SetText(o.issuer)

	sub := a.CreateElement("saml:Subject")
	nid := sub.CreateElement("saml:NameID")
	nid.CreateAttr("Format", o.nameIDFormat)
	nid.SetText(o.nameID)
	sc := sub.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", o.notOnOrAfter.UTC().Format(time.RFC3339))
	if o.inResponseTo != "" {
		scd.CreateAttr("InResponseTo", o.inResponseTo)
	}
	if o.destination != "" {
		scd.CreateAttr("Recipient", o.destination)
	}

	if !o.omitConditions {
		cond := a.CreateElement("saml:Conditions")
		cond.CreateAttr("NotBefore", o.notBefore.UTC().Format(time.RFC3339))
		cond.CreateAttr("NotOnOrAfter", o.notOnOrAfter.UTC().Format(time.RFC3339))
		if !o.omitAudience {
			ar := cond.CreateElement("saml:AudienceRestriction")
			aud := o.audience
			if aud == "" {
				aud = "https://signari.test/sp"
			}
			ar.CreateElement("saml:Audience").SetText(aud)
		}
	}

	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", now.UTC().Format(time.RFC3339))
	as.CreateAttr("SessionIndex", "session-1")

	if o.email != "" {
		stmt := a.CreateElement("saml:AttributeStatement")
		at := stmt.CreateElement("saml:Attribute")
		at.CreateAttr("Name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
		at.CreateElement("saml:AttributeValue").SetText(o.email)
	}

	// Sign whichever element the case calls for, using the same signer the
	// outbound side uses -- so a signature this consumer rejects is a real
	// rejection, not a mismatch of tooling.
	if o.signAssertion {
		signed, err := signElement(a, u.key, u.certDER)
		if err != nil {
			t.Fatal(err)
		}
		resp.RemoveChild(a)
		resp.AddChild(signed)
		a = signed
		if err := moveSignatureAfterIssuer(a); err != nil {
			t.Fatal(err)
		}
	}
	if o.signResponse {
		signed, err := signElement(resp, u.key, u.certDER)
		if err != nil {
			t.Fatal(err)
		}
		doc.SetRoot(signed)
	}

	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func inboundProvider(u *upstream) *InboundProvider {
	return &InboundProvider{
		EntityID:   "https://upstream.test/idp",
		SSOURL:     "https://upstream.test/sso",
		CertPEM:    u.certPEM,
		SPEntityID: "https://signari.test/sp",
		ACSURL:     "https://signari.test/saml/acs",
	}
}

func TestConsumeAcceptsAGoodResponse(t *testing.T) {
	u := newUpstream(t)
	p := inboundProvider(u)
	raw := u.response(t, respOpts{
		inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
		email: "alice@corp.test",
	})

	got, err := ConsumeResponse(raw, p, ConsumeOptions{
		ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("a valid response was refused: %v", err)
	}
	if got.Subject != "alice@corp.test" {
		t.Fatalf("subject %q", got.Subject)
	}
	if got.Email != "alice@corp.test" {
		t.Fatalf("email %q", got.Email)
	}
	if got.SessionIndex != "session-1" {
		t.Fatalf("session index %q", got.SessionIndex)
	}
	if got.AssertionID == "" {
		t.Fatal("no assertion ID, so nothing to replay-check against")
	}
}

// Each case below differs from the accepted response above by ONE thing.
func TestConsumeRefuses(t *testing.T) {
	u := newUpstream(t)
	other := newUpstream(t)

	cases := []struct {
		name string
		// build returns the response and the options to consume it with.
		build func(p *InboundProvider) ([]byte, ConsumeOptions)
		want  string
	}{
		{
			name: "unsigned",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{inResponseTo: "_req-1", destination: p.ACSURL}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "signed",
		},
		{
			name: "signed by a different key",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return other.response(t, respOpts{
						inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "",
		},
		{
			name: "answers a different request",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-OTHER", destination: p.ACSURL, signAssertion: true,
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "not the one this browser sent",
		},
		{
			name: "unsolicited when unsolicited is off",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{destination: p.ACSURL, signAssertion: true}),
					ConsumeOptions{Destination: p.ACSURL, Now: time.Now()}
			},
			want: "unsolicited assertion refused",
		},
		{
			name: "addressed to another service provider",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
						audience: "https://someone-else.test/sp",
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "not to us",
		},
		{
			name: "no audience restriction at all",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
						omitAudience: true,
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "addressed to everybody",
		},
		{
			name: "no conditions at all",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
						omitConditions: true,
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "no Conditions",
		},
		{
			name: "expired",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
						notBefore:    time.Now().Add(-2 * time.Hour),
						notOnOrAfter: time.Now().Add(-time.Hour),
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "expired",
		},
		{
			name: "not valid yet",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
						notBefore:    time.Now().Add(time.Hour),
						notOnOrAfter: time.Now().Add(2 * time.Hour),
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "not valid until",
		},
		{
			name: "addressed to another endpoint",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-1", destination: "https://elsewhere.test/acs",
						signAssertion: true,
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "not to this endpoint",
		},
		{
			name: "issued by a different provider",
			build: func(p *InboundProvider) ([]byte, ConsumeOptions) {
				return u.response(t, respOpts{
						inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
						issuer: "https://impostor.test/idp",
					}),
					ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now()}
			},
			want: "not by the configured provider",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := inboundProvider(u)
			raw, opt := tc.build(p)
			got, err := ConsumeResponse(raw, p, opt)
			if err == nil {
				t.Fatalf("ACCEPTED a response that should be refused (subject %q)",
					got.Subject)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason:\n  got:  %v\n  want: contains %q",
					err, tc.want)
			}
		})
	}
}

// TestUnsolicitedAllowedWhenConfigured proves the escape hatch works, so the
// refusal above is a choice rather than an inability.
func TestUnsolicitedAllowedWhenConfigured(t *testing.T) {
	u := newUpstream(t)
	p := inboundProvider(u)
	p.AllowUnsolicited = true

	raw := u.response(t, respOpts{destination: p.ACSURL, signAssertion: true})
	if _, err := ConsumeResponse(raw, p, ConsumeOptions{
		Destination: p.ACSURL, Now: time.Now(),
	}); err != nil {
		t.Fatalf("unsolicited refused even when allowed: %v", err)
	}
}

// TestResponseLevelSignatureAccepted covers the other legal placement.
func TestResponseLevelSignatureAccepted(t *testing.T) {
	u := newUpstream(t)
	p := inboundProvider(u)
	raw := u.response(t, respOpts{
		inResponseTo: "_req-1", destination: p.ACSURL, signResponse: true,
	})
	if _, err := ConsumeResponse(raw, p, ConsumeOptions{
		ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now(),
	}); err != nil {
		t.Fatalf("a response-level signature was refused: %v", err)
	}
}

// TestSignatureWrapping is the attack this consumer exists to survive.
//
// The attacker takes a legitimately signed assertion and adds a second,
// unsigned one carrying a different subject. Implementations that verify one
// element and read another sign the attacker in as whoever they named.
func TestSignatureWrapping(t *testing.T) {
	u := newUpstream(t)
	p := inboundProvider(u)

	honest := u.response(t, respOpts{
		inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
		nameID: "alice@corp.test",
	})

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(honest); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	signed := root.FindElement("./Assertion")
	if signed == nil {
		t.Fatal("no signed assertion to wrap")
	}

	// A forged assertion naming somebody else, placed FIRST so a naive reader
	// takes it, while the genuine signed one still verifies.
	forged := signed.Copy()
	forged.CreateAttr("ID", "_forged")
	if sig := forged.FindElement("./Signature"); sig != nil {
		forged.RemoveChild(sig)
	}
	if nid := forged.FindElement("./Subject/NameID"); nid != nil {
		nid.SetText("admin@corp.test")
	}
	root.InsertChildAt(0, forged)

	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}

	got, cerr := ConsumeResponse(raw, p, ConsumeOptions{
		ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now(),
	})
	if cerr == nil && got.Subject == "admin@corp.test" {
		t.Fatal("SIGNATURE WRAPPING SUCCEEDED: the forged subject was returned")
	}
	if cerr == nil {
		t.Fatalf("the wrapped document was accepted (subject %q); it must be refused",
			got.Subject)
	}
}

// TestTransientNameIDIsRejectedByCallers documents the check callers must make.
func TestTransientNameIDIsRejectedByCallers(t *testing.T) {
	if err := CheckSubjectFormat(FullNameIDFormat("transient")); err == nil {
		t.Fatal("a transient NameID was accepted as an identifier")
	}
	if err := CheckSubjectFormat(FullNameIDFormat("persistent")); err != nil {
		t.Fatalf("a persistent NameID was refused: %v", err)
	}
	if err := CheckSubjectFormat(FullNameIDFormat("emailAddress")); err != nil {
		t.Fatalf("an email NameID was refused: %v", err)
	}
}

// TestSkewIsBounded stops a large tolerance extending the replay window.
func TestSkewIsBounded(t *testing.T) {
	if got := clampSkew(0); got != 30*time.Second {
		t.Fatalf("default skew %s", got)
	}
	if got := clampSkew(86400); got != 5*time.Minute {
		t.Fatalf("a day of skew was accepted as %s", got)
	}
	if got := clampSkew(60); got != time.Minute {
		t.Fatalf("a minute of skew became %s", got)
	}
}

func TestBuildAuthnRequest(t *testing.T) {
	p := inboundProvider(newUpstream(t))
	req, err := BuildAuthnRequest(p, "relay-123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if req.ID == "" {
		t.Fatal("no request ID, so no response could ever be matched to it")
	}
	if !strings.Contains(req.RedirectURL, "SAMLRequest=") {
		t.Fatalf("no SAMLRequest in %q", req.RedirectURL)
	}
	if !strings.Contains(req.RedirectURL, "RelayState=relay-123") {
		t.Fatalf("no RelayState in %q", req.RedirectURL)
	}
	if !strings.Contains(req.XML, p.ACSURL) {
		t.Fatal("the request does not name our ACS URL")
	}

	// It must survive the round trip the upstream will perform on it.
	q := strings.SplitN(strings.SplitN(req.RedirectURL, "SAMLRequest=", 2)[1], "&", 2)[0]
	decoded, derr := DecodeRedirect(mustUnescape(t, q))
	if derr != nil {
		t.Fatalf("the request we send cannot be decoded by a receiver: %v", derr)
	}
	if !strings.Contains(string(decoded), "AuthnRequest") {
		t.Fatal("the decoded request is not an AuthnRequest")
	}
}

func mustUnescape(t *testing.T, s string) string {
	t.Helper()
	out, err := url.QueryUnescape(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSignatureWrappingVariants runs the payloads a real attacker builds.
//
// The XSW family works by making the verifier and the application look at
// different elements. Each variant below keeps a genuinely signed assertion --
// so the cryptography is sound -- and arranges for a forged one to be the one
// that gets read.
//
// Two different properties, and the test checks them separately because they are
// not the same strength:
//
//	with the full defence          the document is REFUSED
//	with the outermost guard off   no forged subject is ever returned
//
// The second is the one that matters for takeover, and it holds because claims
// are read from the element goxmldsig verified rather than from a second lookup
// in the original tree. The first is what the assertion-count guard adds.
//
// The distinction was found by running this test rather than by reasoning: with
// the guard removed, a forged assertion placed AFTER the signed one is accepted
// -- and yields the honest subject, so the attacker gains nothing, but a
// malformed document is accepted, which is the precondition for the next bug
// rather than a bypass in itself. The guard stays on for that reason.
func TestSignatureWrappingVariants(t *testing.T) {
	u := newUpstream(t)
	p := inboundProvider(u)
	honest := u.response(t, respOpts{
		inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
		nameID: "alice@corp.test",
	})

	forge := func(src *etree.Element, id string) *etree.Element {
		f := src.Copy()
		f.CreateAttr("ID", id)
		if sig := f.FindElement("./Signature"); sig != nil {
			f.RemoveChild(sig)
		}
		f.FindElement("./Subject/NameID").SetText("admin@corp.test")
		return f
	}

	build := func(t *testing.T, mutate func(doc *etree.Document)) []byte {
		t.Helper()
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(honest); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		out, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	cases := []struct {
		name   string
		mutate func(doc *etree.Document)
	}{
		{
			// The forged assertion first, so a reader taking "the assertion" takes it.
			name: "forged assertion placed before the signed one",
			mutate: func(doc *etree.Document) {
				r := doc.Root()
				r.InsertChildAt(0, forge(r.FindElement("./Assertion"), "_forged"))
			},
		},
		{
			// The forged assertion second, so the signed one is found first. This is
			// the variant that must not merely be refused: it must not sign anybody
			// in as the forged subject.
			name: "forged assertion placed after the signed one",
			mutate: func(doc *etree.Document) {
				r := doc.Root()
				r.AddChild(forge(r.FindElement("./Assertion"), "_forged"))
			},
		},
		{
			// The signed assertion hidden where a verifier still finds it and a
			// reader does not -- the classic payload.
			name: "signed assertion hidden inside Extensions",
			mutate: func(doc *etree.Document) {
				r := doc.Root()
				signed := r.FindElement("./Assertion")
				forged := forge(signed, "_forged")
				r.RemoveChild(signed)
				ext := r.CreateElement("samlp:Extensions")
				ext.AddChild(signed)
				r.AddChild(forged)
			},
		},
		{
			// The forged assertion nested inside the signed one, so it is covered by
			// the signature's own subtree.
			name: "forged assertion nested inside the signed one",
			mutate: func(doc *etree.Document) {
				signed := doc.Root().FindElement("./Assertion")
				signed.AddChild(forge(signed, "_forged"))
			},
		},
		{
			// Same ID on both, so the reference resolves to whichever the parser
			// happens to reach first.
			name: "duplicate IDs",
			mutate: func(doc *etree.Document) {
				r := doc.Root()
				signed := r.FindElement("./Assertion")
				dup := forge(signed, signed.SelectAttrValue("ID", ""))
				r.InsertChildAt(0, dup)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := build(t, tc.mutate)

			// Twice: with the outermost guard, and without it. The second run is
			// the one that proves the defence is layered rather than a single
			// check standing between an attacker and an account.
			for _, guard := range []bool{true, false} {
				refuseMultipleAssertions = guard
				got, err := ConsumeResponse(raw, p, ConsumeOptions{
					ExpectedInResponseTo: "_req-1", Destination: p.ACSURL, Now: time.Now(),
				})
				// The forged subject must never be returned, under either
				// configuration. This is the takeover property.
				if err == nil && got.Subject == "admin@corp.test" {
					t.Fatal("SIGNATURE WRAPPING SUCCEEDED: signed in as the forged subject")
				}
				if guard {
					// And with the full defence in place, the document is refused
					// outright rather than merely rendered harmless.
					if err == nil {
						t.Fatalf("a wrapped document was accepted (subject %q)", got.Subject)
					}
					t.Logf("refused: %v", err)
					continue
				}
				if err != nil {
					t.Logf("still refused without the count guard: %v", err)
				} else {
					t.Logf("accepted without the count guard, but harmless: subject %q",
						got.Subject)
				}
			}
			refuseMultipleAssertions = true
		})
	}
}
