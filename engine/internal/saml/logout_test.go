package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"
)

// spSigner stands in for a service provider: its own key, and the certificate
// we would have registered for it.
func spSigner(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := selfSign("https://sp.example.com", key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// signRedirect builds a redirect-binding query the way a service provider does:
// sign the octets of the parameters in the fixed order, then append Signature.
func signRedirect(t *testing.T, key *rsa.PrivateKey, samlRequest, relayState string) string {
	t.Helper()
	parts := []string{"SAMLRequest=" + url.QueryEscape(samlRequest)}
	if relayState != "" {
		parts = append(parts, "RelayState="+url.QueryEscape(relayState))
	}
	parts = append(parts, "SigAlg="+url.QueryEscape(sigAlgRSASHA256))
	signed := strings.Join(parts, "&")

	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

func TestRedirectSignatureVerifies(t *testing.T) {
	key, certPEM := spSigner(t)
	q := signRedirect(t, key, "deflated-request-bytes", "state123")
	if err := VerifyRedirectSignature(q, certPEM, "SAMLRequest"); err != nil {
		t.Fatalf("a correctly signed request was refused: %v", err)
	}
}

func TestRedirectSignatureWithoutRelayState(t *testing.T) {
	key, certPEM := spSigner(t)
	q := signRedirect(t, key, "deflated-request-bytes", "")
	if err := VerifyRedirectSignature(q, certPEM, "SAMLRequest"); err != nil {
		t.Fatalf("refused a signed request that carried no RelayState: %v", err)
	}
}

// TestUnsignedLogoutRequestIsRefused is gosaml2 GHSA-pcgw-qcv5-h8ch. Accepting
// this means anybody can sign anybody out, with no credential whatsoever.
func TestUnsignedLogoutRequestIsRefused(t *testing.T) {
	_, certPEM := spSigner(t)
	q := "SAMLRequest=" + url.QueryEscape("deflated-request-bytes")
	err := VerifyRedirectSignature(q, certPEM, "SAMLRequest")
	if err == nil {
		t.Fatal("an UNSIGNED LogoutRequest was accepted")
	}
	if !strings.Contains(err.Error(), "not signed") {
		t.Errorf("the error should say the request was unsigned; got %v", err)
	}
}

// TestTamperedRequestIsRefused: the signature must actually cover the message.
func TestTamperedRequestIsRefused(t *testing.T) {
	key, certPEM := spSigner(t)
	q := signRedirect(t, key, "deflated-request-bytes", "state123")
	tampered := strings.Replace(q, "deflated-request-bytes", "different-request-bytes", 1)
	if tampered == q {
		t.Fatal("the fixture did not change; this test proves nothing")
	}
	if err := VerifyRedirectSignature(tampered, certPEM, "SAMLRequest"); err == nil {
		t.Fatal("a request whose contents were changed after signing was accepted")
	}
}

// TestRelayStateTamperingIsRefused -- RelayState is inside the signed octets, so
// changing it must break the signature too.
func TestRelayStateTamperingIsRefused(t *testing.T) {
	key, certPEM := spSigner(t)
	q := signRedirect(t, key, "req", "state123")
	tampered := strings.Replace(q, "state123", "state999", 1)
	if err := VerifyRedirectSignature(tampered, certPEM, "SAMLRequest"); err == nil {
		t.Fatal("RelayState was changed after signing and the request was still accepted")
	}
}

// TestSignatureFromAnotherKeyIsRefused: a valid signature by the wrong party.
func TestSignatureFromAnotherKeyIsRefused(t *testing.T) {
	attacker, _ := spSigner(t)
	_, victimCertPEM := spSigner(t)
	q := signRedirect(t, attacker, "req", "state")
	if err := VerifyRedirectSignature(q, victimCertPEM, "SAMLRequest"); err == nil {
		t.Fatal("a request signed by a different key was accepted")
	}
}

// TestSHA1IsRefused. Chosen-prefix collisions against SHA-1 are practical, and
// a warning nobody reads is not a control.
func TestSHA1IsRefused(t *testing.T) {
	key, certPEM := spSigner(t)
	signed := "SAMLRequest=req&SigAlg=" + url.QueryEscape(sigAlgRSASHA1)
	sum := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	q := signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	err := VerifyRedirectSignature(q, certPEM, "SAMLRequest")
	if err == nil {
		t.Fatal("an RSA-SHA1 signature was accepted")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("the error should say what to configure instead; got %v", err)
	}
}

// TestNoRegisteredCertificateRefuses. Without a certificate there is nothing to
// verify against, and "verify against nothing" means "accept anything".
func TestNoRegisteredCertificateRefuses(t *testing.T) {
	key, _ := spSigner(t)
	q := signRedirect(t, key, "req", "")
	err := VerifyRedirectSignature(q, "", "SAMLRequest")
	if err == nil {
		t.Fatal("a request was verified against no certificate at all")
	}
	if !strings.Contains(err.Error(), "no signing certificate") {
		t.Errorf("the error should explain what to register; got %v", err)
	}
}

// TestSignedOctetsUseTheRawQuery is the subtle one.
//
// The signature covers the parameters percent-encoded exactly as the sender
// wrote them. Rebuilding the string from a parsed map re-encodes with a
// different escaping set and sorts the keys, so the bytes verified are not the
// bytes signed -- every legitimate request then fails.
func TestSignedOctetsUseTheRawQuery(t *testing.T) {
	// A RelayState with characters implementations disagree about encoding.
	raw := "SAMLRequest=abc%2Bdef&RelayState=a+b%7Ec&SigAlg=" + url.QueryEscape(sigAlgRSASHA256)
	got, err := signedOctets(raw+"&Signature=zzz", "SAMLRequest")
	if err != nil {
		t.Fatal(err)
	}
	if got != raw {
		t.Errorf("signedOctets re-encoded the query.\n got: %s\nwant: %s", got, raw)
	}
}

// TestSignedOctetsKeepSpecOrder. The order is fixed by the specification, not by
// the order the parameters happen to appear in.
func TestSignedOctetsKeepSpecOrder(t *testing.T) {
	raw := "SigAlg=x&Signature=zzz&RelayState=rs&SAMLRequest=req"
	got, err := signedOctets(raw, "SAMLRequest")
	if err != nil {
		t.Fatal(err)
	}
	if want := "SAMLRequest=req&RelayState=rs&SigAlg=x"; got != want {
		t.Errorf("signedOctets = %q, want %q", got, want)
	}
}

func TestValidateLogoutRequest(t *testing.T) {
	p := testProvider()
	const dest = "https://auth.example.com/saml/slo"
	base := func() *LogoutRequest {
		return &LogoutRequest{
			ID: "_lo1", Version: "2.0",
			IssueInstant: time.Now().UTC().Format(time.RFC3339),
			Destination:  dest,
			Issuer:       p.EntityID,
			NameID:       "opaque-name-id",
			SessionIndex: "sess-1",
		}
	}
	if _, err := ValidateLogoutRequest(base(), p, dest, time.Now()); err != nil {
		t.Fatalf("a valid LogoutRequest was refused: %v", err)
	}

	bad := map[string]func(*LogoutRequest){
		"wrong issuer":      func(r *LogoutRequest) { r.Issuer = "https://evil.test/md" },
		"wrong destination": func(r *LogoutRequest) { r.Destination = "https://other-idp.test/slo" },
		"no subject":        func(r *LogoutRequest) { r.NameID = "" },
		"no id":             func(r *LogoutRequest) { r.ID = "" },
		"wrong version":     func(r *LogoutRequest) { r.Version = "1.1" },
		"stale": func(r *LogoutRequest) {
			r.IssueInstant = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			r := base()
			mutate(r)
			if _, err := ValidateLogoutRequest(r, p, dest, time.Now()); err == nil {
				t.Errorf("accepted a LogoutRequest with %s", name)
			}
		})
	}
}

func TestBuildLogoutRequestRefusesAnEmptySubject(t *testing.T) {
	key, certDER := testSigner(t)
	_, err := BuildLogoutRequest(LogoutRequestInput{
		Issuer: "https://auth.example.com/saml", Destination: "https://sp.example.com/slo",
		Now: time.Now(),
	}, key, certDER)
	if err == nil {
		t.Fatal("built a LogoutRequest with no NameID; the provider would end nothing " +
			"and the failure would look like success")
	}
}

func TestLogoutDocumentsAreSignedOnce(t *testing.T) {
	key, certDER := testSigner(t)

	req, err := BuildLogoutRequest(LogoutRequestInput{
		Issuer: "https://auth.example.com/saml", Destination: "https://sp.example.com/slo",
		NameID: "opaque", NameIDFormat: NameIDFormatPersistent, SessionIndex: "s1",
		Now: time.Now(),
	}, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BuildLogoutResponse(LogoutResponseInput{
		Issuer: "https://auth.example.com/saml", Destination: "https://sp.example.com/slo",
		InResponse: "_lo1", Now: time.Now(),
	}, key, certDER)
	if err != nil {
		t.Fatal(err)
	}

	for name, doc := range map[string]string{"LogoutRequest": req, "LogoutResponse": resp} {
		if n := strings.Count(doc, "<ds:Signature "); n != 1 {
			t.Errorf("%s has %d signatures, want 1", name, n)
		}
		if !strings.Contains(doc, "</saml:Issuer><ds:Signature ") {
			t.Errorf("%s: the signature does not immediately follow Issuer, which the "+
				"schema fixes and strict providers enforce", name)
		}
	}
}

// TestRedirectSignRoundTrip: what we send must verify under the same rules we
// apply to what we receive.
//
// Signing and verifying are separate code paths that must agree byte for byte
// about percent-encoding, parameter order and which parameters are covered.
// Testing each against a fixture would let a SHARED misunderstanding pass both;
// running them against each other is what catches that.
func TestRedirectSignRoundTrip(t *testing.T) {
	key, certDER := testSigner(t)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	doc, err := BuildLogoutRequest(LogoutRequestInput{
		Issuer: "https://auth.example.com/saml", Destination: "https://sp.example.com/slo",
		NameID: "opaque", NameIDFormat: NameIDFormatPersistent, SessionIndex: "s1",
		Now: time.Now(),
	}, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRedirect(doc)
	if err != nil {
		t.Fatal(err)
	}

	// RelayState values chosen for characters whose encoding implementations
	// disagree about -- the exact place a sign/verify mismatch shows up.
	for _, rs := range []string{"", "plain", "a b~c", "a+b/c=d", "%41%42", "tok/en+1="} {
		t.Run("relaystate="+rs, func(t *testing.T) {
			q, err := SignRedirectQuery("SAMLRequest", encoded, rs, key)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyRedirectSignature(q, certPEM, "SAMLRequest"); err != nil {
				t.Fatalf("our own signed query failed our own verification: %v\nquery: %s", err, q)
			}
			// And the receiver must recover exactly what we sent.
			vals, err := url.ParseQuery(q)
			if err != nil {
				t.Fatal(err)
			}
			if got := vals.Get("RelayState"); got != rs {
				t.Errorf("RelayState round-tripped as %q, want %q", got, rs)
			}
			back, err := DecodeRedirect(vals.Get("SAMLRequest"))
			if err != nil {
				t.Fatalf("our own encoded document did not decode: %v", err)
			}
			if string(back) != doc {
				t.Error("the document did not survive the encode/decode round trip")
			}
		})
	}
}

// TestReEncodingTheQueryBreaksTheSignature.
//
// The point of taking raw substrings rather than a parsed map. A RelayState
// written as %41%42 decodes to "AB", and re-encoding produces "AB" -- different
// bytes from what was signed. An implementation that rebuilds the query before
// verifying rejects requests that are perfectly valid.
//
// Deterministic by construction: the fixture uses an encoding Go's own encoder
// would never emit, so the rebuilt string is guaranteed to differ.
func TestReEncodingTheQueryBreaksTheSignature(t *testing.T) {
	key, certPEM := spSigner(t)

	// Signed with RelayState percent-encoded the long way, as some senders do.
	signed := "SAMLRequest=req&RelayState=%41%42&SigAlg=" + url.QueryEscape(sigAlgRSASHA256)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	q := signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))

	if err := VerifyRedirectSignature(q, certPEM, "SAMLRequest"); err != nil {
		t.Fatalf("the query as sent did not verify: %v", err)
	}

	// Now the mistake: parse and re-encode before verifying.
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := vals.Encode()
	if strings.Contains(rebuilt, "%41%42") {
		t.Fatal("Go re-emitted %41%42; the fixture no longer demonstrates the difference")
	}
	if err := VerifyRedirectSignature(rebuilt, certPEM, "SAMLRequest"); err == nil {
		t.Error("a re-encoded query still verified, so this test cannot show why the " +
			"raw substrings matter -- check signedOctets is not normalising")
	}
}
