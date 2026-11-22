package oid4vp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func selfSigned(t *testing.T, dns ...string) (*x509.Certificate, string, *ecdsa.PrivateKey) {
	t.Helper()
	k := genKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "verifier"},
		DNSNames: dns, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), k
}

func TestTheClientIDIsDerivedAsEachPrefixSays(t *testing.T) {
	leaf, _, _ := selfSigned(t, "verifier.example")
	const resp = "https://verifier.example/oid4vp/x/response"

	if id, err := ClientID(PrefixX509SANDNS, resp, leaf); err != nil || id != "x509_san_dns:verifier.example" {
		t.Errorf("x509_san_dns: %q %v", id, err)
	}
	sum := sha256.Sum256(leaf.Raw)
	if id, err := ClientID(PrefixX509Hash, resp, leaf); err != nil ||
		id != "x509_hash:"+base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("x509_hash: %q %v", id, err)
	}
	if id, err := ClientID(PrefixRedirectURI, resp, nil); err != nil || id != "redirect_uri:"+resp {
		t.Errorf("redirect_uri: %q %v", id, err)
	}
	// The wallet holds the response URI's host to the certificate's name
	// (specs/oid4vp.txt:670), so a certificate for another name is refused here,
	// where the operator can be told, and not by every wallet.
	if _, err := ClientID(PrefixX509SANDNS, "https://other.example/r", leaf); err == nil {
		t.Error("a certificate for another host was taken")
	}
	if _, err := ClientID(PrefixRedirectURI, "http://verifier.example/r", nil); err == nil {
		t.Error("a plain-http response URI was taken")
	}
	if _, err := ParsePrefix("did"); err == nil {
		t.Error("an unknown prefix parsed")
	}
}

func TestTheRequestObjectIsSignedAndTyped(t *testing.T) {
	leaf, chainPEM, key := selfSigned(t, "verifier.example")
	chain, err := ParseChain(chainPEM)
	if err != nil || len(chain) != 1 {
		t.Fatalf("%v %d", err, len(chain))
	}
	now := time.Unix(1_800_000_000, 0)
	req := Request{ClientID: "x509_san_dns:verifier.example", ResponseURI: "https://verifier.example/r",
		ResponseMode: ModeDirectPost, Nonce: "n", State: "s", WalletNonce: "w",
		Ask: Ask{ID: "person", VCTValues: []string{testVCT}, Claims: []Path{{"email"}}}}
	signed, err := Sign(req.Parameters(now), key, chain)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jose.ParseSigned(signed, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	h := tok.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != TypRequest {
		t.Errorf("typ %q", typ)
	}
	// go-jose decodes x5c as base64 DER, so a chain coming back is the check that
	// it was not written as base64url.
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	chains, err := h.Certificates(x509.VerifyOptions{Roots: roots})
	if err != nil || len(chains) == 0 || !chains[0][0].Equal(leaf) {
		t.Errorf("x5c: %v %v", chains, err)
	}
	payload, err := tok.Verify(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(payload, &p)
	for k, want := range map[string]any{"client_id": req.ClientID, "response_type": "vp_token",
		"response_mode": "direct_post", "response_uri": req.ResponseURI, "nonce": "n", "state": "s",
		"wallet_nonce": "w", "aud": "https://self-issued.me/v2"} {
		if p[k] != want {
			t.Errorf("%s = %v, want %v", k, p[k], want)
		}
	}
	if _, ok := p["redirect_uri"]; ok {
		t.Error("redirect_uri beside response_uri, which a wallet answers invalid_request (specs/oid4vp.txt:1361)")
	}
	q, _ := json.Marshal(p["dcql_query"])
	if !strings.Contains(string(q), `"vct_values":["`+testVCT+`"]`) || !strings.Contains(string(q), `"format":"dc+sd-jwt"`) {
		t.Errorf("dcql_query %s", q)
	}

	// The key must be the certificate's.
	_, _, otherKey := selfSigned(t, "verifier.example")
	if _, err := Sign(req.Parameters(now), otherKey, chain); err == nil {
		t.Error("a request was signed with a key its certificate is not for")
	}
}

func TestTheWalletIsSentAReferenceOrEveryParameter(t *testing.T) {
	req := Request{ClientID: "x509_hash:abc", ResponseURI: "https://v.example/r", ResponseMode: ModeDirectPost,
		Nonce: "n", State: "s", Ask: Ask{ID: "p", VCTValues: []string{testVCT}}}
	ref, err := req.URL("openid4vp://", "https://v.example/request/s", true)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(ref)
	if q := u.Query(); len(q) != 4 || q.Get("client_id") != "x509_hash:abc" ||
		q.Get("request_uri") != "https://v.example/request/s" || q.Get("request_uri_method") != "post" ||
		!strings.Contains(q.Get("client_metadata"), "vp_formats_supported") {
		t.Errorf("by reference: %s", ref)
	}
	if get, _ := req.URL("openid4vp://", "https://v.example/request/s", false); strings.Contains(get, "client_metadata") {
		t.Errorf("a request fetched by GET carries client_metadata: %s", get)
	}
	byValue, err := req.URL("https://wallet.example/authorize", "", false)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(byValue)
	var dcql map[string]any
	if err := json.Unmarshal([]byte(u.Query().Get("dcql_query")), &dcql); err != nil || u.Query().Get("nonce") != "n" {
		t.Errorf("by value: %s %v", byValue, err)
	}
	if u.Query().Get("aud") != "" {
		t.Error("a request in the query carries a request object's aud")
	}
}

// The example of section 7.3, applied as section 7.1.1 says.
func TestAClaimsPathSelectsAsTheSpecificationShows(t *testing.T) {
	var cred map[string]any
	_ = json.Unmarshal([]byte(`{"name":"Arthur Dent","address":{"street_address":"42 Market Street",
		"locality":"Milliways","postal_code":"12345"},"degrees":[{"type":"Bachelor of Science",
		"university":"University of Betelgeuse"},{"type":"Master of Science","university":"University of Betelgeuse"}],
		"nationalities":["British","Betelgeusian"]}`), &cred)
	for _, c := range []struct {
		path string
		want []any
	}{
		{`["name"]`, []any{"Arthur Dent"}},
		{`["address","street_address"]`, []any{"42 Market Street"}},
		{`["degrees",null,"type"]`, []any{"Bachelor of Science", "Master of Science"}},
		{`["nationalities",1]`, []any{"Betelgeusian"}},
		{`name`, []any{"Arthur Dent"}},
	} {
		p, err := ParsePath(c.path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Select(cred, p)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(c.want)
		if string(g) != string(w) {
			t.Errorf("%s selected %s, want %s", c.path, g, w)
		}
	}
	for _, bad := range []string{`["name","first"]`, `["address",0]`, `["nationalities",5]`, `["missing"]`, `["degrees","type"]`} {
		p, _ := ParsePath(bad)
		if _, err := Select(cred, p); err == nil {
			t.Errorf("%s selected something", bad)
		}
	}
	for _, bad := range []string{``, `[]`, `["a",-1]`, `["a",1.5]`, `[{"a":1}]`, `[`} {
		if _, err := ParsePath(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestAnAskNoWalletCouldAnswerIsRefused(t *testing.T) {
	for _, a := range []Ask{
		{ID: "", VCTValues: []string{testVCT}},
		{ID: "has space", VCTValues: []string{testVCT}},
		{ID: "p"},
		{ID: "p", VCTValues: []string{""}},
		{ID: "p", VCTValues: []string{testVCT}, Claims: []Path{{"email"}, {"email"}}},
	} {
		if err := a.Validate(); err == nil {
			t.Errorf("%+v was valid", a)
		}
	}
	if err := (Ask{ID: "person_1", VCTValues: []string{testVCT}, Claims: []Path{{"email"}}}).Validate(); err != nil {
		t.Error(err)
	}
}
