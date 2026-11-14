package oid4vp

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testOrigin = "https://verifier.example"

func dcRequest() Request {
	return Request{ClientID: testClientID, ResponseMode: ModeDirectPost, Nonce: testNonce, State: "state-1",
		ResponseURI: "https://verifier.example/response",
		Ask:         Ask{ID: "person", VCTValues: []string{testVCT}, Claims: []Path{{"email"}}}}
}

// Unsigned, the parameters as they are: no client_id, which "MUST be omitted"
// (specs/oid4vp.txt:2496), and nothing the API has no use for.
func TestAnUnsignedBrowserRequestCarriesItsParametersAlone(t *testing.T) {
	protocol, data, err := dcRequest().DCAPI(testOrigin, nil, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if protocol != ProtocolUnsigned {
		t.Errorf("protocol %q", protocol)
	}
	for _, absent := range []string{"client_id", "state", "response_uri", "expected_origins", "request"} {
		if _, ok := data[absent]; ok {
			t.Errorf("an unsigned request carries %s", absent)
		}
	}
	if data["response_mode"] != ModeDCAPI || data["nonce"] != testNonce || data["response_type"] != "vp_token" ||
		data["dcql_query"] == nil || data["client_metadata"] == nil {
		t.Errorf("data %v", data)
	}
}

// Signed, a request object in "request", naming the verifier by its client_id and the one
// origin it may be asked from (:2500, :2505); an encrypted mode becomes dc_api.jwt with the
// key to encrypt to in client_metadata.
func TestASignedBrowserRequestNamesItsOrigin(t *testing.T) {
	leaf, _, key := selfSigned(t, "verifier.example")
	chain := []*x509.Certificate{leaf}
	req := dcRequest()
	req.ResponseMode = ModeDirectPostJWT
	_, public, err := NewResponseKey("state-1")
	if err != nil {
		t.Fatal(err)
	}
	req.EncryptTo = public
	protocol, data, err := req.DCAPI(testOrigin, key, chain, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if protocol != ProtocolSigned || len(data) != 1 {
		t.Fatalf("protocol %q, data %v", protocol, data)
	}
	tok, err := jose.ParseSigned(data["request"].(string), Algorithms())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := tok.Verify(key.Public())
	if err != nil {
		t.Fatalf("the request object is not signed with the request key: %v", err)
	}
	p := string(payload)
	for _, want := range []string{`"client_id":"` + testClientID + `"`, `"expected_origins":["` + testOrigin + `"]`,
		`"response_mode":"dc_api.jwt"`, `"jwks"`} {
		if !strings.Contains(p, want) {
			t.Errorf("the request object lacks %s: %s", want, p)
		}
	}
	for _, absent := range []string{`"state"`, `"response_uri"`} {
		if strings.Contains(p, absent) {
			t.Errorf("the request object carries %s", absent)
		}
	}
}

// What a DigitalCredential's data holds (:2649-2651): the parameters, an encrypted
// response, or an error, and nothing in clear to a request that asked for encryption.
func TestABrowsersAnswerIsReadAsTheRequestAskedForIt(t *testing.T) {
	sealed, public, err := NewResponseKey("state-1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseResponseKey(sealed)
	if err != nil {
		t.Fatal(err)
	}
	const token = `{"person":["eyJ...~"]}`

	if vp, refused, err := ReadDCAPIAnswer([]byte(`{"vp_token":`+token+`}`), nil, ""); err != nil || refused || vp != token {
		t.Errorf("in clear: %q %v %v", vp, refused, err)
	}
	jwe := encryptAs(t, public, "state-1", jose.A128GCM, `{"vp_token":`+token+`}`)
	if vp, _, err := ReadDCAPIAnswer([]byte(`{"response":"`+jwe+`"}`), key, "state-1"); err != nil || vp != token {
		t.Errorf("encrypted: %q %v", vp, err)
	}
	if _, refused, err := ReadDCAPIAnswer([]byte(`{"error":"access_denied"}`), key, "state-1"); err != nil || !refused {
		t.Errorf("an error was read as %v %v", refused, err)
	}
	for name, c := range map[string]struct {
		data string
		key  bool
		kid  string
	}{
		"in clear to an encrypted request":     {data: `{"vp_token":` + token + `}`, key: true, kid: "state-1"},
		"encrypted to an unencrypted request":  {data: `{"response":"` + jwe + `"}`},
		"encrypted to another request's key":   {data: `{"response":"` + jwe + `"}`, key: true, kid: "state-2"},
		"nothing":                              {data: `{}`},
		"not JSON":                             {data: `vp_token`},
		"an encrypted answer holding no token": {data: `{"response":"` + encryptAs(t, public, "state-1", jose.A128GCM, `{}`) + `"}`, key: true, kid: "state-1"},
	} {
		k := key
		if !c.key {
			k = nil
		}
		if _, refused, err := ReadDCAPIAnswer([]byte(c.data), k, c.kid); err == nil || refused {
			t.Errorf("%s was taken", name)
		}
	}
}

func TestAPresentationThroughTheBrowserIsMadeForTheOrigin(t *testing.T) {
	if got := OriginAudience("https://verifier.example"); got != "origin:https://verifier.example" {
		t.Errorf("%q", got)
	}
}
