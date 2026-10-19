package httpapi

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// What `signari saml signing` set is what the provider receives (2.05). The
// two flags were loaded and read by nothing, so every response signed the
// assertion only, and a provider requiring a signed Response refused them all.
func TestAProviderIsSentTheSignaturesItWasSetTo(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()

	respond := func(assertions, responses bool) string {
		t.Helper()
		if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers
			SET sign_assertions = $2, sign_responses = $3 WHERE entity_id = $1`,
			rf.own, assertions, responses); err != nil {
			t.Fatal(err)
		}
		doc := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_sign-%d" Version="2.0"
 IssueInstant="%s" Destination="https://signin-test.example/saml/sso"
 AssertionConsumerServiceURL="https://sp.test/acs"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
			time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), rf.own)
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.BestCompression)
		_, _ = w.Write([]byte(doc))
		_ = w.Close()
		r := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+
			url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes())), nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		m := samlResponseField.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("no SAMLResponse in a %d answer: %.300s", rec.Code, rec.Body.String())
		}
		xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		return string(xml)
	}
	// Where each signature is: the Response's comes before its Status, the
	// assertion's after it.
	signatures := func(doc string) (response, assertion bool) {
		status := strings.Index(doc, "<samlp:Status>")
		for i := 0; ; {
			j := strings.Index(doc[i:], "<ds:Signature ")
			if j < 0 {
				return response, assertion
			}
			if i+j < status {
				response = true
			} else {
				assertion = true
			}
			i += j + 1
		}
	}

	for _, c := range []struct{ assertions, responses bool }{
		{true, false}, {true, true}, {false, true},
	} {
		resp, asrt := signatures(respond(c.assertions, c.responses))
		if resp != c.responses || asrt != c.assertions {
			t.Errorf("set to sign assertions %v and responses %v, the provider was sent "+
				"a signed Response %v and a signed assertion %v",
				c.assertions, c.responses, resp, asrt)
		}
	}
}
