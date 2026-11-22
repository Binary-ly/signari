package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ecpRequest is what an ECP brings: the provider's AuthnRequest, in a SOAP body.
func ecpRequest(issuer, acs, binding, extra string) string {
	return fmt.Sprintf(`<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Body>`+
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `+
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_ecp-%d" Version="2.0" IssueInstant="%s" `+
		`AssertionConsumerServiceURL="%s" ProtocolBinding="%s">`+
		`<saml:Issuer>%s</saml:Issuer>%s</samlp:AuthnRequest></S:Body></S:Envelope>`,
		time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), acs, binding, issuer, extra)
}

const bindingPAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"

// A client that is not a browser signs a person in to a provider that takes
// ECP: the AuthnRequest in, the person by Basic, the Response out in a SOAP
// body with the ECP header naming the provider's PAOS endpoint. Nothing gets
// through without the right password, or to a provider with no PAOS endpoint
// (8.08).
func TestAnECPSignsAPersonIn(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	if _, err := rf.f.pool.Exec(ctx, `
		INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
		SELECT id, 'https://sp.test/ecp', 'PAOS', false FROM core.saml_providers WHERE entity_id = $1`,
		rf.own); err != nil {
		t.Fatal(err)
	}
	send := func(body, user, password string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/saml/ecp", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")
		if user != "" {
			r.SetBasicAuth(user, password)
		}
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	request := ecpRequest(rf.own, "https://sp.test/ecp", bindingPAOS, "")

	if rec := send(request, "", ""); rec.Code != http.StatusUnauthorized ||
		!strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("no credentials: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if rec := send(request, rf.f.email, "not the password"); rec.Code != http.StatusUnauthorized ||
		strings.Contains(rec.Body.String(), "Assertion") {
		t.Errorf("a wrong password: %d", rec.Code)
	}

	rec := send(request, rf.f.email, signInTestPassword)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("the right password: %d %.300s", rec.Code, body)
	}
	for _, want := range []string{`<ecp:Response soap11:mustUnderstand="1"`,
		`soap11:actor="http://schemas.xmlsoap.org/soap/actor/next"`,
		`AssertionConsumerServiceURL="https://sp.test/ecp"`, "<samlp:Response ", "<saml:Assertion ",
		"status:Success", `Destination="https://sp.test/ecp"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer lacks %s", want)
		}
	}
	if strings.Contains(body, "SessionIndex") {
		t.Error("an ECP assertion names a session that does not exist")
	}

	// Asked for a second factor with a password alone: refused in SAML, to the provider.
	mfa := ecpRequest(rf.own, "https://sp.test/ecp", bindingPAOS,
		`<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>`+
			`urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`)
	if rec := send(mfa, rf.f.email, signInTestPassword); !strings.Contains(rec.Body.String(), "NoAuthnContext") ||
		strings.Contains(rec.Body.String(), "<saml:Assertion ") {
		t.Errorf("a demand for a second factor met by a password: %d %.300s", rec.Code, rec.Body.String())
	}

	// Not to a URL registered for POST, and not for a provider with no PAOS endpoint.
	for name, bad := range map[string]string{
		"a POST URL":         ecpRequest(rf.own, "https://sp.test/acs", bindingPAOS, ""),
		"a POST URL by POST": ecpRequest(rf.own, "https://sp.test/acs", "", ""),
		"no PAOS endpoint":   ecpRequest(rf.foreign, "https://sp.test/ecp", bindingPAOS, ""),
		"not a SOAP request": "<nothing/>",
	} {
		if rec := send(bad, rf.f.email, signInTestPassword); rec.Code != http.StatusInternalServerError ||
			strings.Contains(rec.Body.String(), "<saml:Assertion ") {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}
