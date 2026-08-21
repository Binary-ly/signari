package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// RFC 6749 §3.1: "Request and response parameters MUST NOT be included more than
// once." ASVS 5.0.0 V15.3.7 asks the same thing as parameter-pollution defence.
//
// This codebase already knew why it mattered — the reasoning was written at the
// PAR endpoint — and applied it **only** there. The authorization endpoint and
// the token endpoint had no check at all, which is where a duplicate
// `redirect_uri` or `code` actually gets acted on.
//
// The PAR guard also had the opposite flaw: it refused EVERY repeat, including
// `resource`, which RFC 8707 §2 permits more than once and which this server
// reads as a list everywhere else.

func TestDuplicateParametersAreRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		values  url.Values
		wantErr bool
	}{
		"single values":           {url.Values{"client_id": {"a"}, "scope": {"openid"}}, false},
		"duplicate redirect_uri":  {url.Values{"redirect_uri": {"https://good", "https://evil"}}, true},
		"duplicate code":          {url.Values{"code": {"a", "b"}}, true},
		"duplicate client_id":     {url.Values{"client_id": {"a", "b"}}, true},
		"repeated resource is ok": {url.Values{"resource": {"https://a", "https://b"}}, false},
		"repeated audience is ok": {url.Values{"audience": {"a", "b"}}, false},
		"resource plus a dupe":    {url.Values{"resource": {"a", "b"}, "scope": {"x", "y"}}, true},
		"empty":                   {url.Values{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := refuseDuplicateParams(tc.values)
			if tc.wantErr && err == nil {
				t.Error("accepted a duplicate parameter")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("refused a legitimate request: %v", err)
			}
		})
	}
}

// The endpoint the rule exists for. A request carrying two `redirect_uri` values
// must not be answered by redirecting to either of them.
func TestTheAuthorizationEndpointRefusesDuplicateRedirectURIs(t *testing.T) {
	f := newTokenFixture(t)

	q := url.Values{
		"client_id":     {f.clientID},
		"response_type": {"code"},
		"scope":         {"openid"},
		"redirect_uri":  {"https://rp.test/cb", "https://evil.test/cb"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	// Not a redirect, to either of them.
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("the request was answered with a redirect to %q; a request whose "+
			"redirect_uri appears twice has no trustworthy destination, and "+
			"answering with one of the two is precisely the pollution this "+
			"refuses", loc)
	}
	if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), "appears 2 times") {
		t.Errorf("the duplicate was not reported: %d %s", rec.Code, truncate(rec.Body.String(), 200))
	}
}

// And the token endpoint, where a duplicate `code` would be redeemed.
func TestTheTokenEndpointRefusesDuplicateParameters(t *testing.T) {
	f := newTokenFixture(t)

	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"one", "two"},
		"client_id":  {f.clientID},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", status, body)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", body["error"])
	}
	if d, _ := body["error_description"].(string); !strings.Contains(d, "appears 2 times") {
		t.Errorf("description = %q; it should name the offending parameter", d)
	}
}

// A conformant RFC 8707 request must still work. Refusing it was the other half
// of the defect: the PAR guard treated a repeated `resource` as pollution.
func TestRepeatedResourceIndicatorsAreAccepted(t *testing.T) {
	f := newTokenFixture(t)

	q := url.Values{
		"client_id":     {f.clientID},
		"response_type": {"code"},
		"scope":         {"openid"},
		"redirect_uri":  {"https://rp.test/cb"},
		"resource":      {"https://api.one.test", "https://api.two.test"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "appears 2 times") {
		t.Errorf("two `resource` values were refused as duplicates; RFC 8707 §2 "+
			"permits the parameter more than once, and this server reads it as a "+
			"list everywhere else: %s", truncate(rec.Body.String(), 200))
	}
}
