package oauth

import (
	"net/url"
	"strings"
	"testing"
)

// A request object we do not support is REFUSED, never ignored.
//
// Found by the conformance suite
// (oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported).
// It reported a missing `state` and a mismatched nonce, which are the symptoms
// rather than the cause: the suite had put those values inside the request
// object, the engine read the query instead, and the two disagreed.
//
// Discovery advertises `request_parameter_supported: false`, and not reading a
// parameter is not the same as saying no. Silently ignoring a request object
// leaves the client believing the signed copy was authoritative while every
// value it protected -- state, nonce, redirect_uri, scope -- was taken from the
// unprotected query. A request object exists to provide integrity; dropping it
// without a word removes that guarantee and reports success.

func TestARequestObjectIsRefusedRatherThanIgnored(t *testing.T) {
	for _, tc := range []struct {
		param string
		code  string
	}{
		{"request", "request_not_supported"},
		{"request_uri", "request_uri_not_supported"},
	} {
		t.Run(tc.param, func(t *testing.T) {
			q := url.Values{
				"client_id":             {"app"},
				"redirect_uri":          {"https://app.example.com/cb"},
				"response_type":         {"code"},
				"scope":                 {"openid"},
				"state":                 {"outer-state"},
				"nonce":                 {"outer-nonce"},
				"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
				"code_challenge_method": {"S256"},
				tc.param:                {"eyJhbGciOiJub25lIn0.eyJzdGF0ZSI6ImlubmVyIn0."},
			}
			req := ParseAuthz(q)

			// Parsed at all -- if ParseAuthz dropped it, the validator could never
			// refuse it and this test would pass while the bug remained.
			if tc.param == "request" && req.RequestObject == "" {
				t.Fatal("ParseAuthz did not read the request parameter")
			}
			if tc.param == "request_uri" && req.RequestURI == "" {
				t.Fatal("ParseAuthz did not read the request_uri parameter")
			}

			err := ValidateAuthz(req, testClient(), nil)
			if err == nil {
				t.Fatalf("a %s was accepted. The client believes its signed copy was "+
					"authoritative while every protected value came from the query", tc.param)
			}
			if err.Code != tc.code {
				t.Errorf("error code = %q, want %q (OIDC Core gives this exact code "+
					"for an unsupported request object)", err.Code, tc.code)
			}
			// The refusal must be redirectable, or the client sees an error page at
			// our origin instead of a machine-readable answer at its own.
			if err.Disposition != DispositionRedirect {
				t.Errorf("a %s refusal is not redirected to the client", tc.param)
			}
		})
	}
}

// The ordinary request is untouched: a validator that refused everything would
// pass the test above and break every client.
func TestARequestWithNoRequestObjectStillSucceeds(t *testing.T) {
	q := url.Values{
		"client_id":             {"app"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"s"},
		"nonce":                 {"n"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	if err := ValidateAuthz(ParseAuthz(q), testClient(), nil); err != nil {
		t.Fatalf("a plain authorization request was refused: %v (%s)", err.Code, err.Description)
	}
}

// The description has to tell the client what to do instead.
func TestTheRefusalSaysWhatToDoInstead(t *testing.T) {
	q := url.Values{
		"client_id":             {"app"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"request":               {"eyJhbGciOiJub25lIn0.e30."},
	}
	err := ValidateAuthz(ParseAuthz(q), testClient(), nil)
	if err == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(err.Description, "directly") {
		t.Errorf("the refusal does not say to send the parameters directly: %q",
			err.Description)
	}
}
