package oauth

import (
	"net/url"
	"strings"
	"testing"
)

// A §7.1.1 signed authentication request must be refused, not ignored.
//
// CIBA §4 makes backchannel_authentication_request_signing_alg_values_supported
// OPTIONAL and says "If omitted, signed authentication requests are not
// supported by the OP". We omit it — so the endpoint must agree with the
// document rather than quietly accepting the request and reading around the JWT.
func TestSignedCIBARequestIsRefused(t *testing.T) {
	for _, param := range []string{"request", "request_uri"} {
		form := url.Values{
			"scope":      {"openid"},
			"login_hint": {"alice@example.test"},
			param:        {"eyJhbGciOiJSUzI1NiJ9.e30.sig"},
		}
		_, err := ParseCIBARequest(form, "cli", DeliveryPoll)
		if err == nil {
			t.Errorf("%s was accepted; the signed parameters would have been "+
				"silently replaced by the unsigned form values beside them", param)
			continue
		}
		if !strings.Contains(err.Description, param) {
			t.Errorf("the refusal for %s does not name the parameter: %s",
				param, err.Description)
		}
	}
}

// The failure this prevents, stated as a test.
//
// A client that signs its request object and ALSO sends plaintext copies — which
// clients do, for compatibility with servers that take either — must not have the
// signed values dropped. Before this check, the form's binding_message won and
// the signature protected nothing.
func TestASignedRequestBesideFormValuesDoesNotSilentlyUseTheFormValues(t *testing.T) {
	form := url.Values{
		"scope":           {"openid"},
		"login_hint":      {"alice@example.test"},
		"binding_message": {"attacker-supplied"},
		"request":         {"eyJhbGciOiJSUzI1NiJ9.e30.sig"},
	}
	req, err := ParseCIBARequest(form, "cli", DeliveryPoll)
	if err == nil {
		t.Fatalf("the request was accepted with binding_message %q taken from the "+
			"form while a signed request object was present and discarded",
			req.BindingMessage)
	}
}

// The control: an ordinary unsigned request must still work.
func TestAnOrdinaryCIBARequestStillWorks(t *testing.T) {
	form := url.Values{
		"scope":      {"openid"},
		"login_hint": {"alice@example.test"},
	}
	req, err := ParseCIBARequest(form, "cli", DeliveryPoll)
	if err != nil {
		t.Fatalf("an ordinary request was refused: %s", err.Description)
	}
	if req.Hint != "alice@example.test" {
		t.Errorf("hint = %q", req.Hint)
	}
}
