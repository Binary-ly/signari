package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ASVS 5.0.0 V3.5.2: an endpoint defended by CORS preflight must not be callable
// with a request that triggers no preflight.
//
// The WebAuthn ceremony endpoints are cookie-authenticated and carry no CSRF
// token, relying instead on `SameSite=Lax`, `corsNone`, and WebAuthn's own origin
// binding. The middle one was bypassable: `Content-Type: application/json`
// forces a preflight, but `text/plain` is CORS-safelisted and a plain HTML form
// can send it — and a form body can be crafted to be valid JSON. The handlers
// decoded whatever arrived without looking at the content type, so the preflight
// they relied on was optional.
func TestWebAuthnEndpointsRequireTheJSONContentType(t *testing.T) {
	f := newTokenFixture(t)

	// The shape a cross-site form produces: a CORS-safelisted content type
	// carrying a body that happens to be valid JSON.
	for _, path := range []string{
		"/account/passkeys/begin",
		"/account/passkeys/finish",
		"/login/passkey/begin",
		"/login/passkey/finish",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"a":1}`))
			req.Header.Set("Content-Type", "text/plain")
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnsupportedMediaType {
				t.Errorf("status = %d, want 415. A form-submittable content type "+
					"reaches this handler without a CORS preflight, so the preflight "+
					"it relies on is optional: %s", rec.Code, truncate(rec.Body.String(), 160))
			}
		})
	}
}

// And the content type our own client sends must still be accepted, or every
// passkey ceremony breaks.
func TestWebAuthnEndpointsAcceptApplicationJSON(t *testing.T) {
	f := newTokenFixture(t)

	for _, ct := range []string{"application/json", "application/json; charset=utf-8"} {
		req := httptest.NewRequest(http.MethodPost, "/login/passkey/begin",
			strings.NewReader(`{}`))
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)

		if rec.Code == http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q was refused; passkey.js sends exactly this", ct)
		}
	}
}
