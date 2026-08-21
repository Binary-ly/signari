package httpapi

import (
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// Requiring the JSON content type on endpoints defended by CORS preflight.
//
// ASVS 5.0.0 V3.5.2:
//
//	"Verify that, if the application relies on the CORS preflight mechanism to
//	prevent disallowed cross-origin use of sensitive functionality, it is not
//	possible to call the functionality with a request which does not trigger a
//	CORS-preflight request. This may require checking the values of the 'Origin'
//	and 'Content-Type' request header fields."
//
// # What this closes
//
// The WebAuthn ceremony endpoints are cookie-authenticated and carry no CSRF
// token, unlike the sixteen other browser POSTs in this package. Three things
// were standing in for one:
//
//   - `SameSite=Lax`, which does not send the session cookie on a cross-site
//     POST at all;
//   - `corsNone` for these paths, so a cross-origin `fetch` gets no
//     `Access-Control-Allow-Origin` and is refused;
//   - WebAuthn's own origin binding, which stops a page on another origin
//     producing an assertion for this relying party.
//
// The second of those was bypassable and that is the requirement's whole point.
// A cross-origin `fetch` sending `Content-Type: application/json` triggers a
// preflight — but a plain HTML `<form enctype="text/plain">` does not, because
// `text/plain` is a CORS-safelisted content type, and a form body can be crafted
// to be valid JSON. The handlers decoded whatever arrived without ever looking
// at the content type, so the preflight they relied on was optional.
//
// Not exploitable as things stand: `SameSite=Lax` withholds the cookie, so the
// request arrives unauthenticated. That is one mechanism deep where the rest of
// this package is two or three, and "the other defence happens to hold" is the
// reasoning this codebase has had to retract several times.
func requireJSONContentType(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return fmt.Errorf("this endpoint requires Content-Type: application/json")
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("the Content-Type header is malformed")
	}
	if !strings.EqualFold(mt, "application/json") {
		return fmt.Errorf("this endpoint requires Content-Type: application/json, not %q", mt)
	}
	return nil
}

// writeJSONContentTypeError answers a request that did not carry it.
func writeJSONContentTypeError(w http.ResponseWriter, err error) {
	writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", err.Error())
}
