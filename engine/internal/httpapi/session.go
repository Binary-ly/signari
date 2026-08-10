package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

const SessionCookieName = "__Host-idp_session"

// CrossSiteCookieName is a SEPARATE, narrowly scoped cookie for the one case
// that genuinely needs SameSite=None: a form_post response landing back on us
// cross-site. It never carries session authority.
//
// Putting SameSite=None on the session cookie to "make form_post work" is the
// root of most "login works in Chrome but not Safari" reports, and it widens the
// session cookie's exposure for the sake of one narrow flow.
const CrossSiteCookieName = "idp_xs"

// CSRFCookieName carries the double-submit token for the sign-in form.
//
// Double-submit is usually criticised because an attacker on a sibling subdomain
// can set the cookie and then know its value. The __Host- prefix is exactly what
// closes that: the browser refuses the cookie unless it is Secure, Path=/, and
// carries no Domain, so only this precise origin can write it. Anyone who can
// still set it already has script execution here, at which point CSRF is not the
// problem.
//
// Not HttpOnly. The value must be readable by a future JS-driven sign-in page;
// it is not a credential on its own, only proof the request came from a form we
// served.
const CSRFCookieName = "__Host-idp_csrf"

// csrfFormField is the hidden input name carrying the same value.
const csrfFormField = "csrf_token"

// csrfToken returns the token for this browser, minting one if absent.
//
// Deliberately stable for the browser session rather than rotated on every
// render: rotating breaks the ordinary case of two open sign-in tabs, where the
// second render would invalidate the first tab's form. Rotation buys little here
// -- there is no authenticated session yet to fixate, and login issues a fresh
// session cookie anyway.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(CSRFCookieName); err == nil && validCSRFValue(c.Value) {
		return c.Value, nil
	}
	tok, err := newSID()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:  CSRFCookieName,
		Value: tok,
		Path:  "/",
		// __Host- requires all three. Browsers treat http://localhost as a secure
		// context, so this does not break local development.
		Secure:   true,
		HttpOnly: false,
		// Lax, matching the session cookie: a cross-site POST does not carry the
		// cookie at all, so the comparison fails before the token even matters.
		// That is a second, independent barrier -- not a replacement for the token,
		// because SameSite behaviour still varies across browsers and versions.
		SameSite: http.SameSiteLaxMode,
	})
	return tok, nil
}

// checkCSRF compares the submitted field against the cookie.
//
// Both must be present and equal. An absent cookie is a failure, not a pass:
// treating "no cookie" as "nothing to check" is the standard way double-submit
// gets silently disabled, since a cross-site POST is precisely the request that
// arrives without one.
func checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(CSRFCookieName)
	if err != nil || !validCSRFValue(c.Value) {
		return false
	}
	submitted := r.PostFormValue(csrfFormField)
	if !validCSRFValue(submitted) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(submitted)) == 1
}

// validCSRFValue rejects anything that cannot be a token we issued, so a caller
// cannot make two empty or malformed values compare equal.
func validCSRFValue(v string) bool {
	// 32 random bytes, base64url unpadded.
	if len(v) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// newSID returns an opaque session identifier. 256 bits from crypto/rand: it is
// a bearer value, so it must not be guessable and must not encode anything.
func newSID() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setSessionCookie writes the session cookie.
//
// SameSite=Lax, not Strict: Strict would drop the cookie on the top-level
// redirect back from an external identity provider or a form_post callback, so
// the user would land logged-in-but-not-recognised. Lax still blocks the
// cross-site POST cases that matter.
func (s *Server) setSessionCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sid,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// No Domain, no MaxAge: a session cookie, and __Host- forbids Domain anyway.
	})
}

// clearSessionCookie expires the cookie. The attributes must match the ones used
// when setting it or the browser will not replace it.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// sessionCookie reads the session cookie's SECRET value.
//
// Named for what it is. It is deliberately not called sessionID: this value is a
// bearer credential and must never be published, whereas the sid it resolves to
// is public and appears in every ID token. Conflating the two is how an ID token
// becomes a session-stealing primitive.
func sessionCookie(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	// Defensive: a cookie value containing whitespace or control characters
	// cannot be one we issued, and passing it to a query would only waste a
	// round trip.
	if strings.ContainsAny(c.Value, " \t\r\n;,") {
		return ""
	}
	return c.Value
}
