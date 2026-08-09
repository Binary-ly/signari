package httpapi

import (
	"crypto/rand"
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
