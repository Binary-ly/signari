package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"
)

const SessionCookieName = "__Host-signari_session"

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
const CSRFCookieName = "__Host-signari_csrf"

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
		Secure: true,
		// HttpOnly, because nothing needs to read this from JavaScript.
		//
		// The double-submit pattern is sometimes written with a readable cookie so
		// a script can copy it into a header. Here the token is rendered into the
		// form server-side, so script access buys nothing -- and costs real
		// defence: an XSS that can read the token can forge requests that pass the
		// comparison. Found by gosec (G124), which was right.
		HttpOnly: true,
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
// redirect back from an external identity provider, so the user would land
// logged-in-but-not-recognised. Lax still blocks the cross-site POST cases that
// matter.
//
// maxAge 0 is a browser-session cookie, gone when the browser closes. A
// positive one is "stay signed in on this device" (5.11): the cookie outlasts
// a restart, for at most what the session itself has left.
func (s *Server) setSessionCookie(w http.ResponseWriter, sid string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sid,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		// No Domain: __Host- forbids it.
	})
}

// RememberCookieName carries "stay signed in on this device" from the page it
// was ticked on to the request that completes the sign-in, which after a
// second factor or a provider's round trip is a later one (5.11). It names
// nobody and grants nothing: it can only make the session cookie outlast the
// browser, and only where the organisation offers that.
const RememberCookieName = "__Host-signari_remember"

// rememberTTL is how long the choice is kept: longer than a pending sign-in,
// because a provider's own sign-in page may take a person a while.
const rememberTTL = 15 * time.Minute

// stayField is the sign-in page's checkbox. Not "remember": the second-factor
// page's "remember this device" has that name, and completes the sign-in in
// the same request, so sharing it would make skipping the factor also keep the
// session past the browser.
const stayField = "stay_signed_in"

// noteRemember keeps the person's choice for the rest of the sign-in.
func (s *Server) noteRemember(w http.ResponseWriter, r *http.Request) {
	if r.FormValue(stayField) != "1" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: RememberCookieName, Value: "1", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(rememberTTL.Seconds()),
	})
}

// forgetRemember drops the choice once a sign-in has used it: the one the
// request brought, and the one noteRemember set in this same response when the
// form that asked also completed the sign-in. Clearing only the first left the
// second for fifteen minutes, and the next person to sign in on the browser
// was signed in to stay without asking. The second is taken back out of the
// response rather than followed by a deletion: a response that sets a cookie
// and then clears it relies on the client applying the two in order.
func (s *Server) forgetRemember(w http.ResponseWriter, r *http.Request) {
	if set := w.Header()["Set-Cookie"]; len(set) > 0 {
		kept := set[:0]
		for _, h := range set {
			if !strings.HasPrefix(h, RememberCookieName+"=") {
				kept = append(kept, h)
			}
		}
		w.Header()["Set-Cookie"] = kept
	}
	if _, err := r.Cookie(RememberCookieName); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: RememberCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// rememberAsked reports whether this sign-in asked to stay signed in: in this
// request, or on the page it started from.
func rememberAsked(r *http.Request) bool {
	if r.FormValue(stayField) == "1" {
		return true
	}
	c, err := r.Cookie(RememberCookieName)
	return err == nil && c.Value == "1"
}

// persistentCookieAge is how long the cookie of a session that asked to stay
// signed in may last: what the session has left before its absolute deadline,
// or 0 -- a browser-session cookie -- where the organisation does not offer it.
func (s *Server) persistentCookieAge(ctx context.Context, sid string) int {
	var age int
	if err := s.db.QueryRow(ctx, `
		SELECT CASE WHEN o.persistent_sessions
		            THEN greatest(0, floor(extract(epoch FROM s.absolute_not_after - now())))::int ELSE 0 END
		  FROM core.sessions s JOIN core.organizations o ON o.id = s.org_id WHERE s.sid = $1`, sid).
		Scan(&age); err != nil {
		s.log.Error("reading whether a session may outlast the browser", "err", err)
		return 0
	}
	return age
}

// persistentOffered reports whether the sign-in page offers the choice.
func (s *Server) persistentOffered(ctx context.Context, orgID string) bool {
	if s.db == nil || orgID == "" {
		return false
	}
	var on bool
	if err := s.db.QueryRow(ctx, `SELECT persistent_sessions FROM core.organizations WHERE id = $1::uuid`,
		orgID).Scan(&on); err != nil {
		return false
	}
	return on
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
