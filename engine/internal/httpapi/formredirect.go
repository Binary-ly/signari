package httpapi

import (
	"fmt"
	"html"
	"net/http"
)

// A redirect that follows one of this server's own forms is sent as a page.
//
// Every sign-in page says `form-action 'self'`, so that markup injected into it
// cannot post a password somewhere else. Chrome applies that directive to every
// redirect in the navigation a form starts, not only to the form's own target.
// The walk from a password to an application is such a navigation: POST /login,
// 303 to /oauth2/authorize, 303 to the relying party. It stopped at the last hop,
// on the sign-in page, with the right password, no error, and a violation only in
// the console. Consent, a second factor, a prompt, Duo and an external factor all
// end the same way.
//
// Listing the destination in the policy would mean every page working out where
// the journey might end, and the one that misses it hangs. Taking the directive
// off would give up what it is for. So the navigation is ended instead: the form
// is answered with a page, which navigates by itself, and from there the journey
// is an ordinary one the directive has no say in. Being here, around every route,
// a page added next year cannot forget it.
//
// Only for a form on one of this server's own pages, which is what carries the
// policy. A form on a relying party's page, such as a POST to the authorization
// endpoint, is governed by that page's policy and keeps its redirect, as does
// anything that is not a browser navigating.

// fromOwnForm reports a browser submitting a form on a page from this origin.
// Sec-Fetch-* is set by the browser and a page cannot change it.
func fromOwnForm(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		r.Header.Get("Sec-Fetch-Site") == "same-origin" &&
		r.Header.Get("Sec-Fetch-Dest") == "document"
}

func (s *Server) withFormRedirects(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fromOwnForm(r) {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&formRedirectWriter{ResponseWriter: w, s: s, r: r}, r)
	})
}

// formRedirectWriter turns a redirect into a page, and passes anything else
// through untouched.
type formRedirectWriter struct {
	http.ResponseWriter
	s *Server
	r *http.Request
	// answered is set once the status has gone, and replaced once it went as a
	// page, so that whatever the handler writes next is dropped.
	answered, replaced bool
}

func (w *formRedirectWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *formRedirectWriter) WriteHeader(code int) {
	if w.answered {
		return
	}
	w.answered = true
	location := w.Header().Get("Location")
	if code < 300 || code > 399 || location == "" {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.replaced = true
	p := w.s.tr(w.r)
	h := w.Header()
	h.Del("Location")
	h.Del("Content-Length")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// Nothing on this page runs, and it has no form of its own.
	setCSP(w, `default-src 'none'; form-action 'none'; frame-ancestors 'none'`)
	w.ResponseWriter.WriteHeader(http.StatusOK)
	// By hand, because html/template refuses a URL in a refresh, and a custom
	// scheme in a link, and a native application's redirect may be either. The
	// value came from this server's own redirect, and it is escaped. The link is
	// for a browser with refreshing turned off.
	target := html.EscapeString(location)
	text := html.EscapeString(p.Text("redirect.continue"))
	if _, err := fmt.Fprintf(w.ResponseWriter, `<!doctype html>
<html lang="%s" dir="%s"><head><meta charset="utf-8"><meta name="color-scheme" content="light dark">
<meta http-equiv="refresh" content="0;url=%s"><title>%s</title></head>
<body><p><a href="%s">%s</a></p></body></html>
`, html.EscapeString(p.Lang()), html.EscapeString(p.Dir()), target, text, target, text); err != nil {
		w.s.log.Warn("writing the page that follows a form", "err", err, "correlation_id", correlationID(w.r.Context()))
	}
}

func (w *formRedirectWriter) Write(b []byte) (int, error) {
	if w.replaced {
		return len(b), nil
	}
	w.answered = true
	return w.ResponseWriter.Write(b)
}
