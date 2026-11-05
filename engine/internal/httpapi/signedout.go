package httpapi

import (
	"net/http"
	"strings"
)

// Where a sign-out ends when nobody asked to be sent anywhere after it (0.93). A person's
// browser was answered {"status":"signed out"}, from the end-session endpoint, an
// upstream's logout, a SAML upstream's and the SAML chain's report, and a sign-out that
// failed with the JSON of an API error. A browser is shown the signedout page now; a
// caller asking for anything but HTML is answered what it was, so nothing that read the
// JSON is broken by it.

// signedOut ends a sign-out that has nowhere to go. notified and failed are the
// applications a SAML chain told and could not reach, nil where there was no chain.
func (s *Server) signedOut(w http.ResponseWriter, r *http.Request, notified, failed []string) {
	if !acceptsHTML(r) {
		body := map[string]any{"status": "signed out"}
		if notified != nil || failed != nil {
			body["notified"], body["failed"] = notified, failed
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	s.renderPage(w, r, "signedout", map[string]any{"Notified": notified, "Failed": failed})
}

// signOutFailed ends a sign-out that could not end the session: said, and not claimed
// as done, so somebody on a shared computer knows to try again.
func (s *Server) signOutFailed(w http.ResponseWriter, r *http.Request) {
	if !acceptsHTML(r) {
		writeError(w, http.StatusInternalServerError, "server_error",
			"sign-out could not be completed; your session may still be active")
		return
	}
	s.renderPageStatus(w, r, http.StatusInternalServerError, "signedout", map[string]any{"Incomplete": true})
}

// acceptsHTML is a browser navigating, which asks for HTML; a script or an API client
// asking for JSON, or for nothing in particular, does not.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}
