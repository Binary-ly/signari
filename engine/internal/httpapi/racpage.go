package httpapi

import (
	"net/http"
	"strings"

	"signari.dev/engine/internal/rac"
	"signari.dev/engine/internal/store"
)

// The browser half of remote access.
//
// # Why this one page carries a dependency
//
// Everywhere else in this engine the browser code is hand-written and the
// sign-in page in particular carries none at all, because a dependency there
// runs where the session cookie lives. This page is the deliberate exception,
// and the reasoning is in static/PROVENANCE.md: the client is the counterpart
// of guacd, from the same project, versioned against the daemon that already
// holds the credentials for every host in the estate. Rewriting the compositor
// would produce rendering corruption rather than clean errors, and would
// decline a supply chain we have already accepted on the server side.
//
// The library is served from its own path so the page's CSP can stay
// script-src 'self' with no inline script.

// handleGuacamoleJS serves the vendored client library.
func (s *Server) handleGuacamoleJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	// Pinned content at a stable path: it changes only when the vendored file
	// does, and the binary changes with it.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, "guacamole-common.js", buildTime, rac.LibraryJS())
}

// handleRACJS serves the glue between that library and this engine.
func (s *Server) handleRACJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	http.ServeContent(w, r, "rac.js", buildTime, strings.NewReader(rac.ClientJS))
}

// handleRACView renders the viewer for one connection.
func (s *Server) handleRACView(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	slug := r.PathValue("slug")
	if !ok {
		http.Redirect(w, r, parkLogin("/rac/view/"+slug), http.StatusSeeOther)
		return
	}

	// Checked here as well as on the WebSocket, so somebody who may not reach a
	// machine gets a page that says so rather than a viewer that fails to
	// connect for reasons it cannot explain.
	conn, err := store.LoadRACConnection(ctx, s.db, orgID, slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	allowed, err := store.MayUse(ctx, s.db, conn, userID)
	if err != nil || !allowed {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// script-src 'self' because the library and the glue are both served from
	// here; connect-src for the WebSocket; img-src data: and blob: because the
	// display decodes image streams into both.
	setCSP(w, rac.ViewCSP)
	w.Header().Set("X-Frame-Options", "DENY")
	// The page set, not renderBare: renderBare would call htmlPageHeaders and
	// replace the policy set just above with `default-src 'none'` and no
	// script-src, which is a viewer that loads no viewer.
	if err := s.pageSet().ExecuteIn(w, s.langFor(r), "racview", map[string]any{
		"Slug": conn.Slug, "Name": conn.DisplayName, "Protocol": conn.Protocol,
	}); err != nil {
		s.log.Error("rendering the remote-access viewer", "err", err)
	}
}

// handleRACIndex lists the machines a user may reach.
func (s *Server) handleRACIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/rac"), http.StatusSeeOther)
		return
	}
	conns, err := store.ListRACConnections(ctx, s.db, orgID, userID)
	if err != nil {
		s.log.Error("listing remote connections", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "racindex", map[string]any{
		"Connections": conns,
		"Configured":  s.guacdAddr != "",
	})
}
