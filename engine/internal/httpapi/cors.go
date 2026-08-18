package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"signari.dev/engine/internal/oidc"
)


// corsMode describes how much latitude an endpoint gets.
type corsMode int

const (
	corsNone corsMode = iota
	// corsPublic is for documents meant to be world-readable: the discovery
	// document and JWKS. They contain no secrets, are already cacheable by
	// anyone, and a client library needs to read them before it knows anything
	// about origins. `*` is honest about that.
	corsPublic
	// corsClientOrigin is for endpoints a client's own script calls. The origin
	// must be one a client registered a redirect URI on -- an origin we have
	// already validated exactly, so no new configuration surface appears.
	corsClientOrigin
)

// corsPolicyFor maps a path to its mode. An explicit allow-list rather than a
// prefix rule: a prefix quietly grants CORS to the next endpoint added under it,
// and one of the paths below the OAuth prefix is the one place it is forbidden.
func corsPolicyFor(path string) corsMode {
	switch path {
	case oidc.PathDiscovery, oidc.PathJWKS:
		return corsPublic
	case oidc.PathToken, oidc.PathUserinfo, oidc.PathRevocation, oidc.PathIntrospection,
		"/oauth2/par", "/oauth2/device_authorization":
		return corsClientOrigin

		// oidc.PathAuthorize is absent, and must stay absent. RFC 9700 §2.6 makes
		// that a MUST NOT.
	}
	return corsNone
}

const (
	corsAllowHeaders = "Authorization, Content-Type, DPoP, Accept"
	// WWW-Authenticate carries the error for every 401 this server returns, so a
	// script that cannot read it cannot tell an expired token from a revoked one.
	corsExposeHeaders = "WWW-Authenticate"
	corsMaxAge        = "600"
)

// withCORS wraps the mux.
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		mode := corsPolicyFor(r.URL.Path)
		allowed := ""
		switch mode {
		case corsPublic:
			allowed = "*"
		case corsClientOrigin:
			if s.originRegistered(r.Context(), origin) {
				allowed = origin
				// The response varies by Origin, so a cache must not serve one
				// origin's response to another.
				w.Header().Add("Vary", "Origin")
			}
		}

		if allowed == "" {
			// No headers at all. A preflight to a forbidden endpoint gets a plain
			// answer and the browser refuses the real request -- which is the
			// correct outcome, and says less than an explicit denial would.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		h := w.Header()
		h.Set("Access-Control-Allow-Origin", allowed)
		h.Set("Access-Control-Expose-Headers", corsExposeHeaders)

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
			h.Set("Access-Control-Max-Age", corsMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originRegistered(ctx context.Context, origin string) bool {
	// Parse before comparing. An Origin is scheme://host[:port] with no path;
	// anything else is not one, and string-matching a malformed value against a
	// derived list is how a suffix match sneaks in.
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	want := u.Scheme + "://" + u.Host

	for _, o := range s.registeredOrigins(ctx) {
		if o == want {
			return true
		}
	}
	return false
}

// registeredOrigins returns the cached set of origins from registered redirect
// URIs.
//
// Cached because this runs on every cross-origin request including preflights,
// and the set changes only when a client is registered or edited. A short TTL
// rather than invalidation: being up to a minute stale means a freshly
// registered SPA waits, which is a far smaller problem than a cache that a
// forgotten write path fails to clear.
func (s *Server) registeredOrigins(ctx context.Context) []string {
	s.originsMu.Lock()
	defer s.originsMu.Unlock()

	if time.Now().Before(s.originsExpire) {
		return s.originsCache
	}

	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT redirect_uri FROM core.client_redirect_uris`)
	if err != nil {
		s.log.Error("loading registered origins for CORS", "err", err)
		// Serve the previous answer rather than an empty one. Returning nothing
		// on a database blip would refuse every SPA at once, and this list only
		// ever widens what a browser may read -- never what it may do.
		return s.originsCache
	}
	defer rows.Close()

	seen := map[string]bool{}
	out := []string{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		u, perr := url.Parse(raw)
		if perr != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		// Only web origins. A private-use scheme redirect (com.example.app:/cb)
		// belongs to a native app, which has no browser origin and cannot be the
		// source of a cross-origin fetch.
		if u.Scheme != "https" && u.Scheme != "http" {
			continue
		}
		o := u.Scheme + "://" + u.Host
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}

	s.originsCache = out
	s.originsExpire = time.Now().Add(time.Minute)
	return out
}
