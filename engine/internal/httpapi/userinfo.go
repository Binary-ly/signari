package httpapi

import (
	"net/http"
	"strings"

	"github.com/sulimanbenhalim/idp/engine/internal/store"
	"github.com/sulimanbenhalim/idp/engine/internal/tokens"
)

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	raw := bearerToken(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="idp"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, err := tokens.VerifyAccessToken(s.cfg.Keys, s.cfg.Issuer, raw)
	if err != nil {
		// Logged with the reason, returned without it.
		s.log.Info("userinfo token rejected", "err", err)
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="idp", error="invalid_token", error_description="The access token is invalid"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !tokens.HasScope(claims.Scope, "openid") {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="idp", error="insufficient_scope", scope="openid"`)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// An explicitly revoked token must stop working here immediately. This is the
	// endpoint where /revoke earns its 200: we are the resource server, so there
	// is no excuse for honouring a token the client told us to drop.
	if revoked, err := store.JTIRevoked(ctx, s.db, claims.JTI); err != nil || revoked {
		if err != nil {
			s.log.Error("userinfo revocation check failed", "err", err)
		}
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="idp", error="invalid_token", error_description="The access token has been revoked"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// The session must still be live. See (1) above.
	if claims.SessionID != "" {
		live, err := store.IsSessionLive(ctx, s.db, claims.SessionID)
		if err != nil || !live {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="idp", error="invalid_token", error_description="The session has ended"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	out := map[string]any{"sub": claims.Subject}

	// Claims are released strictly by granted scope. `profile` and `email` are
	// separate grants and must not leak into each other.
	var email, username string
	var verified *bool
	if err := s.db.QueryRow(ctx,
		`SELECT COALESCE(email,''), COALESCE(username,''), email_verified_at IS NOT NULL
		 FROM core.users WHERE id = $1 AND status = 'active'`,
		claims.Subject).Scan(&email, &username, &verified); err != nil {
		// A token for a user who no longer exists or is deactivated.
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="idp", error="invalid_token", error_description="The subject is not active"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if tokens.HasScope(claims.Scope, "email") && email != "" {
		out["email"] = email
		out["email_verified"] = verified != nil && *verified
	}
	if tokens.HasScope(claims.Scope, "profile") && username != "" {
		out["preferred_username"] = username
	}

	writeJSON(w, http.StatusOK, out)
}

// bearerToken reads RFC 6750 §2.1. The header form only: a token in a query
// string lands in access logs, browser history, and Referer headers, and RFC 9700
// says not to accept it.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
