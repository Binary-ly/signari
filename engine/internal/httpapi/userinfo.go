package httpapi

import (
	"net/http"
	"strings"

	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	raw := bearerToken(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="signari"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, err := tokens.VerifyAccessTokenAny(s.cfg.Keys, s.acceptedIssuers(), raw)
	if err != nil {
		// Logged with the reason, returned without it.
		s.log.Info("userinfo token rejected", "err", err)
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token", error_description="The access token is invalid"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !tokens.HasScope(claims.Scope, "openid") {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="insufficient_scope", scope="openid"`)
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
			`Bearer realm="signari", error="invalid_token", error_description="The access token has been revoked"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// The session must still be live. See (1) above.
	if claims.SessionID != "" {
		live, err := store.IsSessionLive(ctx, s.db, claims.SessionID)
		if err != nil || !live {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="signari", error="invalid_token", error_description="The session has ended"`)
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
			`Bearer realm="signari", error="invalid_token", error_description="The subject is not active"`)
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

// bearerToken reads the access token from the Authorization header (RFC 6750
// §2.1) or, on a POST, from the form body (§2.2).
//
// Never from the query string (§2.3), which OIDC also permits: a token there
// lands in access logs, browser history and Referer headers, and RFC 9700
// advises against accepting it. The body form has none of those properties.
//
// OIDC Core §5.3.1 requires the endpoint to accept POST with the token as an
// `access_token` form field, which is what clients that cannot set headers (and
// several SDKs) actually use. Supporting only the header made this endpoint
// unusable for them.
//
// Presenting the token in BOTH places is rejected rather than resolved by
// precedence: two different token values in one request is either a broken
// client or an attempt to have the check read one and the logic use the other.
func bearerToken(r *http.Request) string {
	var header string
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		header = strings.TrimSpace(h[len(prefix):])
	}

	if r.Method != http.MethodPost {
		return header
	}
	// Only application/x-www-form-urlencoded, per the spec. Parsing any body
	// type here would let a token arrive somewhere nothing else expects it.
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return header
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	body := strings.TrimSpace(r.PostForm.Get("access_token"))
	switch {
	case body == "":
		return header
	case header == "":
		return body
	default:
		// Both present. Ambiguous by construction.
		return ""
	}
}
