package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/sulimanbenhalim/idp/engine/internal/clients"
	"github.com/sulimanbenhalim/idp/engine/internal/oauth"
	"github.com/sulimanbenhalim/idp/engine/internal/store"
	"github.com/sulimanbenhalim/idp/engine/internal/tokens"
)

// authenticateTokenEndpointClient is the shared front half of /revoke and
// /introspect.
//
// Both endpoints are client-authenticated for the same reason: without it,
// /introspect is a free oracle for validating stolen tokens and /revoke is a
// denial-of-service primitive against anyone whose token you can guess.
func (s *Server) authenticateTokenEndpointClient(w http.ResponseWriter, r *http.Request) (*clients.Client, bool) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "malformed form body", Status: http.StatusBadRequest})
		return nil, false
	}

	req, perr := oauth.ParseTokenRequest(r.Header, r.PostForm)
	if perr != nil {
		writeTokenError(w, perr)
		return nil, false
	}

	c, err := s.lookupClient(ctx, req.ClientID)
	if err != nil || c == nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
			Description: "unknown client", Status: http.StatusUnauthorized})
		return nil, false
	}
	if aerr := oauth.RequireClientAuth(c, req); aerr != nil {
		writeTokenError(w, aerr)
		return nil, false
	}
	if c.Type == "confidential" {
		ok, err := s.verifyClientSecret(ctx, c, req.ClientSecret)
		if err != nil || !ok {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
				Description: "client authentication failed", Status: http.StatusUnauthorized})
			return nil, false
		}
	}
	return c, true
}

// handleRevoke implements RFC 7009.
//
// The response is 200 for a token that was revoked, a token that was already
// revoked, a token belonging to someone else, and a token that never existed.
// That uniformity is required (§2.2) and it is the point: any distinction here
// would let a caller probe which token values are real.
//
// What actually happens differs by token type, and the difference is worth being
// precise about rather than papering over:
//
//   - A refresh token is stored, so revoking it kills its whole family. Real and
//     immediate.
//   - An access token is a signed JWT, so it cannot be un-signed. Its jti goes on
//     a denylist that userinfo and introspection consult, which covers every
//     resource server that asks us. One validating the JWT offline will keep
//     accepting it until it expires -- five minutes -- and no issuer of stateless
//     tokens can do better than that.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticateTokenEndpointClient(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	raw := r.PostForm.Get("token")
	if raw == "" {
		// The one case RFC 7009 does treat as an error: the parameter is
		// missing, which is a broken client rather than an unknown token.
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "token is required", Status: http.StatusBadRequest})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The hint is an optimisation, not a decision: RFC 7009 §2.1 requires the
	// server to try the other type if the hinted lookup misses. Trusting a wrong
	// hint is how a client's revocation silently does nothing.
	revoked, err := store.RevokeRefreshToken(ctx, tx, store.HashToken(raw), c.ClientID)
	if err != nil {
		s.log.Error("revoking refresh token", "client_id", c.ClientID, "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	if !revoked {
		// Not a refresh token of ours. Try it as an access token.
		if claims, verr := tokens.VerifyAccessToken(s.cfg.Keys, s.cfg.Issuer, raw); verr == nil {
			// Only the client's own tokens. A valid token presented by a
			// different client is somebody else's credential, and revoking it
			// would be a cross-client denial of service.
			if claims.ClientID == c.ClientID && claims.JTI != "" {
				if err := store.RevokeJTI(ctx, tx, claims.JTI, c.ClientID,
					time.Unix(claims.Expiry, 0)); err != nil {
					s.log.Error("denylisting access token", "client_id", c.ClientID, "err", err)
					writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
					return
				}
				revoked = true
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		s.log.Error("committing revocation", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	// Logged either way, because "the client called revoke and nothing matched"
	// is the shape of both a retry and a misconfigured integration.
	s.log.Info("token revocation", "client_id", c.ClientID, "matched", revoked)
	w.WriteHeader(http.StatusOK)
}

// introspectionResponse is RFC 7662 §2.2. Every field but `active` is omitted
// when the token is not active: an inactive response must reveal nothing beyond
// the single bit.
type introspectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Expiry    int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	JTI       string `json:"jti,omitempty"`
	SessionID string `json:"sid,omitempty"`
}

// handleIntrospect implements RFC 7662.
//
// This is what makes revocation real for resource servers, so `active` answers
// the question they actually care about -- "may I honour this right now" -- not
// the weaker "was this correctly signed and not yet expired". It is false if:
//
//   - the signature or issuer does not check out,
//   - the token expired,
//   - its jti was revoked,
//   - the session behind it was signed out, expired, or revoked,
//   - or (for refresh tokens) the token was consumed by rotation or its family
//     was revoked.
//
// A caller may only introspect its own tokens. Otherwise any registered client
// could use this endpoint to validate tokens it stole from another, which turns
// a debugging aid into an attack tool.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticateTokenEndpointClient(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	raw := r.PostForm.Get("token")
	if raw == "" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "token is required", Status: http.StatusBadRequest})
		return
	}

	if resp := s.introspectAccessToken(ctx, c, raw); resp != nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusOK, s.introspectRefreshToken(ctx, c, raw))
}

// introspectAccessToken returns nil when raw is not one of our access tokens, so
// the caller can try it as a refresh token.
func (s *Server) introspectAccessToken(ctx context.Context, c *clients.Client, raw string) *introspectionResponse {
	claims, err := tokens.VerifyAccessToken(s.cfg.Keys, s.cfg.Issuer, raw)
	if err != nil {
		return nil
	}

	// Someone else's token. Inactive, with no explanation -- the caller learns
	// nothing it did not already know.
	if claims.ClientID != c.ClientID {
		s.log.Info("client introspected another client's token",
			"caller", c.ClientID, "token_client", claims.ClientID)
		return &introspectionResponse{Active: false}
	}

	inactive := &introspectionResponse{Active: false}

	if time.Now().After(time.Unix(claims.Expiry, 0)) {
		return inactive
	}
	revoked, err := store.JTIRevoked(ctx, s.db, claims.JTI)
	if err != nil {
		// JTIRevoked fails closed and says why. Report inactive rather than
		// erroring: a resource server that cannot get an answer must not treat
		// the token as good.
		s.log.Error("introspection revocation check failed", "err", err)
		return inactive
	}
	if revoked {
		return inactive
	}

	// A token minted from a session is only as live as that session. A token
	// from client_credentials has no session and is not subject to this.
	if claims.SessionID != "" {
		live, err := store.SessionLive(ctx, s.db, claims.SessionID)
		if err != nil {
			s.log.Error("introspection session check failed", "err", err)
			return inactive
		}
		if !live {
			return inactive
		}
	}

	return &introspectionResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		TokenType: "Bearer",
		Expiry:    claims.Expiry,
		IssuedAt:  claims.IssuedAt,
		Subject:   claims.Subject,
		Audience:  c.ClientID,
		Issuer:    s.cfg.Issuer,
		JTI:       claims.JTI,
		SessionID: claims.SessionID,
	}
}

func (s *Server) introspectRefreshToken(ctx context.Context, c *clients.Client, raw string) *introspectionResponse {
	inactive := &introspectionResponse{Active: false}

	st, err := store.LookupRefreshToken(ctx, s.db, store.HashToken(raw))
	if err != nil {
		s.log.Error("introspecting refresh token", "err", err)
		return inactive
	}
	if !st.Found || st.ClientID != c.ClientID || !st.Active {
		return inactive
	}
	// A live refresh token whose session has ended is not usable, and saying
	// otherwise would contradict what the refresh grant itself would do.
	if st.SID != "" {
		live, err := store.SessionLive(ctx, s.db, st.SID)
		if err != nil || !live {
			return inactive
		}
	}

	return &introspectionResponse{
		Active:    true,
		Scope:     joinScopes(st.Scopes),
		ClientID:  st.ClientID,
		TokenType: "refresh_token",
		Expiry:    st.ExpiresAt.Unix(),
		Subject:   st.UserID,
		Audience:  c.ClientID,
		Issuer:    s.cfg.Issuer,
		SessionID: st.SID,
	}
}
