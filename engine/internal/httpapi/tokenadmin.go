package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
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

	// RFC 6749 §3.1: no parameter more than once. The authorize, token and PAR
	// endpoints refuse duplicates; revoke and introspect flow through here and
	// were the two token-endpoint-family handlers that did not -- found by
	// applying the rule where the traffic later grew, rather than only where it
	// ours. It matters for the same reason as everywhere else: `token` twice is
	// answered about the first while a proxy or audit shipper reading the last
	// records a different token, so the decision and the record of it describe
	// different requests. ParseTokenRequest takes Get(), so without this the
	// duplicate is silent.
	if err := refuseDuplicateParams(r.PostForm); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: err.Error(), Status: http.StatusBadRequest})
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
		if claims, verr := tokens.VerifyAccessTokenAny(s.cfg.Keys, s.acceptedIssuers(), raw); verr == nil {
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
			} else if claims.ClientID != "" && claims.ClientID != c.ClientID {
				// §2.1: "verifies whether the token was issued to the client
				// making the revocation request. If this validation fails, the
				// request is refused and the client is informed of the error."
				//
				// Distinct from §2.2's unknown-token case, which MUST be 200.
				// This token is real and this caller may not revoke it, and
				// answering 200 would tell them it had been revoked when it had
				// not -- the same silent-success failure this endpoint's review
				// criticises elsewhere.
				s.log.Info("revocation refused: token belongs to another client",
					"presented_by", c.ClientID, "correlation_id", correlationID(ctx))
				writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
					Description: "this token was issued to a different client",
					Status:      http.StatusBadRequest})
				return
			}
		}
	}

	if !revoked {
		// The same §2.1 check for refresh tokens, which RevokeRefreshToken
		// cannot report on its own: it returns false for unknown, foreign and
		// already-revoked alike, and only the middle one is an error.
		owner, oerr := store.RefreshTokenOwner(ctx, tx, store.HashToken(raw))
		if oerr != nil {
			s.log.Error("looking up refresh token owner", "err", oerr)
			writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
			return
		}
		if owner != "" && owner != c.ClientID {
			s.log.Info("revocation refused: refresh token belongs to another client",
				"presented_by", c.ClientID, "correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "this token was issued to a different client",
				Status:      http.StatusBadRequest})
			return
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

	Audience  audienceValue `json:"aud,omitempty"`
	Issuer    string        `json:"iss,omitempty"`
	JTI       string        `json:"jti,omitempty"`
	SessionID string        `json:"sid,omitempty"`

	// AuthorizationDetails is RFC 9396 §9.2:
	//
	//	"If the AS includes authorization detail information for the token in
	//	its response, the information MUST be conveyed with
	//	authorization_details as a top-level member of the introspection
	//	response JSON object."
	//
	// Top-level and under that exact name, not nested inside anything -- an RS
	// looks for it there and nowhere else. Carried verbatim from the token so
	// introspection and the JWT claim cannot disagree about what was granted;
	// two independently-built answers to one question is how they drift.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// Cnf conveys the sender constraint to the resource server.
	//
	// RFC 9449 §6.2: "For a DPoP-bound access token, the hash of the public key
	// to which the token is bound is conveyed to the protected resource as
	// metainformation in a token introspection response ... as a top-level
	// member of the introspection response JSON." RFC 8705 §3.2 says the same
	// for the `x5t#S256` member of a certificate-bound token.
	//
	// Without it an RS that validates by introspection -- which is the caller
	// §2.1 describes -- cannot honour the binding at all. RFC 9449 §6 states
	// the requirement from the RS's side: "Resource servers MUST be able to
	// reliably identify whether an access token is DPoP-bound".
	//
	// Carried verbatim from the verified token for the same reason as
	// `authorization_details`: two independently-derived answers to one
	// question are two answers that can drift apart.
	Cnf *tokens.Confirmation `json:"cnf,omitempty"`
}

// audienceValue renders `aud` the way JWT does: absent when empty, a bare string
// when there is exactly one, an array when there are several.
//
// RFC 7662 §2.2 permits either form -- "Service-specific string identifier or
// list of string identifiers" -- and RFC 7519 §4.1.3 makes the single-string
// case the special one. Emitting an array unconditionally would be legal and
// would still break any resource server that reads `aud` as a string, which is
// the shape this endpoint has always returned.
type audienceValue []string

func (a audienceValue) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
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

	if c.Type == "public" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
			Description: "introspection requires an authenticated client; public " +
				"clients cannot authenticate and RFC 7662 section 2.1 requires " +
				"authorization for this endpoint",
			Status: http.StatusUnauthorized})
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
	claims, err := tokens.VerifyAccessTokenAny(s.cfg.Keys, s.acceptedIssuers(), raw)
	if err != nil {
		return nil
	}

	if claims.ClientID != c.ClientID && !audienceIncludes(claims.Audience, c.ClientID) {
		s.log.Info("client introspected a token it is neither the owner nor an audience of",
			"caller", c.ClientID, "token_client", claims.ClientID)
		return &introspectionResponse{Active: false}
	}

	inactive := &introspectionResponse{Active: false}

	if time.Now().After(time.Unix(claims.Expiry, 0)) {
		return inactive
	}
	// RFC 7009 §2.1's cascade, checked before the per-jti denylist: revoking the
	// refresh token invalidates every access token from the same grant, and a
	// client revokes the refresh token far more often than each access token.
	if grantRevoked, gerr := store.GrantRevoked(ctx, s.db, claims.GrantID); gerr != nil || grantRevoked {
		if gerr != nil {
			s.log.Error("introspection grant revocation check failed", "err", gerr)
		}
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
		TokenType: introspectedTokenType(claims.Cnf),
		Expiry:    claims.Expiry,
		IssuedAt:  claims.IssuedAt,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		Issuer:    s.cfg.Issuer,
		JTI:       claims.JTI,
		SessionID: claims.SessionID,

		AuthorizationDetails: claims.AuthorizationDetails,
		Cnf:                  claims.Cnf,
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
		Issuer:    s.cfg.Issuer,
		SessionID: st.SID,
	}
}

// audienceIncludes reports whether a caller is named in a token's audience.
//
// RFC 7662 §4's test for who may introspect: "whether or not the token can be
// used at the resource server making the introspection call".
func audienceIncludes(aud []string, clientID string) bool {
	if clientID == "" {
		return false
	}
	for _, a := range aud {
		if a == clientID {
			return true
		}
	}
	return false
}

// introspectedTokenType names the token type for an introspection response.
//
// RFC 9449 §6.2: "If the token_type member is included in the introspection
// response, it MUST contain the value DPoP." We included the member and
// hardcoded "Bearer", so a resource server was told a sender-constrained token
// was an ordinary bearer token -- and an RS that believes "Bearer" never asks
// for a proof, so it honours the token for whoever presents it. The wrong answer
// is worse here than no answer at all.
//
// `bearerOrDPoP` in dpop.go is the same rule for the token endpoint, where it
// was found and fixed in an earlier pass across three call sites. This is a
// fourth site, in another file, and §6.2 states the requirement separately for
// it -- which is why sweeping the token responses did not reach it.
//
// A certificate-bound token stays "Bearer". RFC 8705 conveys its binding through
// `cnf.x5t#S256` and never redefines the token type: such a token is still
// presented with the Bearer scheme, over a mutually-authenticated connection.
// Calling it "DPoP" would tell the client to send a proof it does not have.
func introspectedTokenType(cnf *tokens.Confirmation) string {
	if cnf != nil && cnf.JKT != "" {
		return "DPoP"
	}
	return "Bearer"
}
