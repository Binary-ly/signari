package httpapi

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

const (
	codeTTL    = 60 * time.Second // RFC 6749 recommends <= 10 minutes; short is free here
	sessionTTL = 12 * time.Hour
)

// handleAuthorize implements /oauth2/authorize.
//
// The shape is: validate -> is there a live session? -> if not, park the request
// and show login -> issue a code.
//
// Validation happens BEFORE the login prompt. Prompting for credentials and only
// then discovering the client is unknown trains users to type passwords into
// pages reached from unvalidated links.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := oauth.ParseAuthz(r.URL.Query())

	c, lookupErr := s.lookupClient(ctx, req.ClientID)
	if authzErr := oauth.ValidateAuthz(req, c, lookupErr); authzErr != nil {
		s.writeAuthzError(w, r, req, authzErr)
		return
	}

	sid := ""
	live := false
	if cookie := sessionCookie(r); cookie != "" {
		var err error
		// The cookie is a bearer secret; the sid it maps to is the public
		// identifier. Never treat the cookie value as the sid.
		sid, live, err = store.ResolveSessionCookie(ctx, s.db, store.HashToken(cookie))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.log.Error("checking session", "err", err)
			s.writeAuthzError(w, r, req,
				&oauth.AuthzError{Code: "server_error", Description: "could not verify session",
					Disposition: oauth.DispositionRedirect})
			return
		}
	}

	// A live session is NOT automatically sufficient. This is where a step-up
	// requirement becomes real: acr_values, max_age and prompt=login are each a
	// client saying it does not trust what we already have.
	//
	// Re-evaluated per authorization request, deliberately. Treating acr as a
	// property frozen at login is a genuine bypass -- a password-only session
	// would satisfy every future multi-factor demand for as long as it lives.
	if live {
		var authTime time.Time
		var amr []string
		if err := s.db.QueryRow(ctx,
			`SELECT auth_time, amr FROM core.sessions WHERE sid = $1`, sid).Scan(&authTime, &amr); err != nil {
			s.log.Error("loading session context for step-up", "err", err)
			s.writeAuthzError(w, r, req, &oauth.AuthzError{Code: "server_error",
				Description: "could not verify session", Disposition: oauth.DispositionRedirect})
			return
		}
		if reason, detail := oauth.SessionSufficient(amr, authTime, time.Now(),
			req.ACRValues, req.MaxAge, req.Prompt); reason != oauth.StepUpNone {
			s.log.Info("step-up required", "sid", sid, "reason", reason,
				"correlation_id", correlationID(ctx))
			// The session stays live. Step-up asks for another factor; it does
			// not throw away an authentication that was legitimately performed.
			live = false

			// prompt=none plus an unmet requirement is unsatisfiable by
			// definition: the client forbade interaction and we need some.
			if req.Prompt == "none" {
				s.writeAuthzError(w, r, req, &oauth.AuthzError{
					Code:        stepUpErrorCode(reason),
					Description: detail,
					Disposition: oauth.DispositionRedirect})
				return
			}
		}
	}

	if !live {
		// prompt=none means "do not interact". A client asking for silent
		// authentication must get an error it can handle, not a login page.
		if req.Prompt == "none" {
			s.writeAuthzError(w, r, req,
				&oauth.AuthzError{Code: "login_required",
					Description: "no active session and prompt=none was requested",
					Disposition: oauth.DispositionRedirect})
			return
		}
		s.renderLogin(w, r, r.URL.RawQuery, "")
		return
	}

	// Consent is checked AFTER authentication and step-up, and BEFORE any code is
	// issued. Asking first would show a stranger which clients exist and what
	// they request; issuing first would make the question decorative.
	var userID string
	if err := s.db.QueryRow(ctx,
		`SELECT user_id::text FROM core.sessions WHERE sid = $1`, sid).Scan(&userID); err != nil {
		s.log.Error("loading session user for consent", "err", err)
		s.writeAuthzError(w, r, req, &oauth.AuthzError{Code: "server_error",
			Description: "could not verify session", Disposition: oauth.DispositionRedirect})
		return
	}
	decision, ask, err := s.needsConsent(r, c, userID, req)
	if err != nil {
		s.log.Error("checking consent", "err", err)
		s.writeAuthzError(w, r, req, &oauth.AuthzError{Code: "server_error",
			Description: "could not check consent", Disposition: oauth.DispositionRedirect})
		return
	}
	if ask {
		// prompt=none forbade interaction, and consent is interaction. The client
		// gets an error it can act on rather than a screen it cannot show.
		if req.Prompt == "none" {
			s.writeAuthzError(w, r, req, &oauth.AuthzError{Code: "consent_required",
				Description: "the user has not consented to the requested scopes",
				Disposition: oauth.DispositionRedirect})
			return
		}
		s.renderConsent(w, r, c, decision, r.URL.RawQuery)
		return
	}

	s.issueCodeAndRedirect(w, r, req, c, sid)
}

// issueCodeAndRedirect mints an authorization code for a live session.
func (s *Server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request,
	req oauth.AuthzRequest, c *clients.Client, sid string) {

	ctx := r.Context()

	var orgID, userID string
	err := s.db.QueryRow(ctx,
		`SELECT org_id::text, user_id::text FROM core.sessions WHERE sid = $1`, sid).
		Scan(&orgID, &userID)
	if err != nil {
		s.log.Error("loading session", "err", err)
		http.Error(w, "session lookup failed", http.StatusInternalServerError)
		return
	}

	code, hash, err := store.NewCode()
	if err != nil {
		s.log.Error("generating code", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	grant := oauth.GrantRecord{
		ClientID:            c.ClientID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		Scopes:              splitScopes(req.Scope),
		ExpiresAt:           time.Now().Add(codeTTL),
	}
	if err := store.IssueCode(ctx, tx, orgID, c.ClientID, sid, userID, grant, hash, req.Resources); err != nil {
		s.log.Error("issuing code", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Record that this relying party saw the session, so logout can enumerate it.
	if err := store.TouchSessionClient(ctx, tx, sid, c.ClientID); err != nil {
		s.log.Error("recording session client", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	// RFC 9207: tell the client which issuer answered, closing the mix-up attack.
	q.Set("iss", s.cfg.Issuer)
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleToken implements /oauth2/token for the authorization_code grant.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Token responses must never be cached: they carry bearer credentials.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "malformed form body", Status: http.StatusBadRequest})
		return
	}

	req, perr := oauth.ParseTokenRequest(r.Header, r.PostForm)
	if perr != nil {
		writeTokenError(w, perr)
		return
	}
	if gerr := oauth.ValidateGrantType(req.GrantType); gerr != nil {
		writeTokenError(w, gerr)
		return
	}
	c, lookupErr := s.lookupClient(ctx, req.ClientID)
	if lookupErr != nil || c == nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
			Description: "unknown client", Status: http.StatusUnauthorized})
		return
	}
	if aerr := oauth.RequireClientAuth(c, req); aerr != nil {
		writeTokenError(w, aerr)
		return
	}
	if c.Type == "confidential" {
		ok, err := s.verifyClientSecret(ctx, c, req.ClientSecret)
		if err != nil || !ok {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
				Description: "client authentication failed", Status: http.StatusUnauthorized})
			return
		}
	}

	if req.GrantType == "refresh_token" {
		s.handleRefreshGrant(w, r, c, req)
		return
	}
	if req.GrantType == "client_credentials" {
		s.handleClientCredentialsGrant(w, r, c, req)
		return
	}
	if req.GrantType == oauth.GrantTypeTokenExchange {
		s.handleTokenExchange(w, r, c)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	hash := store.HashToken(req.Code)
	consumed, cerr := store.ConsumeCode(ctx, tx, hash)

	if errors.Is(cerr, store.ErrCodeReused) {
		// Reuse is theft until proven otherwise. Reject AND kill the lineage,
		// then commit the revocation -- rolling back here would leave a stolen
		// code's tokens alive.
		n, rerr := store.RevokeFamilyForCode(ctx, tx, hash)
		if rerr != nil {
			s.log.Error("revoking after code reuse", "err", rerr)
		} else if aerr := audit.Write(ctx, tx, audit.Event{
			Type:          audit.EventCodeReused,
			ClientID:      req.ClientID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"families_revoked": n},
		}); aerr != nil {
			// The revocation still commits below if it can. Losing the audit row
			// for a theft signal is bad; failing to revoke the stolen tokens
			// because of it would be worse.
			s.log.Error("auditing code reuse", "err", aerr)
			if err := tx.Commit(ctx); err != nil {
				s.log.Error("committing revocation after code reuse", "err", err)
			}
		} else if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing revocation after code reuse", "err", err)
		}
		s.log.Warn("authorization code reuse detected", "client_id", req.ClientID,
			"families_revoked", n, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "authorization code has already been used", Status: http.StatusBadRequest})
		return
	}
	if cerr != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "authorization code is unknown or expired", Status: http.StatusBadRequest})
		return
	}

	if _, verr := oauth.ValidateCodeRedemption(req, c, &consumed.GrantRecord, time.Now()); verr != nil {
		// The code is already consumed by this point, which is correct: a failed
		// redemption must not leave a reusable code behind.
		if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing code consumption after failed validation", "err", err)
		}
		writeTokenError(w, verr)
		return
	}

	resp, err := s.mintTokens(ctx, tx, c, consumed)
	if err != nil {
		s.log.Error("minting tokens", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// mintSet issues the access token, ID token, and -- when offline_access was
// granted -- a refresh token, all from one authenticated subject.
//
// familyID is empty for a first issuance (an authorization code) and set when
// rotating, so a rotated token stays in its original lineage. Starting a new
// family on every refresh would make reuse detection impossible: there would be
// nothing to revoke.
func (s *Server) mintSet(ctx context.Context, tx pgx.Tx, c *clients.Client,
	orgID, userID, sid, nonce string, scopes, resources []string, familyID string) (*tokenResponse, []byte, error) {

	alg := keys.Algorithm(c.IDTokenAlg)
	key, err := s.cfg.Keys.Active(alg)
	if err != nil {
		return nil, nil, fmt.Errorf("no active key for the client's algorithm %s: %w", alg, err)
	}
	signer := tokens.NewSigner(key)

	now := time.Now()
	jti, err := newSID()
	if err != nil {
		return nil, nil, err
	}

	issuer := s.issuerFor(c)

	// RFC 8707: the requested resources become the AUDIENCE.
	//
	// Until now `resource` was parsed, stored and carried through refresh, and
	// then quietly dropped -- every access token was audienced to the client
	// itself. That means a token a client obtained for the billing API is
	// equally valid at the admin API, because neither can tell them apart: the
	// only audience either sees is "this client". Asking for a narrow token and
	// receiving a universal one is the opposite of what the parameter is for.
	//
	// With resources present, they ARE the audience. The client id stays only
	// when none were requested, which preserves today's behaviour for callers
	// that do not use the parameter.
	audience := []string{c.ClientID}
	if len(resources) > 0 {
		audience = resources
	}

	at, err := signer.SignJSON(tokens.AccessTokenClaims{
		Issuer:    issuer,
		Subject:   userID,
		Audience:  audience,
		Expiry:    now.Add(tokens.DefaultAccessTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
		JTI:       jti,
		ClientID:  c.ClientID,
		Scope:     joinScopes(scopes),
		SessionID: sid,
	}, tokens.TypAccessToken)
	if err != nil {
		return nil, nil, err
	}
	atHash, err := tokens.AtHash(alg, at)
	if err != nil {
		return nil, nil, err
	}

	resp := &tokenResponse{
		AccessToken: at,
		TokenType:   "Bearer",
		ExpiresIn:   int(tokens.DefaultAccessTokenTTL.Seconds()),
		Scope:       joinScopes(scopes),
	}

	// An ID token is an authentication statement, so it is only minted where
	// openid was granted -- a pure refresh of an API token should not re-assert
	// who the user is.
	if containsScope(scopes, "openid") {
		var authTime time.Time
		var acr string
		var amr []string
		if err := tx.QueryRow(ctx,
			`SELECT auth_time, acr, amr FROM core.sessions WHERE sid = $1`, sid).
			Scan(&authTime, &acr, &amr); err != nil {
			return nil, nil, fmt.Errorf("loading session context: %w", err)
		}
		claims := tokens.IDTokenClaims{
			Issuer:          issuer,
			Subject:         userID,
			Audience:        c.ClientID,
			Expiry:          now.Add(tokens.DefaultIDTokenTTL).Unix(),
			IssuedAt:        now.Unix(),
			AuthTime:        authTime.Unix(),
			ACR:             acr,
			AMR:             amr,
			Nonce:           nonce,
			SessionID:       sid,
			AuthorizedParty: c.ClientID,
			AccessTokenHash: atHash,
		}
		if err := s.addProfileClaims(ctx, tx, &claims, userID, scopes); err != nil {
			return nil, nil, err
		}

		idt, err := signer.SignIDToken(claims)
		if err != nil {
			return nil, nil, err
		}
		resp.IDToken = idt
	}

	if !containsScope(scopes, "offline_access") {
		return resp, nil, nil
	}

	if familyID == "" {
		familyID, err = store.NewRefreshFamily(ctx, tx, orgID, c.ClientID, userID, sid)
		if err != nil {
			return nil, nil, err
		}
	}
	rt, err := newSID()
	if err != nil {
		return nil, nil, err
	}
	rtHash := store.HashToken(rt)
	ttl := time.Duration(c.RefreshTokenTTLSeconds()) * time.Second
	if err := store.IssueRefreshToken(ctx, tx, familyID, rtHash, scopes, resources, ttl); err != nil {
		return nil, nil, err
	}
	resp.RefreshToken = rt
	return resp, rtHash, nil
}

func (s *Server) mintTokens(ctx context.Context, tx pgx.Tx, c *clients.Client, g *store.ConsumedCode) (*tokenResponse, error) {
	resp, _, err := s.mintSet(ctx, tx, c, g.OrgID, g.UserID, g.SessionID, g.Nonce, g.Scopes, g.Resources, "")
	return resp, err
}

func (s *Server) mintFromGrant(ctx context.Context, tx pgx.Tx, c *clients.Client, g *store.RefreshGrant) (*tokenResponse, []byte, error) {
	// No nonce on refresh: the claim belongs to the original authorization
	// request, and re-emitting a stale one would assert a binding that no longer
	// corresponds to any live client request.
	return s.mintSet(ctx, tx, c, g.OrgID, g.UserID, g.SessionID, "", g.Scopes, g.Resources, g.FamilyID)
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// handleRefreshGrant rotates a refresh token.
//
// Rotation without reuse detection is just churn: the value comes entirely from
// what happens when an already-rotated token is presented. That means a leaked
// token is detectable exactly once -- when the legitimate client and the thief
// both try to use the same generation -- so the response is to destroy the whole
// lineage rather than the single token.
// addProfileClaims puts the identity claims in the ID token itself.
//
// These were advertised in claims_supported and only ever available from
// userinfo, which forces every relying party into a second round trip for an
// email address they were told the ID token carries.
//
// Release is strictly by granted scope, and `profile` and `email` are separate
// grants that must not leak into each other -- the same rule userinfo applies,
// deliberately duplicated here rather than assumed, because two endpoints
// disagreeing about which scope releases what is how data escapes.
//
// A user who no longer exists or is deactivated is an ERROR, not an empty claim
// set: minting an authentication statement about a deactivated account is the
// one outcome that must not happen quietly.
func (s *Server) addProfileClaims(ctx context.Context, tx pgx.Tx,
	claims *tokens.IDTokenClaims, userID string, scopes []string) error {

	wantEmail := containsScope(scopes, "email")
	wantProfile := containsScope(scopes, "profile")
	if !wantEmail && !wantProfile {
		return nil
	}

	var email, username string
	var verified bool
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(email,''), COALESCE(username,''), email_verified_at IS NOT NULL
		FROM core.users WHERE id = $1 AND status = 'active'`, userID).
		Scan(&email, &username, &verified); err != nil {
		return fmt.Errorf("loading identity claims for %s: %w", userID, err)
	}

	if wantEmail && email != "" {
		claims.Email = email
		// A pointer, so `false` is emitted rather than dropped by omitempty.
		// "email_verified absent" and "email_verified false" mean different
		// things to a relying party deciding whether to trust the address.
		claims.EmailVerified = &verified
	}
	if wantProfile {
		claims.Username = username
		// No `name`: there is no display name stored anywhere, so there is
		// nothing honest to put in it. It has been removed from claims_supported
		// rather than emitted empty.
	}
	return nil
}

// handleClientCredentialsGrant issues a token for the client itself.
//
// There is no user here, and every difference from the other grants follows from
// that one fact:
//
//   - No ID token. An ID token is an authentication statement about a person;
//     there is no person. Issuing one with the client as `sub` is a well-known
//     way to confuse a downstream relying party into treating a machine as a
//     user, and OIDC Core does not define it for this grant.
//   - No refresh token. The client can always authenticate again -- it holds the
//     secret -- so a refresh token would be a second, longer-lived credential
//     with no benefit. RFC 6749 §4.4.3 says so explicitly.
//   - No session, so no sid, and nothing for logout to terminate.
//   - `sub` is the client_id, per RFC 9068 §5.
//
// Public clients are refused: this grant IS the client's secret, so a client
// without one has nothing to authenticate with.
func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request,
	c *clients.Client, req oauth.TokenRequest) {

	if !c.AllowsGrantType("client_credentials") {
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "client may not use the client_credentials grant",
			Status:      http.StatusBadRequest})
		return
	}
	if c.Type != "confidential" {
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "the client_credentials grant requires a confidential client",
			Status:      http.StatusBadRequest})
		return
	}

	// Default to the client's registered scopes when none are asked for, which is
	// what callers expect; narrow to what was requested otherwise.
	scopes := c.Scopes
	if req.Scope != "" {
		scopes = splitScopes(req.Scope)
		if unknown := c.UnknownScopes(scopes); len(unknown) > 0 {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
				Description: "client is not registered for scope " + unknown[0],
				Status:      http.StatusBadRequest})
			return
		}
	}
	// `openid` asks for an authentication statement about a user. There isn't
	// one. Silently dropping it would leave a caller waiting for an id_token
	// that never comes, so it is refused with the reason.
	if containsScope(scopes, "openid") {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
			Description: "openid is not available to the client_credentials grant: there is no user to authenticate",
			Status:      http.StatusBadRequest})
		return
	}

	alg := keys.Algorithm(c.IDTokenAlg)
	key, err := s.cfg.Keys.Active(alg)
	if err != nil {
		s.log.Error("no active key for client_credentials", "alg", alg, "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	jti, err := newSID()
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	now := time.Now()
	at, err := tokens.NewSigner(key).SignJSON(tokens.AccessTokenClaims{
		Issuer:   s.cfg.Issuer,
		Subject:  c.ClientID,
		Audience: []string{c.ClientID},
		Expiry:   now.Add(tokens.DefaultAccessTokenTTL).Unix(),
		IssuedAt: now.Unix(),
		JTI:      jti,
		ClientID: c.ClientID,
		Scope:    joinScopes(scopes),
		// No SessionID: nothing to tie this to, and inventing one would make
		// logout appear to cover a token it cannot.
	}, tokens.TypAccessToken)
	if err != nil {
		s.log.Error("signing client_credentials token", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	writeJSON(w, http.StatusOK, &tokenResponse{
		AccessToken: at,
		TokenType:   "Bearer",
		ExpiresIn:   int(tokens.DefaultAccessTokenTTL.Seconds()),
		Scope:       joinScopes(scopes),
	})
}

func (s *Server) handleRefreshGrant(w http.ResponseWriter, r *http.Request,
	c *clients.Client, req oauth.TokenRequest) {

	ctx := r.Context()
	if req.RefreshToken == "" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "refresh_token is required", Status: http.StatusBadRequest})
		return
	}
	if !c.AllowsGrantType("refresh_token") {
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "client may not use the refresh_token grant", Status: http.StatusBadRequest})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	oldHash := store.HashToken(req.RefreshToken)
	grant, rerr := store.RotateRefreshToken(ctx, tx, oldHash)

	if errors.Is(rerr, store.ErrRefreshReused) {
		n, revErr := store.RevokeFamilyByToken(ctx, tx, oldHash, "reuse_detected")
		if revErr != nil {
			s.log.Error("revoking family after refresh reuse", "err", revErr)
		} else if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing revocation after refresh reuse", "err", err)
		}
		s.log.Warn("refresh token reuse detected -- family revoked",
			"client_id", c.ClientID, "families_revoked", n)
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "refresh token has already been used", Status: http.StatusBadRequest})
		return
	}
	if rerr != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "refresh token is invalid or expired", Status: http.StatusBadRequest})
		return
	}

	// A refresh token must not belong to a different client than the one
	// presenting it, even when that client authenticated correctly.
	if grant.ClientID != c.ClientID {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "refresh token was not issued to this client", Status: http.StatusBadRequest})
		return
	}

	resp, newHash, err := s.mintFromGrant(ctx, tx, c, grant)
	if err != nil {
		s.log.Error("minting from refresh", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	if err := store.LinkSuccessor(ctx, tx, oldHash, newHash); err != nil {
		s.log.Error("linking successor", "err", err)
	}
	if err := tx.Commit(ctx); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleLoginPost verifies credentials and creates a session.
func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	authzQuery := r.PostForm.Get("authz")
	identifier := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	userID, orgID, stored, ok, err := s.lookupCredential(ctx, identifier)
	if err != nil {
		s.log.Error("looking up credential", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return
	}

	// One generic message for every failure -- unknown user, wrong password,
	// deactivated account. Distinguishing them is a user-enumeration oracle.
	const generic = "Incorrect username or password."

	if !ok {
		// No local credential. Before treating this as "no such user", check
		// whether it is a user we imported whose password still lives at the
		// provider being migrated away from. Those two cases look identical at
		// this form and must be handled completely differently.
		if done := s.tryDelegated(w, r, identifier, password, authzQuery); done {
			return
		}

		// Still spend the hashing budget so a missing user is not measurably
		// faster than a wrong password.
		_, _ = s.hasher.Verify(ctx, dummyHash, password)
		// No subject recorded: there is no account, and writing the submitted
		// identifier would put an attacker-chosen string -- often someone else's
		// email -- into an append-only table.
		s.auditDetached(ctx, audit.Event{
			Type:          audit.EventLoginFailed,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "unknown_identifier"},
		})
		s.renderLogin(w, r, authzQuery, generic)
		return
	}

	// Checked BEFORE spending an Argon2 evaluation. Verifying first would make
	// the throttle an amplifier: every rejected attempt would still cost the
	// server 19MB and a CPU burst, which is what the limiter exists to prevent.
	throttle, terr := store.CheckLoginThrottle(ctx, s.db, userID)
	if terr != nil {
		s.log.Error("checking login throttle", "err", terr)
	}
	if throttle.Throttled {
		// The generic message is kept: revealing that an account is throttled
		// confirms it exists. Retry-After carries the interval for a client that
		// wants it, and the header is not an enumeration signal on its own
		// because it is sent on the generic failure either way.
		w.Header().Set("Retry-After", strconv.Itoa(int(throttle.RetryAfter.Seconds())))
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "throttled", "failures": throttle.Failures},
		})
		s.renderLogin(w, r, authzQuery, generic)
		return
	}

	needsRehash, verr := s.hasher.Verify(ctx, stored, password)
	if verr != nil {
		if err := store.RecordLoginFailure(ctx, s.db, userID); err != nil {
			s.log.Error("recording login failure", "err", err)
		}
		s.auditDetached(ctx, audit.Event{
			Type:          audit.EventLoginFailed,
			OrgID:         orgID,
			SubjectID:     userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "bad_password"},
		})
		s.renderLogin(w, r, authzQuery, generic)
		return
	}

	// A correct password clears the throttle: we now know who this is, and
	// carrying their earlier typos forward would penalise the one user we have
	// just positively identified.
	if err := store.ClearLoginThrottle(ctx, s.db, userID); err != nil {
		s.log.Error("clearing login throttle", "err", err)
	}

	// Lazy rehash, before either branch: a successful password check upgrades a
	// foreign or below-policy hash whether or not a second factor follows.
	if needsRehash {
		if fresh, herr := s.hasher.Hash(ctx, password); herr == nil {
			if _, err := s.db.Exec(ctx, `
				UPDATE core.password_credentials
				SET hash = $2, algorithm = 'argon2id', is_current = true, updated_at = now()
				WHERE user_id = $1`, userID, fresh); err != nil {
				s.log.Error("rehashing password", "err", err)
			}
		}
	}

	// A correct password does NOT create a session when a second factor is
	// enrolled. It creates a pending authentication that can do nothing but
	// present a code -- otherwise a stolen password alone has already produced
	// something usable, which is the whole thing MFA exists to prevent.
	enrolled, err := store.HasConfirmedTOTP(ctx, s.db, userID)
	if err != nil {
		s.log.Error("checking second factor", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return
	}
	if enrolled {
		s.beginMFAChallenge(w, r, userID, orgID, authzQuery, []string{oauth.AMRPassword})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	s.completeSignIn(w, r, tx, userID, orgID, []string{oauth.AMRPassword}, authzQuery)
}

// completeSignIn creates the session once every required factor is proven.
//
// Shared by the password-only path and the second-factor path so there is ONE
// place a session comes into existence. Two paths would eventually disagree
// about acr, or about auditing, and the MFA one would be the one that drifted.
//
// It takes an open transaction and commits it: the session row, the audit entry
// and any second-factor state must land together or not at all.
func (s *Server) completeSignIn(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	userID, orgID string, amr []string, authzQuery string) {

	ctx := r.Context()

	// Two independent random values: a public sid that goes in tokens, and a
	// secret cookie token that never leaves the browser. Deriving one from the
	// other would collapse them back into a single value.
	sid, err := newSID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cookieToken, err := newSID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// acr is DERIVED from the factors actually used, never asserted. Writing a
	// literal here is how a password-only session ends up claiming multi-factor.
	acr := oauth.ACRFromAMR(amr)

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3, $4, $5, $6, now(), now() + $7::interval)`,
		sid, store.HashToken(cookieToken), orgID, userID, acr, amr, sessionTTL.String()); err != nil {
		s.log.Error("creating session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := audit.Write(ctx, tx, audit.Event{
		Type:          audit.EventLoginSucceeded,
		OrgID:         orgID,
		SubjectID:     userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"amr": amr, "acr": acr},
	}); err != nil {
		// Rule 4 of the package doc: no record, no session. A sign-in nobody can
		// prove happened is exactly what an investigation cannot work with.
		s.log.Error("auditing login", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.clearPending(w)
	s.setSessionCookie(w, cookieToken)

	// Back to whatever was parked, if anything was.
	if authzQuery != "" {
		http.Redirect(w, r, resumeAfterSignIn(authzQuery), http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed in"})
}

// dummyHash is a real Argon2id hash of a value nobody knows, used to keep the
// timing of "no such user" indistinguishable from "wrong password".
const dummyHash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"

func (s *Server) lookupCredential(ctx context.Context, identifier string) (userID, orgID, hash string, ok bool, err error) {
	// The status check is in the query: a deactivated user must not be able to
	// sign in, and doing it here means there is no window where a caller forgets.
	err = s.db.QueryRow(ctx, `
		SELECT u.id::text, u.org_id::text, pc.hash
		FROM core.users u
		JOIN core.password_credentials pc ON pc.user_id = u.id
		WHERE u.status = 'active'
		  AND (lower(u.email) = lower($1) OR lower(u.username) = lower($1))`,
		identifier).Scan(&userID, &orgID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return userID, orgID, hash, true, nil
}

func (s *Server) verifyClientSecret(ctx context.Context, c *clients.Client, presented string) (bool, error) {
	if c.SecretHash == "" || presented == "" {
		return false, nil
	}
	_, err := s.hasher.Verify(ctx, c.SecretHash, presented)
	if errors.Is(err, passwords.ErrMismatch) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Server) lookupClient(ctx context.Context, clientID string) (*clients.Client, error) {
	if clientID == "" {
		return nil, clients.ErrNotFound
	}
	return clients.Lookup(ctx, s.db, clientID)
}

// writeAuthzError delivers an authorization error by whichever route its
// disposition permits. A direct error renders here; only a redirect-disposition
// error is sent to the client.
func (s *Server) writeAuthzError(w http.ResponseWriter, r *http.Request,
	req oauth.AuthzRequest, e *oauth.AuthzError) {

	if e.Disposition == oauth.DispositionRedirect {
		target, err := oauth.ErrorRedirect(req.RedirectURI, s.cfg.Issuer, req.State, e)
		if err == nil {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		s.log.Error("building error redirect", "err", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = errorPage.Execute(w, map[string]string{
		"Code":        e.Code,
		"Description": e.Description,
	})
}

func writeTokenError(w http.ResponseWriter, e *oauth.TokenError) {
	status := e.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	if e.Code == "invalid_client" {
		// RFC 6749 §5.2: a 401 for invalid_client must carry a challenge.
		w.Header().Set("WWW-Authenticate", `Basic realm="signari"`)
	}
	writeJSON(w, status, map[string]string{
		"error":             e.Code,
		"error_description": e.Description,
	})
}

func splitScopes(s string) []string {
	var out []string
	for _, f := range splitFields(s) {
		out = append(out, f)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func joinScopes(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

var errorPage = template.Must(template.New("err").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in error</title></head>
<body><h1>Sign-in error</h1><p><strong>{{.Code}}</strong></p><p>{{.Description}}</p></body></html>`))

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// Terminate FIRST, and let the failure be visible. The previous shape logged
	// every error and then fell through to "signed out" regardless -- so a
	// database blip cleared the cookie, told the user they were signed out, and
	// left the session live with no back-channel notification sent. A user who
	// believes they signed out on a shared machine and did not is worse off than
	// one who is told it failed and tries again.
	// The session identity is captured BEFORE termination, because terminating
	// cascades the SAML participant rows away and the logout chain is built from
	// them.
	chainSID, chainUser, chainOrg := s.sessionIdentity(ctx, sessionCookie(r))

	if err := s.terminateOwnSession(ctx, sessionCookie(r)); err != nil {
		s.log.Error("ending session", "err", err)
		// The cookie is still cleared: it is defence in depth for THIS browser,
		// and withholding it would leave the user with neither outcome. But we
		// do not redirect and do not claim success.
		s.clearSessionCookie(w)
		writeError(w, http.StatusInternalServerError, "server_error",
			"sign-out could not be completed; your session may still be active")
		return
	}

	// Clear the cookie even if there was no live session: the user asked to be
	// signed out, and leaving a stale cookie behind is confusing.
	s.clearSessionCookie(w)

	// post_logout_redirect_uri must be REGISTERED before we redirect to it.
	// An unvalidated post-logout redirect is an open redirector reached from a
	// link that looks like a sign-out, which is a good phishing pretext.
	target := q.Get("post_logout_redirect_uri")
	if target != "" {
		// Scoped to the CLIENT, not global. The previous query asked only whether
		// SOME client had registered this URI, so any client's registered
		// post-logout URI worked for every other client -- a redirect reachable
		// from a link that looks like a sign-out, which is a good phishing pretext.
		//
		// The client is identified by client_id, or derived from id_token_hint when
		// the caller follows the spec and sends one.
		clientID := q.Get("client_id")
		if clientID == "" {
			clientID = s.clientFromIDTokenHint(q.Get("id_token_hint"))
		}
		var ok bool
		if err := s.db.QueryRow(ctx, `
			SELECT true FROM core.client_post_logout_redirect_uris
			WHERE redirect_uri = $1 AND client_id = $2`,
			target, clientID).Scan(&ok); err != nil || !ok {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"post_logout_redirect_uri is not registered")
			return
		}
		if st := q.Get("state"); st != "" {
			if u, err := url.Parse(target); err == nil {
				vals := u.Query()
				vals.Set("state", st)
				u.RawQuery = vals.Encode()
				target = u.String()
			}
		}
		// The post-logout target is now VALIDATED, so it is safe to hand to the
		// SAML chain as the place to land once propagation finishes.
		if chain := s.beginSAMLLogoutChain(ctx, chainSID, chainUser, chainOrg, target); chain != "" {
			http.Redirect(w, r, chain, http.StatusFound)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	// No post-logout redirect: propagate, then report.
	if chain := s.beginSAMLLogoutChain(ctx, chainSID, chainUser, chainOrg, ""); chain != "" {
		http.Redirect(w, r, chain, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// terminateOwnSession revokes the session behind the presented cookie.
//
// Every failure is returned rather than logged-and-ignored, because the caller's
// only honest options are "signed out" and "sign-out failed" -- and it cannot
// tell them apart if the errors are swallowed here. An absent or already-dead
// cookie is NOT a failure: there is nothing to terminate and the user's intent
// is already satisfied.
func (s *Server) terminateOwnSession(ctx context.Context, cookie string) error {
	if cookie == "" {
		return nil
	}
	sid, _, err := store.ResolveSessionCookie(ctx, s.db, store.HashToken(cookie))
	if err != nil {
		return fmt.Errorf("resolving session cookie: %w", err)
	}
	if sid == "" {
		return nil
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning logout transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := store.TerminateSessions(ctx, tx, sid, "", store.ReasonLogout); err != nil {
		return fmt.Errorf("terminating session: %w", err)
	}
	// The commit is what makes the revocation AND the queued back-channel logout
	// notifications durable -- they share this transaction by design, so a failed
	// commit means neither happened.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing logout: %w", err)
	}
	return nil
}

// clientFromIDTokenHint reads the audience of an id_token_hint.
//
// The hint is used ONLY to identify which client is asking, never to authorise
// anything: the post-logout URI is still checked against that client's registered
// set. A hint that fails to verify yields "" and the redirect is refused, which is
// the safe direction.
func (s *Server) clientFromIDTokenHint(hint string) string {
	if hint == "" {
		return ""
	}
	claims, err := tokens.VerifyIDTokenAudience(s.cfg.Keys, s.cfg.Issuer, hint)
	if err != nil {
		s.log.Info("id_token_hint did not verify", "err", err)
		return ""
	}
	return claims
}

// stepUpErrorCode maps a step-up reason to the OIDC error a client can act on.
//
// The distinction matters: login_required tells a client to send the user to
// interactive sign-in, while unmet_authentication_requirements (RFC 9470) tells
// it the requirement itself could not be met. A client that retries the wrong
// one loops forever.
func stepUpErrorCode(r oauth.StepUpReason) string {
	if r == oauth.StepUpNeedStronger {
		return "unmet_authentication_requirements"
	}
	return "login_required"
}

func (s *Server) tryDelegated(w http.ResponseWriter, r *http.Request,
	identifier, password, authzQuery string) bool {

	ctx := r.Context()
	if s.cfg.Root == nil {
		return false
	}
	pending, ok, err := store.LookupMigrationCandidate(ctx, s.db, identifier, s.cfg.Root)
	if err != nil {
		s.log.Error("looking up migration candidate", "err", err)
		return false
	}
	if !ok {
		return false
	}

	verr := s.delegator.Verify(ctx, pending.Source, identifier, password)
	switch {
	case errors.Is(verr, delegated.ErrUnavailable):
		// The OLD provider is broken, not the user. Reported as a temporary
		// failure and NOT counted against the account -- otherwise someone
		// else's outage locks out every user still to be migrated.
		store.RecordDelegationFailure(ctx, s.db, pending.Source.ID, verr.Error())
		s.log.Error("migration source unavailable", "source", pending.Source.DisplayName,
			"err", verr, "correlation_id", correlationID(ctx))
		s.renderLogin(w, r, authzQuery,
			"Sign-in is temporarily unavailable. Please try again shortly.")
		return true

	case verr != nil:
		store.RecordDelegationFailure(ctx, s.db, pending.Source.ID, "rejected")
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: pending.OrgID, SubjectID: pending.UserID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "delegated_rejected", "source": pending.Source.DisplayName},
		})
		s.renderLogin(w, r, authzQuery, "Incorrect username or password.")
		return true
	}

	// Accepted by the old provider. Take a local hash NOW, in the same
	// transaction as the session -- so this user never needs the old system
	// again, and the migration shrinks by one.
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		s.log.Error("hashing a migrated password", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return true
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := store.CompleteMigration(ctx, tx, pending.UserID, pending.OrgID,
		pending.Source.ID, hash); err != nil {
		s.log.Error("completing migration", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return true
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "account.migrated", OrgID: pending.OrgID, SubjectID: pending.UserID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"source": pending.Source.DisplayName},
	}); err != nil {
		s.log.Error("auditing migration", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return true
	}

	s.log.Info("user migrated on first sign-in", "source", pending.Source.DisplayName,
		"correlation_id", correlationID(ctx))
	s.completeSignIn(w, r, tx, pending.UserID, pending.OrgID,
		[]string{oauth.AMRPassword}, authzQuery)
	return true
}

// issuerFor returns the issuer to stamp on this client's tokens.
//
// Almost always the deployment's own issuer. A client carrying an issuer_alias
// is mid-migration from another provider and still checks the OLD `iss` value,
// so its tokens are minted under that instead -- which is what lets an
// application move with a DNS change rather than a code change.
//
// The alias is validated at write time by a database trigger against the
// instance's registered aliases (migration 0015), so a value read here has
// already been proven to be one this deployment legitimately claims.
func (s *Server) issuerFor(c *clients.Client) string {
	if c != nil && c.IssuerAlias != "" {
		return c.IssuerAlias
	}
	return s.cfg.Issuer
}

// acceptedIssuers is what our own resource endpoints will honour: this
// deployment's issuer plus any registered legacy aliases.
func (s *Server) acceptedIssuers() []string {
	return append([]string{s.cfg.Issuer}, s.cfg.IssuerAliases...)
}

// handleTokenExchange implements RFC 8693.
//
// The validation rules live in internal/oauth (scope ceiling, audience
// allow-list, permitted subject token types). This is the part that must get one
// thing right that validation cannot check for it:
//
//	THE SUBJECT TOKEN'S SCOPES COME FROM THE VERIFIED TOKEN, NEVER THE REQUEST.
//
// Reading them from the form would let a caller describe its own token as
// carrying any scope it liked, and the ceiling would then be measured against a
// number the attacker chose.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request, c *clients.Client) {
	ctx := r.Context()
	ex := oauth.ParseExchange(r.PostForm)

	// Verified first. Everything downstream reasons about what this token
	// actually says, not what the request claims about it.
	subject, err := tokens.VerifyAccessTokenAny(s.cfg.Keys, s.acceptedIssuers(), ex.SubjectToken)
	if err != nil {
		s.log.Info("token exchange: subject token rejected", "err", err,
			"caller", c.ClientID, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "the subject token is not valid", Status: http.StatusBadRequest})
		return
	}

	// A revoked or signed-out token must not be exchangeable. Otherwise
	// exchange becomes a way to launder a dead credential into a live one --
	// the token the user revoked yesterday still produces working tokens today.
	if revoked, rerr := store.JTIRevoked(ctx, s.db, subject.JTI); rerr != nil || revoked {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "the subject token has been revoked", Status: http.StatusBadRequest})
		return
	}
	if subject.SessionID != "" {
		live, serr := store.SessionLive(ctx, s.db, subject.SessionID)
		if serr != nil || !live {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "the session behind the subject token has ended",
				Status:      http.StatusBadRequest})
			return
		}
	}

	granted, audience, terr := oauth.ValidateExchange(ex, c.MayExchange, c.ExchangeAudiences,
		subject.ClientID, c.ClientID, splitScopes(subject.Scope))
	if terr != nil {
		writeTokenError(w, terr)
		return
	}

	key, err := s.cfg.Keys.Active(keys.Algorithm(c.IDTokenAlg))
	if err != nil {
		s.log.Error("token exchange: no active key", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	jti, err := newSID()
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	// The actor chain. The caller is recorded as acting for the subject, and any
	// chain the subject token already carried is nested beneath -- so a token
	// three delegations deep still names every party, in order.
	act := &tokens.Actor{Subject: c.ClientID, Act: subject.Act}

	now := time.Now()
	at, err := tokens.NewSigner(key).SignJSON(tokens.AccessTokenClaims{
		Issuer:   s.issuerFor(c),
		Subject:  subject.Subject, // still the USER; exchange delegates, it does not impersonate
		Audience: audience,
		Expiry:   now.Add(tokens.DefaultAccessTokenTTL).Unix(),
		IssuedAt: now.Unix(),
		JTI:      jti,
		ClientID: c.ClientID,
		Scope:    joinScopes(granted),
		// The session is carried through deliberately: an exchanged token must
		// die when the user signs out, exactly like the token it came from.
		SessionID: subject.SessionID,
		Act:       act,
	}, tokens.TypAccessToken)
	if err != nil {
		s.log.Error("token exchange: signing", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "oauth.token_exchanged", SubjectID: subject.Subject, ClientID: c.ClientID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"acting_for": subject.ClientID, "audience": audience, "scope": granted,
		},
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": at,
		// RFC 8693 §2.2.1 requires issued_token_type, and token_type must be
		// "Bearer" spelled exactly so.
		"issued_token_type": oauth.TokenTypeAccess,
		"token_type":        "Bearer",
		"expires_in":        int(tokens.DefaultAccessTokenTTL.Seconds()),
		"scope":             joinScopes(granted),
	})
}

// resumeAfterSignIn decides where a freshly signed-in browser goes.
//
// Two shapes are parked. Nearly always it is an OIDC authorization request,
// which is resumed by replaying its query at the authorization endpoint. But
// flows that are not OIDC at all -- forward auth, and SAML -- park
// `return=<local path>` instead, because replaying their query at the
// authorization endpoint lands the user on a request with no client_id.
//
// That bug was live: /proxy/start parked `return=/proxy/start?rd=...` and
// sign-in sent the browser to /oauth2/authorize?return=/proxy/start, so the
// whole not-yet-signed-in half of forward auth was broken. It went unnoticed
// because every test signed in first.
func resumeAfterSignIn(authzQuery string) string {
	if dest, ok := parkedReturn(authzQuery); ok {
		return dest
	}
	return oidc.PathAuthorize + "?" + authzQuery
}

// parkLogin builds the URL that sends a browser to sign in and come back.
//
// The return path is encoded as a query VALUE, not concatenated. Writing
// "return=" + dest looks equivalent and is not: the moment dest carries its own
// query string, its `&` separates parameters when the parked value is parsed
// again, and everything after the first one is silently lost.
//
// That was a live bug. A SAML request parked as
// `return=/saml/sso?RelayState=x&SAMLRequest=...` came back as
// `/saml/sso?RelayState=x` with the request gone, and the endpoint answered
// "no SAMLRequest" -- a failure that points at the wrong component entirely.
func parkLogin(dest string) string {
	return "/login?authz=" + url.QueryEscape(url.Values{"return": {dest}}.Encode())
}

// parkedReturn extracts a local return path, refusing anything that could leave
// this origin.
//
// This runs immediately AFTER authentication, which makes it one of the most
// attractive open-redirect sinks in the whole application: a link to our own
// login page that deposits the user on an attacker's site once they have
// entered their password is a credible phishing step, and the URL the user
// checked before typing was genuinely ours.
func parkedReturn(authzQuery string) (string, bool) {
	q, err := url.ParseQuery(authzQuery)
	if err != nil {
		return "", false
	}
	dest := q.Get("return")
	if dest == "" {
		return "", false
	}
	// Must be a path on THIS origin. A single leading slash, and nothing that a
	// browser would read as the start of an authority:
	//
	//   //evil.test        protocol-relative, goes to evil.test
	//   /\evil.test       browsers normalise the backslash and it goes there too
	//   /%2f%2fevil.test   decoded by some proxies before the browser sees it
	if !strings.HasPrefix(dest, "/") ||
		strings.HasPrefix(dest, "//") ||
		strings.HasPrefix(dest, "/\\") ||
		strings.Contains(dest, "\\") {
		return "", false
	}
	// Parse it as well, so a value carrying its own scheme or host is refused
	// rather than reasoned about.
	u, err := url.Parse(dest)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "", false
	}
	return dest, true
}

// sessionIdentity resolves who a session cookie belongs to.
//
// Read BEFORE termination: ending the session cascades away the rows the SAML
// logout chain is built from, so afterwards there is nothing left to propagate
// to.
func (s *Server) sessionIdentity(ctx context.Context, cookie string) (sid, userID, orgID string) {
	if cookie == "" {
		return "", "", ""
	}
	sid, _, err := store.ResolveSessionCookie(ctx, s.db, store.HashToken(cookie))
	if err != nil || sid == "" {
		return "", "", ""
	}
	_ = s.db.QueryRow(ctx,
		`SELECT user_id::text, org_id::text FROM core.sessions WHERE sid = $1`, sid).
		Scan(&userID, &orgID)
	return sid, userID, orgID
}
