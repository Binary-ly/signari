package httpapi

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sulimanbenhalim/idp/engine/internal/clients"
	"github.com/sulimanbenhalim/idp/engine/internal/keys"
	"github.com/sulimanbenhalim/idp/engine/internal/oauth"
	"github.com/sulimanbenhalim/idp/engine/internal/oidc"
	"github.com/sulimanbenhalim/idp/engine/internal/passwords"
	"github.com/sulimanbenhalim/idp/engine/internal/store"
	"github.com/sulimanbenhalim/idp/engine/internal/tokens"
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
	if req.GrantType != "authorization_code" && req.GrantType != "refresh_token" {
		writeTokenError(w, &oauth.TokenError{Code: "unsupported_grant_type",
			Description: "only authorization_code and refresh_token are implemented so far",
			Status:      http.StatusBadRequest})
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
		} else if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing revocation after code reuse", "err", err)
		}
		s.log.Warn("authorization code reuse detected", "client_id", req.ClientID, "families_revoked", n)
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
	orgID, userID, sid string, scopes, resources []string, familyID string) (*tokenResponse, []byte, error) {

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

	at, err := signer.SignJSON(tokens.AccessTokenClaims{
		Issuer:    s.cfg.Issuer,
		Subject:   userID,
		Audience:  []string{c.ClientID},
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
		idt, err := signer.SignIDToken(tokens.IDTokenClaims{
			Issuer:          s.cfg.Issuer,
			Subject:         userID,
			Audience:        c.ClientID,
			Expiry:          now.Add(tokens.DefaultIDTokenTTL).Unix(),
			IssuedAt:        now.Unix(),
			AuthTime:        authTime.Unix(),
			ACR:             acr,
			AMR:             amr,
			SessionID:       sid,
			AuthorizedParty: c.ClientID,
			AccessTokenHash: atHash,
		})
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
	resp, _, err := s.mintSet(ctx, tx, c, g.OrgID, g.UserID, g.SessionID, g.Scopes, g.Resources, "")
	return resp, err
}

func (s *Server) mintFromGrant(ctx context.Context, tx pgx.Tx, c *clients.Client, g *store.RefreshGrant) (*tokenResponse, []byte, error) {
	return s.mintSet(ctx, tx, c, g.OrgID, g.UserID, g.SessionID, g.Scopes, g.Resources, g.FamilyID)
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
		// Still spend the hashing budget so a missing user is not measurably
		// faster than a wrong password.
		_, _ = s.hasher.Verify(ctx, dummyHash, password)
		s.renderLogin(w, r, authzQuery, generic)
		return
	}

	needsRehash, verr := s.hasher.Verify(ctx, stored, password)
	if verr != nil {
		s.renderLogin(w, r, authzQuery, generic)
		return
	}

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

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3, $4, '1', ARRAY['pwd'], now(), now() + $5::interval)`,
		sid, store.HashToken(cookieToken), orgID, userID, sessionTTL.String()); err != nil {
		s.log.Error("creating session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Lazy rehash: a successful login silently upgrades a foreign or
	// below-policy hash, inside the same transaction as the login.
	if needsRehash {
		if fresh, herr := s.hasher.Hash(ctx, password); herr == nil {
			if _, err := tx.Exec(ctx, `
				UPDATE core.password_credentials
				SET hash = $2, algorithm = 'argon2id', is_current = true, updated_at = now()
				WHERE user_id = $1`, userID, fresh); err != nil {
				s.log.Error("rehashing password", "err", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.setSessionCookie(w, cookieToken)

	// Back to the parked authorization request, if there was one.
	if authzQuery != "" {
		http.Redirect(w, r, oidc.PathAuthorize+"?"+authzQuery, http.StatusFound)
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
		w.Header().Set("WWW-Authenticate", `Basic realm="idp"`)
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
