package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Cross-app access (specs/id-jag.txt). Both halves are here: this server as the IdP,
// turning a sign-in into a grant another authorization server will take, and this server
// as that other server, taking one. The second is the jwt-bearer grant with more rules.

// idJAGLifetime is how long a grant lasts. §9.2 is about how much a stolen subject token
// reaches, and a grant is a credential on the same terms.
const idJAGLifetime = 5 * time.Minute

// handleIDJAGExchange is §4.3: an ID token this client was given, and a server to be
// admitted to. No person is asked, which is the point of it, so what stands in for them
// is an operator's entry for this client and that server.
func (s *Server) handleIDJAGExchange(w http.ResponseWriter, r *http.Request, c *clients.Client) {
	ctx := r.Context()
	refuse := func(code, description string) {
		writeTokenError(w, &oauth.TokenError{Code: code, Description: description, Status: http.StatusBadRequest})
	}
	// §4.3.3: "MUST reject a request without client authentication with invalid_client".
	if c.Type != "confidential" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
			Description: "a grant is only issued to a client that authenticates", Status: http.StatusUnauthorized})
		return
	}
	// §4.3.3: "If the request contains more than one audience value, the IdP MUST respond
	// with invalid_request."
	audiences := r.PostForm["audience"]
	if len(audiences) != 1 || audiences[0] == "" {
		refuse("invalid_request", "name exactly one audience")
		return
	}
	if firstForm(r, "subject_token_type") != oauth.TokenTypeIDToken {
		refuse("invalid_request", "the subject token of a grant is an ID token")
		return
	}
	if firstForm(r, "authorization_details") != "" {
		refuse("invalid_authorization_details", "a grant carries scopes and resources here")
		return
	}
	userID, idToken, ok := s.idJAGSubject(ctx, w, c, firstForm(r, "subject_token"))
	if !ok {
		return
	}

	entry, known, err := store.IDJAGAudienceFor(ctx, s.db, c.OrgID, c.ClientID, audiences[0])
	if err != nil {
		s.log.ErrorContext(ctx, "reading an id-jag audience", "err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	if entry == nil {
		// §4.3.4.3: the first "needs to change the request", and the second has to take
		// it up with whoever hands out access.
		if known {
			refuse("access_denied", "this client may not reach that authorization server")
		} else {
			refuse("invalid_target", "this server has no relationship with that audience")
		}
		return
	}
	// §4.3.3: "SHOULD respond with invalid_target ... if any requested resource is not
	// governed by the Resource Authorization Server identified by audience".
	resources := r.PostForm["resource"]
	for _, resource := range resources {
		if !slices.Contains(entry.Resources, resource) {
			refuse("invalid_target", "that resource is not one this client may ask for there")
			return
		}
	}
	// As §4.3 has it, these mean what the other server says they mean, so the list is
	// the only thing that decides. Nothing asked for is nothing granted.
	var scopes []string
	if asked := splitScopes(firstForm(r, "scope")); len(asked) > 0 {
		scopes = slices.DeleteFunc(asked, func(scope string) bool { return !slices.Contains(entry.Scopes, scope) })
		if len(scopes) == 0 {
			refuse("invalid_scope", "none of those scopes may be asked for there")
			return
		}
	}
	withdrawn, err := store.ConsentWithdrawn(ctx, s.db, userID, c.ClientID)
	if err != nil {
		s.log.ErrorContext(ctx, "checking for a withdrawn consent", "err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	if withdrawn {
		refuse("access_denied", "this person has withdrawn this client's access")
		return
	}
	if s.grantRefusedByPolicy(w, r, c.OrgID, c.ClientID, userID, idToken.SessionID, strings.Join(scopes, " "), "id_jag") {
		return
	}
	// The operator's provider has a veto over what is issued, and a grant buys tokens
	// somewhere else that no provider of this server will see.
	if _, ok := s.consultTokenHook(ctx, w, c, store.TokenHookRequest{Subject: userID, ClientID: c.ClientID, Scopes: scopes,
		Grant: oauth.GrantTypeTokenExchange, OrgID: c.OrgID}); !ok {
		return
	}
	grant, err := s.signIDJAG(ctx, c, entry, userID, idToken, resources, scopes)
	if err != nil {
		s.log.ErrorContext(ctx, "signing an id-jag", "err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	// §9.2: "SHOULD record the audience, resource, scope, and authenticated client of
	// each Token Exchange request", which is how a client reaching for somewhere new shows.
	s.auditDetached(ctx, audit.Event{Type: "oauth.id_jag_issued", OrgID: c.OrgID, SubjectID: userID, ClientID: c.ClientID,
		CorrelationID: correlationID(ctx), Detail: map[string]any{"audience": entry.Audience, "resource": resources, "scope": scopes}})

	w.Header().Set("Cache-Control", "no-store")
	out := map[string]any{"issued_token_type": oauth.TokenTypeIDJAG, "access_token": grant, "token_type": "N_A",
		"expires_in": int(idJAGLifetime.Seconds())}
	if len(scopes) > 0 {
		out["scope"] = strings.Join(scopes, " ")
	}
	writeJSON(w, http.StatusOK, out)
}

// idJAGSubject is §4.3.3's check of the subject token: one of ours, an ID token and not
// merely something this server signed, issued to the client presenting it, and from a
// sign-in that still stands. A session is the person's and is read now (ADR-007), so
// somebody signed out or deactivated since the ID token was issued gets nothing from it.
func (s *Server) idJAGSubject(ctx context.Context, w http.ResponseWriter, c *clients.Client, raw string) (string, *tokens.IDTokenClaims, bool) {
	refused := func(reason string, err error) (string, *tokens.IDTokenClaims, bool) {
		s.log.InfoContext(ctx, "id-jag: subject token refused", "reason", reason, "err", err, "client_id", c.ClientID,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request", Description: "the subject token is not valid",
			Status: http.StatusBadRequest})
		return "", nil, false
	}
	claims, err := tokens.VerifyIDToken(s.cfg.Keys, s.acceptedIssuers(ctx), raw, time.Now())
	if err != nil {
		return refused("it did not verify", err)
	}
	// §4.3.3: "MUST validate that the audience of the assertion ... matches the client_id
	// of the client authentication of the request".
	if claims.Audience != c.ClientID {
		return refused("issued to another client", nil)
	}
	userID, err := store.PersonOfLiveSession(ctx, s.db, claims.SessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return refused("the sign-in behind it has ended", nil)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "id-jag: reading a session", "err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return "", nil, false
	}
	return userID, claims, true
}

// signIDJAG is §3.1. The address goes in because §3.1 recommends it, and an entry naming
// that server is an operator having said it may have it. An instance can hold several
// organisations, so `tenant` says which, as §4.4.1 needs of a multi-tenant issuer.
func (s *Server) signIDJAG(ctx context.Context, c *clients.Client, entry *store.IDJAGAudience, userID string,
	idToken *tokens.IDTokenClaims, resources, scopes []string) (string, error) {

	key, err := s.cfg.Keys.Active(keys.Algorithm(entry.Alg))
	if err != nil {
		return "", err
	}
	jti, err := newSID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]any{"iss": s.issuerFor(c), "sub": userID, "aud": entry.Audience, "client_id": entry.RemoteClientID,
		"jti": jti, "iat": now.Unix(), "exp": now.Add(idJAGLifetime).Unix(), "tenant": c.OrgID}
	if person, perr := store.CredentialSubject(ctx, s.db, userID); perr != nil {
		return "", perr
	} else if email, found := person["email"]; found {
		claims["email"] = email
	}
	if idToken.AuthTime != 0 {
		claims["auth_time"] = idToken.AuthTime
	}
	if idToken.ACR != "" {
		claims["acr"] = idToken.ACR
	}
	if len(idToken.AMR) > 0 {
		claims["amr"] = idToken.AMR
	}
	switch len(resources) {
	case 0:
	case 1:
		claims["resource"] = resources[0]
	default:
		claims["resource"] = resources
	}
	if len(scopes) > 0 {
		claims["scope"] = strings.Join(scopes, " ")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return tokens.NewSigner(key).SignRaw(payload, oauth.TypIDJAG)
}

// idJAGGrant is §4.4.1 for a grant this server is the audience of, on top of everything
// the jwt-bearer grant asked of it as an assertion: the audience exactly this server, the
// client the one it was issued to name, and each resource one this organisation governs.
// It answers the scopes and resources to issue for. A failure is invalid_grant, in the
// one sentence the grant uses for everything.
func (s *Server) idJAGGrant(ctx context.Context, w http.ResponseWriter, c *clients.Client, st *assertionStatement) ([]string, []string, bool) {
	refuse := func(reason string) ([]string, []string, bool) {
		s.log.InfoContext(ctx, "id-jag: refused", "reason", reason, "client_id", c.ClientID, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant", Description: assertionRefused, Status: http.StatusBadRequest})
		return nil, nil, false
	}
	var claims oauth.IDJAGClaims
	if err := json.Unmarshal(st.payload, &claims); err != nil {
		return refuse("its claims did not parse")
	}
	// §4.4.1: "that element MUST be the issuer identifier", one element being as far as
	// an assertion gets anyway. The token endpoint's address, which a plain assertion may
	// use, is not that.
	if !slices.Contains(s.acceptedIssuers(ctx), st.claims.Audience[0]) {
		return refuse("its audience is not this issuer")
	}
	// §4.4.1: "MUST reject the request with an invalid_grant error unless the client_id
	// claim identifies the authenticated client."
	if claims.ClientID != c.ClientID {
		return refuse("it was issued for another client")
	}
	// §4.4.1: "If the ID-JAG contains a cnf claim, the Resource Authorization Server
	// verifies proof of possession", and a grant that cannot be held to that is not taken.
	if len(claims.Confirmation) > 0 {
		return refuse("it is bound to a key, which is not checked here")
	}
	resources := []string(claims.Resource)
	missing, err := store.UnregisteredResource(ctx, s.db, c.OrgID, resources)
	if err != nil {
		s.log.ErrorContext(ctx, "id-jag: reading the resources", "err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return nil, nil, false
	}
	if missing != "" {
		return refuse("it names a resource this organisation does not govern")
	}
	// The most it can buy is what this client is registered for here. openid goes because
	// nobody signed in here, as the grant says of any assertion.
	scopes := c.Scopes
	if asked := splitScopes(claims.Scope); len(asked) > 0 {
		scopes = slices.DeleteFunc(asked, func(scope string) bool { return !slices.Contains(c.Scopes, scope) })
	}
	scopes = slices.DeleteFunc(slices.Clone(scopes), func(scope string) bool { return scope == "openid" })
	return scopes, resources, true
}
