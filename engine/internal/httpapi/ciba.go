package httpapi

import (
	"errors"
	"html/template"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// Client-Initiated Backchannel Authentication, CIBA Core 1.0 (Final, 2021-09-01).
//
//	POST /oauth2/backchannel      client authenticates -> auth_req_id
//	POST /oauth2/token            grant_type=urn:openid:params:grant-type:ciba
//	GET  /account/requests        the person approves or refuses
//
// # Poll mode only, and said so in discovery
//
// §7.3 defines three delivery modes. Ping and push have us call an endpoint the
// client hosts, which means outbound HTTP to a client-supplied URL from inside
// the authorization server -- a request forgery surface that has to be defended
// with an allow-list, and a delivery guarantee that has to be retried and parked
// when it fails. We have that machinery for back-channel logout
// (internal/outbox), so it is buildable; it is not built here, and
// `backchannel_token_delivery_modes_supported` says `["poll"]` rather than
// listing modes that would silently never deliver.
//
// A client that sends `client_notification_token` is refused rather than served,
// because a client that receives an auth_req_id concludes the mode it asked for
// was accepted, and would wait forever.

// handleBackchannelAuth is the backchannel authentication endpoint, §7.
func (s *Server) handleBackchannelAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	if err := r.ParseForm(); err != nil {
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusBadRequest,
			Code: "invalid_request", Description: "malformed form body"})
		return
	}

	// §7.1: "The Client MUST authenticate to the Backchannel Authentication
	// Endpoint using the authentication method registered for its client_id".
	//
	// There is no unauthenticated variant of this endpoint, and that is the
	// point: it causes a prompt to appear on a stranger's phone. Left open, it
	// would be a way to make somebody's device buzz on demand, which is both a
	// nuisance and a phishing primitive -- the victim is trained to approve
	// prompts, and eventually approves one that was not theirs.
	creds, cerr := oauth.ParseClientCredentials(r.Header, r.PostForm)
	if cerr != nil {
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusUnauthorized,
			Code: "invalid_client", Description: cerr.Description})
		return
	}
	c, err := s.lookupClient(ctx, creds.ClientID)
	if err != nil || c == nil {
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusUnauthorized,
			Code: "invalid_client", Description: "unknown client"})
		return
	}
	if c.Type != "confidential" {
		// §7.1 requires the registered authentication method, and a public
		// client has none. Refused explicitly rather than falling through to a
		// credential check that would pass on an empty secret.
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusUnauthorized,
			Code: "invalid_client",
			Description: "backchannel authentication requires a confidential client: " +
				"this endpoint makes a prompt appear on somebody's device, so the " +
				"caller has to be one we can identify"})
		return
	}
	if err := s.authenticateConfidentialClient(ctx, r, c, creds.ClientSecret); err != nil {
		s.log.Info("backchannel client authentication failed", "client_id", creds.ClientID,
			"err", err, "correlation_id", correlationID(ctx))
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusUnauthorized,
			Code: "invalid_client", Description: "client authentication failed"})
		return
	}

	// §13: unauthorized_client, "the Client is not authorized to use this
	// authentication flow". Registration decides, as it does for every grant.
	if !c.AllowsGrantType(oauth.GrantTypeCIBA) {
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusBadRequest,
			Code: "unauthorized_client",
			Description: "this client is not registered for the CIBA grant; add " +
				oauth.GrantTypeCIBA + " to its grant types"})
		return
	}

	req, perr := oauth.ParseCIBARequest(r.PostForm, c.ClientID)
	if perr != nil {
		writeCIBAError(w, perr)
		return
	}

	// Scopes must be ones the client is registered for, exactly as at the
	// authorization endpoint. A grant that skipped this would be a way to obtain
	// scopes the client could not ask for through a browser.
	if unknown := c.UnknownScopes(splitScopes(req.Scope)); len(unknown) > 0 {
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusBadRequest,
			Code:        "invalid_scope",
			Description: "this client is not registered for scope " + unknown[0]})
		return
	}

	// Only login_hint is resolvable here. login_hint_token and id_token_hint are
	// parsed and refused rather than quietly treated as a login_hint, which
	// would resolve an opaque token as though it were an email address and
	// almost always find nobody -- reporting unknown_user_id for a request that
	// was in fact unsupported.
	if req.HintKind != oauth.HintLogin {
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusBadRequest,
			Code:        "invalid_request",
			Description: req.HintKind + " is not supported by this server; use login_hint"})
		return
	}

	userID, err := store.ResolveCIBASubject(ctx, s.db, c.OrgID, req.Hint)
	if errors.Is(err, store.ErrCIBASubjectUnknown) {
		// §13 gives this its own code. It does disclose whether an identifier
		// exists -- but only to a client that has already authenticated with its
		// own credentials, and the specification requires the distinction so a
		// client can tell "wrong person" from "try again".
		s.auditDetached(ctx, audit.Event{
			Type: "ciba.unknown_subject", OrgID: c.OrgID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"client_id": c.ClientID},
		})
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusBadRequest,
			Code: "unknown_user_id", Description: "no account matches that hint"})
		return
	}
	if err != nil {
		s.log.Error("resolving a CIBA subject", "err", err)
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusInternalServerError,
			Code: "server_error", Description: "unavailable"})
		return
	}

	authReqID, err := oauth.NewAuthReqID()
	if err != nil {
		s.log.Error("minting an auth_req_id", "err", err)
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusInternalServerError,
			Code: "server_error", Description: "unavailable"})
		return
	}

	lifetime := req.Expiry()
	if _, err := store.CreateBackchannelAuthentication(ctx, s.db, c.OrgID, c.ClientID,
		userID, req.Scope, req.BindingMessage, req.ACRValues,
		store.HashToken(authReqID), oauth.CIBAMinPollInterval, lifetime); err != nil {
		s.log.Error("recording a backchannel authentication", "err", err)
		writeCIBAError(w, &oauth.CIBAError{Status: http.StatusInternalServerError,
			Code: "server_error", Description: "unavailable"})
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "ciba.requested", OrgID: c.OrgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"client_id": c.ClientID, "scope": req.Scope,
			"binding_message": req.BindingMessage != "",
		},
	})

	// §7.3's response. 200, not 201: the specification says "HTTP 200 OK".
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_req_id": authReqID,
		"expires_in":  int(lifetime.Seconds()),
		"interval":    oauth.CIBAMinPollInterval,
	})
}

// handleCIBAGrant is the token endpoint half, §10.1.
//
// Deliberately the same shape as handleDeviceCodeGrant, calling the same
// PollDeviceCode, because §11 and RFC 8628 §3.5 are the same four errors with
// the same meanings. Two implementations would be two chances to get the
// ordering wrong, and the ordering is what decides whether a client that polls
// too fast learns anything about the state.
func (s *Server) handleCIBAGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	ctx := r.Context()

	authReqID := r.PostForm.Get("auth_req_id")
	if authReqID == "" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "auth_req_id is required", Status: http.StatusBadRequest})
		return
	}

	d, err := store.PollDeviceCode(ctx, s.db, store.HashToken(authReqID), clientID, "ciba")
	switch {
	case errors.Is(err, store.ErrDeviceCodePending):
		writeTokenError(w, &oauth.TokenError{Code: "authorization_pending",
			Description: "the authorization request is still pending as the end-user " +
				"hasn't yet been authenticated",
			Status: http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeSlowDown):
		writeTokenError(w, &oauth.TokenError{Code: "slow_down",
			Description: "polling faster than the interval; wait five seconds longer",
			Status:      http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeDenied):
		writeTokenError(w, &oauth.TokenError{Code: "access_denied",
			Description: "the end-user denied the authorization request",
			Status:      http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeWrongClient):
		s.log.Info("auth_req_id presented by the wrong client", "presented_by", clientID,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "this auth_req_id was not issued to this client",
			Status:      http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeUnknown):
		writeTokenError(w, &oauth.TokenError{Code: "expired_token",
			Description: "the auth_req_id has expired; make a new authentication request",
			Status:      http.StatusBadRequest})
		return
	case err != nil:
		s.log.Error("polling an auth_req_id", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}

	s.issueDeviceTokens(w, r, d)
}

// handleBackchannelRequests shows the person what is waiting for them.
func (s *Server) handleBackchannelRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/requests"), http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		s.decideBackchannel(w, r, sid, userID, orgID)
		return
	}

	pending, err := store.PendingBackchannelFor(ctx, s.db, userID)
	if err != nil {
		s.log.Error("listing backchannel requests", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	type row struct {
		ID, ClientName, Scope, BindingMessage string
		Expires                               string
	}
	rows := make([]row, 0, len(pending))
	for _, p := range pending {
		rows = append(rows, row{
			ID: p.ID, ClientName: p.ClientName, Scope: p.Scope,
			BindingMessage: p.BindingMessage,
			Expires:        time.Until(p.ExpiresAt).Round(time.Second).String(),
		})
	}
	s.renderPage(w, r, backchannelPage, map[string]any{
		"Requests": rows, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// decideBackchannel records an approval or a refusal.
func (s *Server) decideBackchannel(w http.ResponseWriter, r *http.Request,
	sid, userID, orgID string) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "your session expired; reload and try again", http.StatusForbidden)
		return
	}
	id := r.PostForm.Get("id")
	approve := r.PostForm.Get("decision") == "approve"

	// The session's user is passed to the store, which puts it in the WHERE
	// clause. Approving somebody else's request is therefore not something this
	// handler has to remember to prevent.
	if err := store.DecideBackchannel(ctx, s.db, id, userID, sid, approve); err != nil {
		// Not theirs, already answered, or expired. One message, because
		// distinguishing them would say whether a request exists for somebody
		// else.
		s.log.Info("a backchannel decision did not apply", "err", err,
			"correlation_id", correlationID(ctx))
	} else {
		verb := "denied"
		if approve {
			verb = "approved"
		}
		s.auditDetached(ctx, audit.Event{
			Type: "ciba." + verb, OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"request_id": id},
		})
	}
	http.Redirect(w, r, "/account/requests", http.StatusSeeOther)
}

// writeCIBAError renders §13's error response with its own status code.
func writeCIBAError(w http.ResponseWriter, e *oauth.CIBAError) {
	status := e.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{
		"error": e.Code, "error_description": e.Description,
	})
}

var backchannelPage = template.Must(template.New("backchannel").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in requests</title><style>` + pageCSS + `</style></head>
<body>
<h1>Sign-in requests</h1>
{{if not .Requests}}
<p>Nothing is waiting for you.</p>
{{else}}
<p>An application has asked to sign in as you. Approve it only if you started it.</p>
{{range .Requests}}
<form method="POST" action="/account/requests">
<input type="hidden" name="{{$.CSRFField}}" value="{{$.CSRF}}">
<input type="hidden" name="id" value="{{.ID}}">
<p><strong>{{.ClientName}}</strong> wants: {{.Scope}}</p>
{{if .BindingMessage}}<p>Reference shown on the other device: <code>{{.BindingMessage}}</code></p>{{end}}
<p>Expires in {{.Expires}}.</p>
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Not me</button>
</form>
<hr>
{{end}}
{{end}}
</body></html>`))
