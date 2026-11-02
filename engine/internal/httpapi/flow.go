package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/rar"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/txntoken"
)

// A session's lifetime is its organisation's (store.SessionLifetimesOf), no
// longer a constant here.
const codeTTL = 60 * time.Second // RFC 6749 recommends <= 10 minutes; short is free here

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

	query, perr := authorizeParams(r)
	if perr != nil {
		s.renderAuthzFailure(w, r, perr.Error())
		return
	}
	// Everything below hands the request on by its URL's query: to the sign-in page,
	// the consent page and back here. A POST carries none, so the person signed in
	// and arrived nowhere. On a copy, so the wrappers around this handler go on
	// seeing what was sent.
	if r.Method == http.MethodPost {
		r = r.Clone(ctx)
		r.URL.RawQuery = query.Encode()
	}

	// RFC 6749 §3.1, before anything reads a parameter.
	//
	// Rendered locally rather than redirected, and the ordering is the point: a
	// request carrying two `redirect_uri` values must not be answered by
	// redirecting to either of them. This is the endpoint the rule exists for --
	// it was previously enforced only at PAR, which does not redirect at all.
	if err := refuseDuplicateParams(query); err != nil {
		s.renderAuthzFailure(w, r, err.Error())
		return
	}
	if crossSiteForm(r) {
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
		return
	}

	// A signed Request Object goes where a pushed request goes, so that from here on
	// there is one way a protected request travels. The pages after this hand a request
	// on through the browser, and spread over a URL it would be open to anybody there:
	// the whole of what a signature buys. Parked, the browser carries a handle, and a
	// short `exp` does not run out while somebody looks for their phone.
	objectProblem, byValue := "", false
	if object := query.Get("request"); object != "" {
		handle, problem := s.parkRequestObject(r, query.Get("client_id"), query.Get("request_uri"), object)
		if objectProblem = problem; problem == "" {
			byValue = true
			query.Del("request")
			query.Set("request_uri", handle)
		}
	}

	// # Redeeming a pushed request
	//
	// When request_uri is present, the pushed parameters REPLACE the query
	// entirely -- only client_id survives, because it is needed to find the
	// handle in the first place (RFC 9126 §4).
	//
	// Merging the two would undo the whole feature: whoever controls the browser
	// could append `scope=admin` to a URL whose other parameters are protected,
	// and the request would be authorized with a scope the client never pushed.
	wasPushed, wasSigned := false, false
	if requestURI := query.Get("request_uri"); requestURI != "" && objectProblem == "" {
		wasPushed = true
		pushed, err := s.readPushedRequest(ctx, requestURI, query.Get("client_id"))
		if err != nil {
			s.log.InfoContext(ctx, "pushed request refused", "err", err,
				"correlation_id", correlationID(ctx))
			// Rendered locally. There is no validated redirect_uri to send an
			// error to -- the parameters that would have named one are exactly
			// what could not be retrieved.
			s.renderAuthzFailure(w, r, err.Error())
			return
		}
		pushed.Set("client_id", query.Get("client_id"))
		wasSigned = pushed.Get(signedRequestMark) != ""
		pushed.Del(signedRequestMark)

		// What the pages from here carry through the browser is the handle, and
		// the three things they read to choose what to show, which come from the
		// push and decide nothing: this block replaces them on every arrival.
		parked := url.Values{"client_id": {query.Get("client_id")}, "request_uri": {requestURI}}
		for _, hint := range []string{"login_hint", "ui_locales", "acr_values"} {
			if v := pushed.Get(hint); v != "" {
				parked.Set(hint, v)
			}
		}
		r = r.Clone(ctx)
		r.URL.RawQuery = parked.Encode()
		query = pushed
	}

	req := oauth.ParseAuthz(query)
	req.RequestObjectProblem = objectProblem

	s.admitMetadataClient(r, req.ClientID)
	// In any state, so ValidateAuthz can tell the person the client is
	// disabled; it refuses one before anything else is read.
	c, lookupErr := s.lookupClientAnyState(ctx, req.ClientID)
	if authzErr := oauth.ValidateAuthz(req, c, lookupErr); authzErr != nil {
		s.writeAuthzError(w, r, req, c, authzErr)
		return
	}

	// RFC 9101 §10.5: "the server MUST reject the authorization request from the client
	// that does not conform to this specification", or the signature is something an
	// attacker chooses not to send. Redirected, the redirect_uri being valid by now.
	if c != nil && c.RequireSignedRequest && !wasSigned {
		s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "invalid_request",
			Description: "this client must sign its authorization requests", Disposition: oauth.DispositionRedirect})
		return
	}

	// `claims` is compiled into the ordinary parameters here, and the pages after
	// this hand on the compiled request, so what is consented to is what is granted.
	// A pushed request was compiled when it was pushed. wantSubject is who this
	// request says it is for.
	wantSubject, cerr := oauth.CompileClaims(query, c)
	if cerr != nil {
		s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "invalid_request", Description: cerr.Error(),
			Disposition: oauth.DispositionRedirect})
		return
	}
	if query.Get("claims") != "" {
		req = oauth.ParseAuthz(query)
		if !wasPushed {
			r = r.Clone(ctx)
			r.URL.RawQuery = query.Encode()
		}
	}
	if req.IDTokenHint != "" {
		subject, audience, herr := tokens.VerifyIDTokenHint(s.cfg.Keys, s.cfg.Issuer, req.IDTokenHint)
		if herr != nil || audience != c.ClientID || (wantSubject != "" && wantSubject != subject) {
			s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "invalid_request",
				Description: "id_token_hint is not an ID token this server issued to this client for this person",
				Disposition: oauth.DispositionRedirect})
			return
		}
		wantSubject = subject
	}

	// Redirected like the shape check: the redirect_uri is validated by now.
	if c != nil {
		if err := s.checkResources(ctx, s.db, c, c.OrgID, req.Resources); err != nil {
			aerr := &oauth.AuthzError{Code: "invalid_target", Description: err.Error(),
				Disposition: oauth.DispositionRedirect}
			if !refusedTarget(err) {
				s.log.ErrorContext(ctx, "checking resource indicators", "err", err, "correlation_id", correlationID(ctx))
				aerr.Code, aerr.Description = "temporarily_unavailable", "please try again shortly"
			}
			s.writeAuthzError(w, r, req, c, aerr)
			return
		}
	}

	// A client held to `state` (9.13): redirected, the redirect_uri being valid, so
	// the relying party hears of it rather than a person seeing a dead end.
	if c != nil && c.RequireState && req.State == "" {
		s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "invalid_request",
			Description: "this client must send state", Disposition: oauth.DispositionRedirect})
		return
	}

	// RFC 9396: validated here, after the client is known, because §5's
	// unknown-field rule is enforced against the types this CLIENT may request.
	//
	// Refused as a redirected error, not a rendered page: by this point the
	// redirect_uri is validated, and §5 names an error code
	// (`invalid_authorization_details`) that only reaches the client through the
	// redirect. A client that asked for a permission it may not have needs to be
	// told which one, in the place it is listening.
	if c != nil && req.RawAuthorizationDetails != "" {
		details, aerr := s.parseAuthorizationDetails(ctx, c, req.RawAuthorizationDetails)
		if aerr != nil {
			s.writeAuthzError(w, r, req, c, aerr)
			return
		}
		req.AuthorizationDetails = details
	}

	// A client marked as requiring PAR must not be able to start an ordinary
	// authorization. Without this the feature is advisory: such a client has
	// gained an option, not the integrity property.
	//
	// Read with the client rather than by a second query, which skipped the
	// requirement whenever that query failed. And decided by whether the request
	// was redeemed from a push: the redeemed parameters have replaced the query
	// by now, so asking the query for request_uri refused every request from
	// such a client, the pushed ones included. A request object sent by value is parked
	// the same way and is not a push: RFC 9126 keeps the parameters off the browser
	// altogether, and that one came through it.
	if c != nil && c.RequirePAR && (!wasPushed || byValue) {
		s.log.InfoContext(ctx, "plain authorization request refused for a PAR-only client",
			"client_id", c.ClientID, "correlation_id", correlationID(ctx))
		s.renderAuthzFailure(w, r,
			"This client must start authorization by pushing the request first.")
		return
	}

	// prompt=create (https://openid.net/specs/openid-connect-prompt-create-1_0.html
	// §4.1): the client wants the person shown "the account creation UX rather
	// than the login flow". Unconditional, like login, whether or not somebody
	// is signed in: they may be making a second account.
	if oauth.HasPrompt(req.Prompt, oauth.PromptCreate) {
		s.startCreateAccount(w, r, c)
		return
	}

	// prompt=select_account: OIDC Core §3.1.2.1, the OP "SHOULD prompt the
	// End-User to select a user account". The accounts this browser holds in
	// the client's organisation, to choose from (accounts.go); choosing one
	// resumes here with select_account consumed. With none, a sign-in is the
	// choice, below. It used to force a fresh sign-in whatever was held.
	if oauth.HasPrompt(req.Prompt, oauth.PromptSelectAccount) {
		held, herr := s.heldAccounts(ctx, r, c.OrgID)
		if herr != nil {
			s.log.ErrorContext(ctx, "reading the accounts this browser holds", "err", herr)
		}
		if len(held) > 0 {
			s.renderAccounts(w, r, r.URL.RawQuery, held, "")
			return
		}
	}

	var session store.BrowserSession
	if cookie := sessionCookie(r); cookie != "" {
		var err error
		// The cookie is a bearer secret; the sid it maps to is the public
		// identifier. Never treat the cookie value as the sid.
		session, err = store.ResolveBrowserSession(ctx, s.db, store.HashToken(cookie), s.instanceID)
		if err != nil {
			s.log.ErrorContext(ctx, "checking session", "err", err)
			s.writeAuthzError(w, r, req, c,
				&oauth.AuthzError{Code: "server_error", Description: "could not verify session",
					Disposition: oauth.DispositionRedirect})
			return
		}
	}
	sid, live := session.SID, session.Live

	// A live session is NOT automatically sufficient. This is where a step-up
	// requirement becomes real: acr_values, max_age and prompt=login are each a
	// client saying it does not trust what we already have.
	//
	// Re-evaluated per authorization request, deliberately. Treating acr as a
	// property frozen at login is a genuine bypass -- a password-only session
	// would satisfy every future multi-factor demand for as long as it lives.
	// What the sign-in form says when a step-up sends a person to it.
	loginMsg := ""

	// A session of somebody other than the person the request names is no session
	// for this request: not refused, since the right person may be there to sign in,
	// and never answered with a code for the wrong one.
	somebodyElse := false
	if live && wantSubject != "" {
		// The request names them as this client knows them.
		named, err := subjectFor(ctx, s.db, c, session.UserID)
		if err != nil {
			s.log.ErrorContext(ctx, "reading how this client knows them", "err", err)
			s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "server_error",
				Description: "could not verify session", Disposition: oauth.DispositionRedirect})
			return
		}
		if named != wantSubject {
			live, somebodyElse = false, true
			loginMsg = "This application is asking for somebody else. Sign in as them to go on."
		}
	}
	if live {
		reason, detail := oauth.SessionSufficient(session.AMR, session.AuthTime, time.Now(),
			req.ACRValues, req.MaxAge, req.Prompt)
		// The client's own floor, whatever the request asks for: acr_values is
		// the relying party's to send, and a user can remove it from the URL.
		if reason == oauth.StepUpNone && !meetsClientFloor(c, session.AMR) {
			reason, detail = oauth.StepUpNeedStronger, "this application requires multi-factor authentication"
			if oauth.RequiredRung("", c.MinimumACR) >= 3 {
				detail = "this application requires a sign-in with a passkey or security key"
			}
		}
		if reason != oauth.StepUpNone {
			s.log.InfoContext(ctx, "step-up required", "sid", sid, "reason", reason,
				"correlation_id", correlationID(ctx))
			// The session stays live. Step-up asks for another factor; it does
			// not throw away an authentication that was legitimately performed.
			live = false

			// prompt=none plus an unmet requirement is unsatisfiable by
			// definition: the client forbade interaction and we need some.
			if oauth.HasPrompt(req.Prompt, oauth.PromptNone) {
				s.writeAuthzError(w, r, req, c, &oauth.AuthzError{
					Code:        stepUpErrorCode(reason),
					Description: detail,
					Disposition: oauth.DispositionRedirect})
				return
			}

			// The other unsatisfiable case, and the one that used to loop.
			//
			// A client asks for acr_values=2. The subject has no second factor
			// enrolled. Rendering the sign-in form sends them to a password box,
			// a correct password produces a password-only session -- acr 1, which
			// is the honest answer -- and the redirect lands back here, where the
			// session is found insufficient and the form is rendered again. The
			// person is bounced between two pages forever with nothing explaining
			// why, and no interaction they can perform will ever end it.
			//
			// Only StepUpNeedStronger. A max_age or prompt=login step-up IS
			// satisfiable by signing in again, so those must still show the form.
			if reason == oauth.StepUpNeedStronger {
				if need := oauth.RequiredRung(req.ACRValues, c.MinimumACR); need >= 3 {
					// Only a passkey or a security key reaches these rungs, and at
					// "4" only one bound to its device: without one, every sign-in
					// lands back here, so the requirement is refused instead. With
					// one, the form says which sign-in it wants.
					held, kerr := store.HasWebAuthnKey(ctx, s.db, session.UserID, need == 4)
					switch {
					case kerr != nil:
						s.log.ErrorContext(ctx, "checking for a key at a step-up", "err", kerr)
					case !held:
						s.writeAuthzError(w, r, req, c, &oauth.AuthzError{
							Code: "unmet_authentication_requirements",
							Description: "the requested authentication context needs a passkey or " +
								"security key, and this account has none that reaches it",
							Disposition: oauth.DispositionRedirect})
						return
					}
					loginMsg = "This application asks you to sign in with a passkey or security key."
				} else if enrolled, ferr := store.HasSecondFactor(ctx, s.db, session.UserID); ferr != nil {
					// Failing open here shows the form, which is the previous
					// behaviour: a database error must not turn into a refusal.
					s.log.ErrorContext(ctx, "checking second factor for a step-up", "err", ferr)
				} else if !enrolled {
					s.log.InfoContext(ctx, "step-up is unsatisfiable: no second factor is enrolled",
						"sid", sid, "correlation_id", correlationID(ctx))
					s.writeAuthzError(w, r, req, c, &oauth.AuthzError{
						Code: "unmet_authentication_requirements",
						Description: "this account has no second factor enrolled, so the " +
							"requested authentication context cannot be reached",
						Disposition: oauth.DispositionRedirect})
					return
				} else if s.stepUpNeverAsked(ctx, session.OrgID, session.UserID, r.URL.RawQuery) {
					// The same loop by another road: a factor is enrolled, and
					// the sign-in flow never asks a password sign-in for it.
					s.log.InfoContext(ctx, "step-up is unsatisfiable: the sign-in flow asks for no second factor",
						"sid", sid, "correlation_id", correlationID(ctx))
					s.writeAuthzError(w, r, req, c, &oauth.AuthzError{
						Code: "unmet_authentication_requirements",
						Description: "this organisation's sign-in flow does not ask for a second " +
							"factor, so the requested authentication context cannot be reached",
						Disposition: oauth.DispositionRedirect})
					return
				}
			}
		}
	}

	if !live {
		// prompt=none means "do not interact". A client asking for silent
		// authentication must get an error it can handle, not a login page.
		if oauth.HasPrompt(req.Prompt, oauth.PromptNone) {
			description := "no active session and prompt=none was requested"
			if somebodyElse {
				description = "the session here is not the person this request names, and prompt=none was requested"
			}
			s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "login_required", Description: description,
				Disposition: oauth.DispositionRedirect})
			return
		}
		// Only with no session at all: one short of what is asked needs a factor
		// here, which the provider cannot supply.
		if sid == "" {
			slug, kind, herr := s.pinnedProvider(ctx, c.OrgID)
			if slug == "" && herr == nil {
				slug, kind, herr = s.homeRealm(ctx, c.OrgID, query)
			}
			if herr != nil {
				s.log.ErrorContext(ctx, "finding a home realm", "err", herr, "correlation_id", correlationID(ctx))
			}
			if slug != "" {
				http.Redirect(w, r, providerStart(slug, kind, r.URL.RawQuery), http.StatusSeeOther)
				return
			}
		}
		// The application's own page, which walks the same stages over JSON. Not for
		// that walk's own request, or it would be sent to the page it came from.
		if c.LoginUI != "" && loginMsg == "" && headlessFrom(ctx) == nil {
			http.Redirect(w, r, loginUIRedirect(c.LoginUI, r.URL.RawQuery), http.StatusSeeOther)
			return
		}
		s.renderLogin(w, r, r.URL.RawQuery, loginMsg)
		return
	}

	// Consent is checked AFTER authentication and step-up, and BEFORE any code is
	// issued. Asking first would show a stranger which clients exist and what
	// they request; issuing first would make the question decorative.
	//
	// A session is a sign-in to one organisation, and is no sign-in at all for
	// another's application. Nothing compared the two, so somebody who could
	// sign in anywhere -- an organisation with open signup or federation --
	// opened another tenant's client and was issued its tokens.
	if session.OrgID != c.OrgID {
		s.log.InfoContext(ctx, "a session from another organisation asked for this client",
			"client_id", c.ClientID, "correlation_id", correlationID(ctx))
		if oauth.HasPrompt(req.Prompt, oauth.PromptNone) {
			s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "login_required",
				Description: "the active session does not belong to this client's organisation",
				Disposition: oauth.DispositionRedirect})
			return
		}
		s.renderLogin(w, r, r.URL.RawQuery, "You are signed in to a different organisation. "+
			"Sign in with your account for this application.")
		return
	}
	// # Access policy
	//
	// Evaluated AFTER authentication and step-up (so `mfa` reflects what actually
	// happened) and BEFORE consent -- there is no point asking somebody to
	// approve scopes for an application they are not permitted to reach.
	if c.HasAccessPolicy {
		if pd := s.checkAccessPolicy(ctx, r, c.OrgID, c.ClientID, session.UserID,
			req.Scope, oauth.IsMultiFactor(session.AMR), session.AMR); pd != nil {
			s.log.InfoContext(ctx, "access refused by policy", "client_id", c.ClientID,
				"rule", pd.Rule, "correlation_id", correlationID(ctx))
			// Rendered to the person, not redirected to the client. A policy refusal
			// is about who they are, and the message names what to do next; bouncing
			// it back as `access_denied` would leave them looking at an application
			// error page that cannot explain anything.
			s.renderAuthzFailure(w, r, pd.Message)
			return
		}
	}
	if c.HasClientAccessHook && s.clientAccessRefused(ctx, c.OrgID, c.ClientID, session.UserID) {
		s.renderAuthzFailure(w, r, clientAccessRefusal)
		return
	}
	if wanted := credentialAskOf(req, c, session.UserID); len(wanted.Configurations) > 0 {
		open, oerr := store.CredentialOpenTo(ctx, s.db, wanted)
		if oerr != nil {
			s.log.ErrorContext(ctx, "reading whether a credential is open to a person", "err", oerr,
				"correlation_id", correlationID(ctx))
			s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "server_error",
				Description: "unavailable", Disposition: oauth.DispositionRedirect})
			return
		}
		if !open {
			s.writeAuthzError(w, r, req, c, credentialNotOpen())
			return
		}
	}

	decision, ask, err := s.needsConsent(r, c, session.UserID, req)
	if err != nil {
		s.log.ErrorContext(ctx, "checking consent", "err", err)
		s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "server_error",
			Description: "could not check consent", Disposition: oauth.DispositionRedirect})
		return
	}
	if ask {
		// prompt=none forbade interaction, and consent is interaction. The client
		// gets an error it can act on rather than a screen it cannot show.
		if oauth.HasPrompt(req.Prompt, oauth.PromptNone) {
			s.writeAuthzError(w, r, req, c, &oauth.AuthzError{Code: "consent_required",
				Description: consentRequiredReason(req),
				Disposition: oauth.DispositionRedirect})
			return
		}
		s.renderConsent(w, r, c, decision, req.AuthorizationDetails, r.URL.RawQuery)
		return
	}

	s.issueCodeAndRedirect(w, r, req, c, session)
}

// startCreateAccount answers prompt=create. Where this client's organisation
// takes self-sign-up, the sign-up form, carrying the request to the sign-in
// that completes it: §4.1 counts the flow successful only once an id_token is
// returned. Elsewhere the sign-in form, saying why; the same section leaves
// whether an OP makes a new identity or signs in an existing one out of scope.
// create is consumed either way, or that sign-in would resume to here again.
func (s *Server) startCreateAccount(w http.ResponseWriter, r *http.Request, c *clients.Client) {
	authz := s.answerPrompts(r.Context(), r.URL.RawQuery, oauth.PromptCreate)
	rule, err := s.signupRule(r.Context())
	if err != nil {
		s.log.ErrorContext(r.Context(), "reading the sign-up rule for prompt=create", "err", err)
	}
	if err == nil && rule != nil && rule.OrgID == c.OrgID {
		http.Redirect(w, r, "/signup?authz="+url.QueryEscape(authz), http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, authz, s.tr(r).Text("signup.notoffered"))
}

// clientAccessRefusal is what a person is told when the client_access provider says no.
// Not its reason, which was written outside this deployment.
const clientAccessRefusal = "You do not have access to this application."

// consentRequiredReason says WHICH unapproved thing blocked a prompt=none request.
//
// A client that sent authorization_details and gets back "the user has not
// consented to the requested scopes" will go looking at its scope list, which is
// fine. Details never carry prior consent (see needsConsent), so for a RAR
// request this is not a missing approval to hunt for -- it is a permanent
// property of the request, and saying so stops the client retrying prompt=none
// forever waiting for a grant that will never be stored.
func consentRequiredReason(req oauth.AuthzRequest) string {
	if len(req.AuthorizationDetails) > 0 {
		return "authorization_details always require explicit approval and cannot " +
			"be satisfied by prior consent; retry without prompt=none"
	}
	return "the user has not consented to the requested scopes"
}

// issueCodeAndRedirect mints an authorization code for a live session.
func (s *Server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request,
	req oauth.AuthzRequest, c *clients.Client, session store.BrowserSession) {

	ctx := r.Context()

	// Every code is minted here, whichever page led to it (the authorization
	// endpoint, the consent form), so the organisation is checked here as well
	// as where the request is first read.
	if session.OrgID != c.OrgID {
		s.log.WarnContext(ctx, "refused a code for a session from another organisation",
			"client_id", c.ClientID, "correlation_id", correlationID(ctx))
		s.renderAuthzFailure(w, r, "You are signed in to a different organisation. "+
			"Sign in with your account for this application.")
		return
	}

	code, hash, err := store.NewCode()
	if err != nil {
		s.log.ErrorContext(ctx, "generating code", "err", err)
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
		// The rung this request asked for and the session reaches, above the
		// session's own, for the ID token to report.
		ACR: oauth.SatisfiedACR(session.AMR, req.ACRValues),
	}
	// RFC 9396 §7 requires the token response to return the details "as granted
	// by the resource owner", so they are carried on the code rather than
	// re-derived at the token endpoint from a parameter the client resends. A
	// client that could resend them is a client that could change them.
	details, derr := store.MarshalDetails(req.AuthorizationDetails)
	if derr != nil {
		s.log.ErrorContext(ctx, "encoding authorization_details", "err", derr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// A pushed request gives one code. Spent here and in this transaction, so of two
	// racing for it one has none, and an issuance that fails leaves it good.
	if handle := r.URL.Query().Get("request_uri"); handle != "" {
		spent, serr := store.SpendPushedRequest(ctx, tx, pushedHash(handle))
		if serr != nil {
			s.log.ErrorContext(ctx, "spending a pushed request", "err", serr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !spent {
			_ = tx.Rollback(ctx)
			s.renderAuthzFailure(w, r, errPushedRequestSpent.Error())
			return
		}
	}
	// Asked again, because an offer can have been spent or lapsed while the consent
	// screen stood, and spent here for the same reason as the pushed request.
	if wanted := credentialAskOf(req, c, session.UserID); len(wanted.Configurations) > 0 {
		spent, serr := store.SpendCredentialOffer(ctx, tx, wanted)
		if serr != nil {
			s.log.ErrorContext(ctx, "spending a credential offer", "err", serr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !spent {
			_ = tx.Rollback(ctx)
			s.writeAuthzError(w, r, req, c, credentialNotOpen())
			return
		}
	}
	if err := store.IssueCode(ctx, tx, session.OrgID, c.ClientID, session.SID, session.UserID, grant, hash,
		req.Resources, details); err != nil {
		s.log.ErrorContext(ctx, "issuing code", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.noteChallengeReuse(ctx, tx, session.OrgID, c.ClientID, session.UserID, req.CodeChallenge); err != nil {
		s.log.ErrorContext(ctx, "noting a PKCE challenge", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Record that this relying party saw the session, so logout can enumerate it.
	if err := store.TouchSessionClient(ctx, tx, session.SID, c.ClientID); err != nil {
		s.log.ErrorContext(ctx, "recording session client", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// RFC 9207's iss is the issuer as this client knows it, so a client pinned
	// to an alias is told the alias, as its tokens are.
	out := responseParams{Code: code, State: req.State, Issuer: s.issuerFor(c)}

	// Hybrid: an id_token beside the code, bound to it by c_hash.
	//
	// Minted after the commit, because it hashes the code that was actually
	// issued. Doing it inside the transaction would mean hashing a code that a
	// rollback could still take away.
	if oauth.NormaliseResponseType(req.ResponseType) == "code id_token" {
		idt, ierr := s.mintHybridIDToken(ctx, c, session.SID, code, req.Nonce, s.issuerFor(c))
		if ierr != nil {
			s.log.ErrorContext(ctx, "minting the hybrid id_token", "err", ierr, "client", c.ClientID)
			// The code is already issued and valid. Failing the whole response
			// here would strand it; the client asked for an id_token though, and
			// silently omitting one it will look for is worse than an error it
			// can act on.
			http.Error(w, "the id_token could not be issued", http.StatusInternalServerError)
			return
		}
		out.IDToken = idt
	}

	s.deliverAuthzResponse(w, r, req, c, out)
}

// withRoles adds a person's roles in the application to a token's claims, when the
// client names a claim for them. A mapper that took the same name keeps it, as it would
// against anything else: it was set by an operator, on purpose, for this client.
func withRoles(ctx context.Context, q store.Querier, c *clients.Client, userID, orgID string,
	claims map[string]any) (map[string]any, error) {
	if c.RolesClaim == "" || userID == "" {
		return claims, nil
	}
	if _, taken := claims[c.RolesClaim]; taken {
		return claims, nil
	}
	roles, err := store.ApplicationRoles(ctx, q, orgID, userID, c.ClientID)
	if err != nil {
		return nil, fmt.Errorf("reading the roles in %s: %w", c.ClientID, err)
	}
	if len(roles) == 0 {
		return claims, nil
	}
	if claims == nil {
		claims = map[string]any{}
	}
	claims[c.RolesClaim] = roles
	return claims, nil
}

// mintHybridIDTokenissues the front-channel id_token for a hybrid response.
//
// It carries c_hash and NOT at_hash: no access token exists at this point, and
// none will ever cross the front channel. Profile claims are left out for the
// same reason -- this token travels through the browser, and the back-channel
// one issued at the token endpoint is where an application should read a
// person's details from.
func (s *Server) mintHybridIDToken(ctx context.Context, c *clients.Client,
	sid, code, nonce, issuer string) (string, error) {

	alg := keys.Algorithm(c.IDTokenAlg)
	key, err := s.cfg.Keys.Active(alg)
	if err != nil {
		return "", fmt.Errorf("no active key for %s: %w", alg, err)
	}
	chash, err := tokens.CHash(alg, code)
	if err != nil {
		return "", err
	}

	var authTime time.Time
	var acr string
	var amr []string
	if err := s.db.QueryRow(ctx,
		`SELECT auth_time, acr, amr FROM core.sessions WHERE sid = $1`, sid).
		Scan(&authTime, &acr, &amr); err != nil {
		return "", fmt.Errorf("loading session context: %w", err)
	}

	now := time.Now()
	var userID string
	if err := s.db.QueryRow(ctx,
		`SELECT user_id::text FROM core.sessions WHERE sid = $1`, sid).Scan(&userID); err != nil {
		return "", err
	}
	subject, err := subjectFor(ctx, s.db, c, userID)
	if err != nil {
		return "", err
	}
	idt, err := tokens.NewSigner(key).SignIDToken(tokens.IDTokenClaims{
		Issuer:          issuer,
		Subject:         subject,
		Audience:        c.ClientID,
		Expiry:          now.Add(tokens.DefaultIDTokenTTL).Unix(),
		IssuedAt:        now.Unix(),
		AuthTime:        authTime.Unix(),
		ACR:             acr,
		AMR:             amr,
		Nonce:           nonce,
		SessionID:       sid,
		AuthorizedParty: c.ClientID,
		CodeHash:        chash,
	})
	if err != nil {
		return "", err
	}
	return sealIDToken(c, idt)
}

// sealIDToken encrypts a signed ID token to the client, when it asked for that. OIDC
// Core §2: "If the ID Token is encrypted, it MUST be signed then encrypted". A failure
// is the caller's to refuse on: an RP told to expect it encrypted "SHOULD reject" one
// that is not (§3.1.3.7), and it would be sent through the clear to be rejected.
func sealIDToken(c *clients.Client, signed string) (string, error) {
	if c.IDTokenEncryption.Alg == "" {
		return signed, nil
	}
	return tokens.EncryptTo([]byte(signed), true, c.EncryptionKeys, c.IDTokenEncryption)
}

// tokenStatus records the token endpoint's status, a Write without a
// WriteHeader being the implicit 200.
type tokenStatus struct {
	http.ResponseWriter
	code    int
	written bool
}

func (t *tokenStatus) WriteHeader(code int) {
	if !t.written {
		t.code, t.written = code, true
	}
	t.ResponseWriter.WriteHeader(code)
}

func (t *tokenStatus) Write(b []byte) (int, error) {
	t.written = true
	return t.ResponseWriter.Write(b)
}

// Unwrap keeps the writer underneath reachable, as every wrapper must.
func (t *tokenStatus) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// grantLabel is a grant_type as the tokens-issued counter labels it. A value
// outside the counter's set is contained there as "other".
func grantLabel(grant string) string {
	switch grant {
	case oauth.GrantTypeDeviceCode:
		return "device_code"
	case oauth.GrantTypeCIBA:
		return "ciba"
	case oauth.GrantTypeTokenExchange:
		return "token_exchange"
	case oauth.GrantTypeJWTBearer:
		return "jwt_bearer"
	case oauth.GrantTypePreAuthorizedCode:
		return "preauthorized_code"
	case oauth.GrantTypeUMATicket:
		return "uma_ticket"
	}
	return grant // authorization_code, refresh_token, client_credentials, password
}

// handleToken implements /oauth2/token for the authorization_code grant.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// Tokens issued, by grant, counted where every grant answers. The counter
	// was declared and exported and incremented nowhere, so it read zero on a
	// server issuing thousands a second. The closure reads r as reassigned
	// below, whose form has been parsed by the time a 200 has been written.
	if s.metrics != nil {
		rec := &tokenStatus{ResponseWriter: w, code: http.StatusOK}
		w = rec
		defer func() {
			if rec.code == http.StatusOK {
				s.metrics.Tokens.Inc(grantLabel(r.PostFormValue("grant_type")))
			}
		}()
	}

	// A proof at the token endpoint accompanies no access token yet, so `ath` is
	// absent and only the key matters. Its thumbprint becomes the binding.
	if jkt, err := s.verifyDPoPForRequest(r, ""); errors.Is(err, errDPoPNonce) {
		s.offerDPoPNonce(w)
		writeError(w, http.StatusBadRequest, "use_dpop_nonce", "this server requires a nonce in the DPoP proof")
		return
	} else if err != nil {
		s.log.InfoContext(r.Context(), "DPoP proof refused at the token endpoint", "err", err,
			"correlation_id", correlationID(r.Context()))
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		writeError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
		return
	} else if jkt != "" {
		r = r.WithContext(withDPoPThumbprint(r.Context(), jkt))
	}

	// The certificate on this connection, if any. Recorded whether or not the
	// client authenticates with it: a client may use client_secret_basic and
	// still want certificate-bound tokens, which RFC 8705 §3 explicitly allows.
	if thumb := clientauth.ThumbprintFromState(r.TLS); thumb != "" {
		r = r.WithContext(withCertThumbprint(r.Context(), thumb))
	}

	ctx := r.Context()

	// Token responses must never be cached: they carry bearer credentials.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "malformed form body", Status: http.StatusBadRequest})
		return
	}

	// RFC 6749 §3.1. Same rule as the authorization endpoint, applied here
	// because this is where a duplicate `code` or `client_id` would be redeemed.
	if err := refuseDuplicateParams(r.PostForm); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: err.Error(), Status: http.StatusBadRequest})
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
	// Dispatched BEFORE the client is resolved, because OID4VCI §6.1 permits a
	// wallet to send no client_id at all. Everything below this line assumes one
	// was sent, so a conformant wallet would have been refused as invalid_client
	// before the grant it named was ever considered. The handler resolves the
	// client from the offer instead, and authenticates it there.
	if req.GrantType == oauth.GrantTypePreAuthorizedCode {
		s.handlePreAuthorizedCodeGrant(w, r, req)
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
		if err := s.authenticateConfidentialClient(ctx, r, c, req.ClientSecret); err != nil {
			s.log.InfoContext(ctx, "client authentication failed", "client_id", c.ClientID, "err", err,
				"correlation_id", correlationID(ctx))
			// An attestation failure gets §7.4's specific code, and a challenge
			// failure additionally gets a fresh challenge to retry with. Collapsing
			// everything into `invalid_client` would tell a correctly-configured
			// client only that something was wrong, when the draft defines an
			// error whose whole purpose is to say what to do next.
			if isAttestationFailure(c, err) {
				s.writeAttestationError(w, r, c, err)
				return
			}
			writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
				Description: "client authentication failed", Status: http.StatusUnauthorized})
			return
		}
	}

	if s.refuseUnboundTokenRequest(w, ctx, c) || s.refuseOutOfProfile(w, r, c) {
		return
	}

	// The client must be registered for the grant it is asking for.
	//
	// RFC 6749 §5.2 names the error for exactly this: `unauthorized_client` is
	// "The authenticated client is not authorized to use this authorization
	// grant type." OAuth 2.1 §5.2 keeps it unchanged.
	//
	// Three grants were gated individually -- authorization_code in
	// oauth.ValidateCodeRedemption, client_credentials and refresh_token below --
	// and the DEVICE grant was gated nowhere. So any registered client could run
	// a device flow, whatever it was registered for, and the default value of
	// `grant_types` does not include it. Gating each grant where it happens to be
	// handled is how one gets missed; this is the one place every grant passes
	// through.
	//
	// Token exchange is excluded deliberately: its authorisation is the dedicated
	// `may_exchange` column, checked in oauth.ValidateExchange along with the
	// audiences the client may exchange FOR, which a grant-type list cannot
	// express.
	if req.GrantType != oauth.GrantTypeTokenExchange && !c.AllowsGrantType(req.GrantType) {
		s.log.InfoContext(ctx, "client is not registered for the grant it requested",
			"client_id", c.ClientID, "grant_type", req.GrantType,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "this client is not registered for the " + req.GrantType +
				" grant", Status: http.StatusBadRequest})
		return
	}

	// The client's organisation's token budget (6.10), charged once the client
	// is known to be its: a stranger naming somebody's client id spends
	// nothing of theirs.
	if spent, err := s.tokenBudgetSpent(ctx, w, c); err != nil || spent {
		if err != nil {
			writeTokenError(w, &oauth.TokenError{Code: "temporarily_unavailable",
				Description: "please try again shortly", Status: http.StatusServiceUnavailable})
			return
		}
		writeTokenError(w, &oauth.TokenError{Code: "temporarily_unavailable",
			Description: "this organisation's token budget for the minute is spent",
			Status:      http.StatusTooManyRequests})
		return
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
		// A Transaction Token request is a token exchange with a different
		// requested_token_type. Dispatched here rather than at a second
		// endpoint, so client authentication, revocation checking and session
		// liveness are the ones that already work.
		if firstForm(r, "requested_token_type") == txntoken.TokenType {
			s.handleTxnToken(w, r, c)
			return
		}
		s.handleTokenExchange(w, r, c)
		return
	}
	if req.GrantType == oauth.GrantTypeDeviceCode {
		s.handleDeviceCodeGrant(w, r, c.ClientID)
		return
	}
	if req.GrantType == oauth.GrantTypeCIBA {
		s.handleCIBAGrant(w, r, c.ClientID)
		return
	}
	if req.GrantType == oauth.GrantTypeUMATicket {
		s.handleUMAGrant(w, r, c)
		return
	}
	if req.GrantType == oauth.GrantTypeJWTBearer {
		s.handleJWTBearerGrant(w, r, c)
		return
	}

	// The operator's token provider, asked BEFORE the transaction opens. It is
	// an HTTP call of up to its timeout, and asking it inside the transaction
	// held a pool connection and the code's row lock that long on every
	// redemption, which a slow provider turned into pool exhaustion. The code
	// is read without being consumed and the same local checks are run on it,
	// so the provider still sees only a redemption this engine would approve.
	// A code's columns never change; the transaction below confirms it is the
	// same record it consumes, and asks again inside if it is not.
	var early *store.ConsumedCode
	var hook store.TokenHookResult
	var hookErr error
	if peeked, perr := store.PeekCode(ctx, s.db, store.HashToken(req.Code)); perr == nil {
		if _, verr := oauth.ValidateCodeRedemption(req, c, &peeked.GrantRecord,
			dpopThumbprintFrom(ctx), time.Now()); verr == nil {
			early = peeked
			if peeked.OrgID != c.OrgID || c.HasTokenHook {
				hook, hookErr = store.ConsultTokenProvider(ctx, s.db, s.root, s.outboundClient, s.log,
					peeked.OrgID, tokenHookRequest(peeked, c.ClientID, req.GrantType))
			}
		}
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
			s.log.ErrorContext(ctx, "revoking after code reuse", "err", rerr)
		} else if aerr := audit.Write(ctx, tx, audit.Event{
			Type:          audit.EventCodeReused,
			ClientID:      req.ClientID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"families_revoked": n},
		}); aerr != nil {
			// The revocation still commits below if it can. Losing the audit row
			// for a theft signal is bad; failing to revoke the stolen tokens
			// because of it would be worse.
			s.log.ErrorContext(ctx, "auditing code reuse", "err", aerr)
			if err := tx.Commit(ctx); err != nil {
				s.log.ErrorContext(ctx, "committing revocation after code reuse", "err", err)
			}
		} else if err := tx.Commit(ctx); err != nil {
			s.log.ErrorContext(ctx, "committing revocation after code reuse", "err", err)
		}
		s.log.WarnContext(ctx, "authorization code reuse detected", "client_id", req.ClientID,
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

	// The thumbprint of the DPoP proof on THIS request, verified above and
	// carried in the context. RFC 9449 §10 compares it against the `dpop_jkt`
	// the authorization request bound the code to.
	if _, verr := oauth.ValidateCodeRedemption(req, c, &consumed.GrantRecord,
		dpopThumbprintFrom(ctx), time.Now()); verr != nil {
		// The code is already consumed by this point, which is correct: a failed
		// redemption must not leave a reusable code behind.
		if err := tx.Commit(ctx); err != nil {
			s.log.ErrorContext(ctx, "committing code consumption after failed validation", "err", err)
		}
		writeTokenError(w, verr)
		return
	}

	// The operator's token provider, if one is registered.
	//
	// CONSULTED HERE, after every local check has passed and before anything is
	// minted. That position is the composition rule: the provider is never
	// deciding whether to issue -- this engine has already decided to -- it is
	// deciding whether to withdraw an issuance already approved. It can turn an
	// allow into a deny and can never turn a deny into an allow, because on a
	// refused redemption it is not reached at all.
	//
	// Asked above, before the transaction, on the same record. Asked again here
	// only if what was consumed differs from what was read, which a code's
	// immutability rules out, but which would otherwise issue a token the
	// provider was never asked about. Inside the transaction, the read uses `tx`
	// and not s.db: a second connection taken while holding one deadlocks the
	// pool under concurrent redemptions (it hung the suite for eight minutes once).
	if (early == nil || !sameRedemption(early, consumed)) && (consumed.OrgID != c.OrgID || c.HasTokenHook) {
		hook, hookErr = store.ConsultTokenProvider(ctx, tx, s.root, s.outboundClient, s.log,
			consumed.OrgID, tokenHookRequest(consumed, c.ClientID, req.GrantType))
	}
	if herr := hookErr; herr != nil {
		s.log.ErrorContext(ctx, "consulting the token provider", "err", herr)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	} else if hook.Vetoed {
		// Committed before the veto is recorded on a connection of its own.
		// Recording it first held two, which with a one-connection pool waited
		// forever. The code is spent either way: a vetoed code is not retried.
		if err := tx.Commit(ctx); err != nil {
			s.log.ErrorContext(ctx, "committing code consumption after a provider veto", "err", err)
		}
		s.refuseVetoedIssuance(ctx, w, tokenHookRequest(consumed, c.ClientID, req.GrantType), hook.Reason)
		return
	}
	// What the provider contributed goes into the access token, which it did
	// not before 2.03: the claims were filtered against the allow-list and
	// then dropped.
	ctx = withHookClaims(ctx, hook.Claims)

	resp, err := s.mintTokens(ctx, tx, c, consumed)
	if err != nil {
		s.log.ErrorContext(ctx, "minting tokens", "err", err)
		writeMintError(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// tokenHookRequest is what the operator's token provider is told about a
// redemption, built one way whether it is asked before or inside the
// transaction.
func tokenHookRequest(c *store.ConsumedCode, clientID, grant string) store.TokenHookRequest {
	return store.TokenHookRequest{
		Subject: c.UserID, ClientID: clientID, Scopes: c.Scopes, Grant: grant, OrgID: c.OrgID,
	}
}

// sameRedemption reports whether the code read before the transaction is the
// one consumed inside it, in everything the token provider was told.
func sameRedemption(read, consumed *store.ConsumedCode) bool {
	return read.UserID == consumed.UserID && read.OrgID == consumed.OrgID &&
		read.ClientID == consumed.ClientID && slices.Equal(read.Scopes, consumed.Scopes)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	// RFC 9396 §7: "the AS MUST also return the authorization_details as granted
	// by the resource owner and assigned to the respective access token."
	//
	// Omitted entirely when none were granted, rather than sent as an empty
	// array: a client that never asked should not have to distinguish "you got
	// nothing" from "this server does not do that".
	AuthorizationDetails []rar.Detail `json:"authorization_details,omitempty"`

	// jti is the access token's, for a grant that records which token it
	// minted. Unexported, so it never reaches the response body.
	jti string
}

// mintSet issues the access token, ID token, and -- when offline_access was
// granted -- a refresh token, all from one authenticated subject.
//
// familyID is empty for a first issuance (an authorization code) and set when
// rotating, so a rotated token stays in its original lineage. Starting a new
// family on every refresh would make reuse detection impossible: there would be
// nothing to revoke.
func (s *Server) mintSet(ctx context.Context, tx pgx.Tx, c *clients.Client,
	orgID, userID, sid, nonce string, scopes, resources []string,
	details []rar.Detail, familyID string) (*tokenResponse, []byte, error) {

	// The DPoP thumbprint for this request, if the caller proved possession of a
	// key at the token endpoint. Carried on the context rather than as another
	// parameter because every caller of mintSet would otherwise have to thread a
	// value most of them never set -- and a parameter that is usually empty is
	// one somebody eventually forgets to pass.
	jkt := dpopThumbprintFrom(ctx)

	// Certificate binding, RFC 8705 §3. Read from the connection rather than
	// carried on the context: unlike a DPoP proof, the certificate is a property
	// of the TLS session and cannot be forged into a later request.
	//
	// Only when the client is registered for bound tokens. A client that
	// authenticates by certificate but is not ready for binding keeps getting
	// plain tokens, because flipping binding on breaks every caller that does not
	// present the certificate at the resource server -- that is a cutover, not a
	// side effect of turning on mTLS.
	certThumb := ""
	if c.TLSBoundTokens {
		certThumb = certThumbprintFrom(ctx)
	}

	// The audience, checked as it is minted: whatever accepted the resource
	// earlier, the organisation may have removed it since, or the client may
	// no longer be designated for the Admin API.
	if err := s.checkResources(ctx, tx, c, orgID, resources); err != nil {
		return nil, nil, err
	}

	alg := keys.Algorithm(c.IDTokenAlg)
	key, err := s.cfg.Keys.Active(alg)
	if err != nil {
		return nil, nil, fmt.Errorf("no active key for the client's algorithm %s: %w", alg, err)
	}
	signer := tokens.NewSigner(key)
	accessSigner := signer
	if a := keys.Algorithm(c.AccessTokenAlg()); a != alg {
		accessKey, err := s.cfg.Keys.Active(a)
		if err != nil {
			return nil, nil, fmt.Errorf("no active key for the client's access tokens, %s: %w", a, err)
		}
		accessSigner = tokens.NewSigner(accessKey)
	}

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
	// Details of a credential are what the token is for, on every token of the
	// grant, so that a refresh stays good for issuance and nothing else.
	credentials := len(rar.CredentialConfigurations(details)) > 0
	if issuanceAudienceFrom(ctx) || credentials {
		audience = []string{s.credentialAudience()}
	}

	// The actor behind this session, if an administrator started it.
	//
	// Looked up ONCE here and applied to both tokens. On the access token as
	// well as the ID token, and regardless of scope: an API call made during
	// support access is exactly the case where a resource server needs to know,
	// and a token minted without `openid` would otherwise carry no trace of it.
	//
	// And how this person signed in, for a resource server deciding whether that
	// is enough, as the ID token says it to the client. A token with no session
	// says nothing rather than something assumed.
	var act *tokens.Actor
	var authTime time.Time
	var acr string
	var amr []string
	var accessAuthTime int64
	if sid != "" {
		var impersonator *string
		if err := tx.QueryRow(ctx,
			`SELECT impersonator_id::text, auth_time, acr, amr FROM core.sessions WHERE sid = $1`, sid).
			Scan(&impersonator, &authTime, &acr, &amr); err != nil {
			return nil, nil, fmt.Errorf("loading the session behind a token: %w", err)
		}
		if impersonator != nil && *impersonator != "" {
			act = &tokens.Actor{Subject: *impersonator}
		}
		// The rung the authorization request asked for and was given, above
		// the session's own "1" or "2".
		if granted := grantedACRFrom(ctx); granted != "" {
			acr = granted
		}
		accessAuthTime = authTime.Unix()
	}

	// The refresh family is established BEFORE the access token is signed, so the
	// token can name the grant it belongs to. It used to be created further down,
	// after signing, which is why access tokens carried no grant identity and
	// revoking a refresh token could not reach them.
	if familyID == "" && containsScope(scopes, "offline_access") {
		// Details go on the FAMILY, not the token: they belong to the
		// authorization, and every rotation in the lineage inherits the same
		// grant. Storing them per-token would let two live tokens from one
		// authorization carry different permissions.
		familyDetails, derr := store.MarshalDetails(details)
		if derr != nil {
			return nil, nil, derr
		}
		familyID, err = store.NewRefreshFamily(ctx, tx, orgID, c.ClientID, userID, sid,
			familyDetails, jkt, certThumb)
		if err != nil {
			return nil, nil, err
		}
	}

	// §9: the RS is the party that has to ENFORCE these, and it never sees the
	// token response §7 sends to the client. Filtered per §9.1 so one resource
	// server does not learn what was granted for another.
	//
	// Not those of a credential, whose locations name the Credential Issuer and
	// whose audience is its endpoint: the endpoint reads them from this claim.
	var detailClaim json.RawMessage
	forAudience := rar.FilterByAudience(details, audience)
	if credentials {
		forAudience = details
	}
	if len(forAudience) > 0 {
		encoded, derr := json.Marshal(forAudience)
		if derr != nil {
			return nil, nil, fmt.Errorf("encoding authorization_details for the access token: %w", derr)
		}
		detailClaim = encoded
	}

	// Operator-defined access token claims.
	//
	// Resolved before the token is assembled so a failure refuses the mint
	// rather than issuing one silently missing what an operator configured.
	// A separate destination from the ID token's, because an access token
	// travels to resource servers the user never saw a consent screen for --
	// so releasing something there is a wider decision, and the mapper has to
	// say so explicitly.
	var accessExtra map[string]any
	if s.root != nil && userID != "" && c.HasClaimMappers {
		mapped, merr := store.MappedClaims(ctx, tx, userID, orgID, c.ClientID,
			store.ClaimInAccessToken, joinScopes(scopes), s.root)
		if merr != nil {
			return nil, nil, fmt.Errorf("resolving mapped access token claims: %w", merr)
		}
		accessExtra = mapped
	}
	if accessExtra, err = withRoles(ctx, tx, c, userID, orgID, accessExtra); err != nil {
		return nil, nil, err
	}

	at, err := issueAccessToken(ctx, tx, c, accessSigner, tokens.AccessTokenClaims{
		Issuer:    issuer,
		Subject:   userID,
		Audience:  audience,
		Expiry:    now.Add(c.AccessTokenTTL()).Unix(),
		IssuedAt:  now.Unix(),
		JTI:       jti,
		ClientID:  c.ClientID,
		Scope:     joinScopes(scopes),
		SessionID: sid,
		ACR:       acr,
		AuthTime:  accessAuthTime,
		Act:       act,
		Cnf:       bindingFor(jkt, certThumb),

		AuthorizationDetails: detailClaim,
		GrantID:              familyID,
		Extra:                accessExtra,
	})
	if err != nil {
		return nil, nil, err
	}
	atHash, err := tokens.AtHash(alg, at)
	if err != nil {
		return nil, nil, err
	}

	resp := &tokenResponse{
		AccessToken: at,
		// "DPoP", not "Bearer", when the token is sender-constrained (RFC 9449
		// §5). Not cosmetic: a client told "Bearer" sends no proof, and every
		// request it makes is then refused.
		TokenType: bearerOrDPoP(jkt),
		ExpiresIn: int(c.AccessTokenTTL().Seconds()),
		Scope:     joinScopes(scopes),
		jti:       jti,
	}

	// An ID token is an authentication statement, so it is only minted where
	// openid was granted -- a pure refresh of an API token should not re-assert
	// who the user is.
	if containsScope(scopes, "openid") {
		if sid == "" {
			return nil, nil, fmt.Errorf("loading session context: %w", pgx.ErrNoRows)
		}
		subject, err := subjectFor(ctx, tx, c, userID)
		if err != nil {
			return nil, nil, err
		}
		actor, err := actorFor(ctx, tx, c, act)
		if err != nil {
			return nil, nil, err
		}
		claims := tokens.IDTokenClaims{
			Issuer:          issuer,
			Subject:         subject,
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
			Actor:           actor,
		}
		if err := s.addProfileClaims(ctx, tx, &claims, userID, scopes); err != nil {
			return nil, nil, err
		}

		// Operator-defined claims, resolved LAST so the fixed set above is
		// already in place.
		//
		// IDTokenClaims.MarshalJSON refuses to let one overwrite a field the
		// struct produced, so this cannot replace `sub`, `acr`, `email` or
		// anything else — a mapper can only ever add. That is enforced at three
		// layers on purpose (schema, resolution, serialisation), and this is the
		// call site that makes the feature reachable at all.
		if s.root != nil && userID != "" && c.HasClaimMappers {
			mapped, merr := store.MappedClaims(ctx, tx, userID, orgID, c.ClientID,
				store.ClaimInIDToken, joinScopes(scopes), s.root)
			if merr != nil {
				// Refused rather than issued without them. An operator who
				// mapped a claim is relying on it reaching the relying party,
				// and a token silently missing it is the failure this whole
				// wiring exists to fix.
				return nil, nil, fmt.Errorf("resolving mapped ID token claims: %w", merr)
			}
			claims.Extra = mapped
		}

		if claims.Extra, err = withRoles(ctx, tx, c, userID, orgID, claims.Extra); err != nil {
			return nil, nil, err
		}
		idt, err := signer.SignIDToken(claims)
		if err != nil {
			return nil, nil, err
		}
		if resp.IDToken, err = sealIDToken(c, idt); err != nil {
			return nil, nil, err
		}
	}

	if !containsScope(scopes, "offline_access") || refreshKeptFrom(ctx) {
		return resp, nil, nil
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
	// §7: returned "as granted by the resource owner" -- read back from the code,
	// never from a parameter the client resends at the token endpoint. A client
	// that could resend them is a client that could change them.
	granted, derr := store.UnmarshalDetails(g.Details)
	if derr != nil {
		return nil, derr
	}
	resp, _, err := s.mintSet(withGrantedACR(ctx, g.ACR), tx, c, g.OrgID, g.UserID, g.SessionID, g.Nonce,
		g.Scopes, g.Resources, granted, "")
	if err != nil {
		return resp, err
	}
	resp.AuthorizationDetails = rar.WithCredentialIdentifiers(granted)
	return resp, nil
}

// mintFromGrant issues from a rotated refresh grant.
//
// scopes is what the new tokens carry: the grant's own, or a narrower set the
// client asked for. The caller has already established it is a subset -- this
// function must never be the place that decides, because it is also called
// where there is nothing to compare against.
func (s *Server) mintFromGrant(ctx context.Context, tx pgx.Tx, c *clients.Client,
	g *store.RefreshGrant, scopes []string) (*tokenResponse, []byte, error) {
	// No nonce on refresh: the claim belongs to the original authorization
	// request, and re-emitting a stale one would assert a binding that no longer
	// corresponds to any live client request.
	//
	// The granted details come from the FAMILY and are re-applied on every
	// rotation. Dropping them here was the defect this file used to have: the
	// first access token carried the constraint and every refreshed one did not,
	// so a permission narrowed at authorization silently widened back to plain
	// `scope` at the first refresh -- and nothing failed, which is why it
	// survived. Migration 0080 had already added the column for exactly this
	// reason; no code had ever written or read it.
	granted, derr := store.UnmarshalDetails(g.Details)
	if derr != nil {
		return nil, nil, derr
	}
	if len(scopes) == 0 {
		scopes = g.Scopes
	}
	resp, rtHash, err := s.mintSet(ctx, tx, c, g.OrgID, g.UserID, g.SessionID, "",
		scopes, g.Resources, granted, g.FamilyID)
	if err != nil {
		return resp, rtHash, err
	}
	resp.AuthorizationDetails = rar.WithCredentialIdentifiers(granted)
	return resp, rtHash, nil
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
	wantGroups := containsScope(scopes, "groups")
	if !wantEmail && !wantProfile && !wantGroups {
		return nil
	}

	var email, username, name, given, family string
	var verified bool
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(email,''), COALESCE(username,''), email_verified_at IS NOT NULL,
		       COALESCE(display_name,''), COALESCE(given_name,''), COALESCE(surname,'')
		FROM core.users WHERE id = $1 AND status = 'active'`, userID).
		Scan(&email, &username, &verified, &name, &given, &family); err != nil {
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
		// The names an account holds, each only when it holds one. They were
		// never released: this said no display name was stored anywhere, which
		// stopped being true when migration 0105 added them, so relying parties
		// greeted everybody by their username.
		claims.Name, claims.GivenName, claims.FamilyName = name, given, family
	}
	if wantGroups {
		// TWO gates, not one: the scope must be granted AND the client must be
		// released groups. The scope is asked for by the client; the release is
		// decided by the operator. A client that asks for `groups` and was never
		// released them gets nothing, silently -- which is the correct outcome,
		// because the alternative is that any client can learn the shape of the
		// organisation by adding a word to its scope parameter.
		//
		// Read HERE, at issuance, never from the session: a session established
		// this morning must not still mint tokens claiming a group somebody was
		// removed from at lunchtime.
		// The audience IS the client id for an ID token, which is what the
		// release policy is keyed on.
		// In the minting transaction, never the pool: see store.GroupsForUser.
		groups, err := store.GroupsForUser(ctx, tx, userID, claims.Audience)
		if err != nil {
			return fmt.Errorf("loading group membership for %s: %w", userID, err)
		}
		claims.Groups = groups
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
	// RFC 8707, as every other grant: the resources asked for are the audience, each
	// registered, or the Admin API's alone for a client the deployment designated
	// (6.01). Unread here until 0.27, so a service asking for the billing API got a
	// token audienced to itself and valid wherever that was accepted.
	audience := []string{c.ClientID}
	if len(req.Resources) > 0 {
		if err := s.checkResources(r.Context(), s.db, c, c.OrgID, req.Resources); err != nil {
			writeMintError(w, err)
			return
		}
		audience = req.Resources
	}
	// The subject is the client itself.
	hookCtx, ok := s.consultTokenHook(r.Context(), w, c, store.TokenHookRequest{
		Subject: c.ClientID, ClientID: c.ClientID, Scopes: scopes, Grant: req.GrantType, OrgID: c.OrgID})
	if !ok {
		return
	}

	alg := keys.Algorithm(c.AccessTokenAlg())
	key, err := s.cfg.Keys.Active(alg)
	if err != nil {
		s.log.ErrorContext(r.Context(), "no active key for client_credentials", "alg", alg, "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	jti, err := newSID()
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	now := time.Now()
	// Certificate binding on THIS path too, RFC 8705 §3.
	//
	// This is the path a mutual-TLS service client actually uses, and it minted
	// unbound tokens while the authorization-code path bound them -- the exact
	// half-implementation the migration for this feature warns about: a client
	// authenticates with a certificate and receives a token as stealable as any
	// other.
	certThumb := ""
	if c.TLSBoundTokens {
		certThumb = certThumbprintFrom(r.Context())
	}

	// Named once and reused, because the binding and the announcement of the
	// binding must agree. They did not: the token below carried `cnf.jkt` while
	// the response said `token_type: Bearer`, so a DPoP client was handed a
	// sender-constrained token and told it was an ordinary bearer one. It would
	// then send `Authorization: Bearer ...` with no proof, and every resource
	// request would be refused -- the token unusable from the moment it was
	// issued.
	//
	// RFC 9449 §5: "A token_type of DPoP MUST be included in the access token
	// response to signal to the client that the access token was bound to its
	// DPoP key". bearerOrDPoP three functions above already spelled out the
	// consequence; this path simply never called it.
	ccJKT := dpopThumbprintFrom(r.Context())

	at, err := issueAccessToken(hookCtx, s.db, c, tokens.NewSigner(key), tokens.AccessTokenClaims{
		Issuer:   s.issuerFor(c),
		Subject:  c.ClientID,
		Audience: audience,
		Expiry:   now.Add(c.AccessTokenTTL()).Unix(),
		IssuedAt: now.Unix(),
		JTI:      jti,
		Cnf:      bindingFor(ccJKT, certThumb),
		ClientID: c.ClientID,
		Scope:    joinScopes(scopes),
		// No SessionID: nothing to tie this to, and inventing one would make
		// logout appear to cover a token it cannot.
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "signing client_credentials token", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	writeJSON(w, http.StatusOK, &tokenResponse{
		AccessToken: at,
		TokenType:   bearerOrDPoP(ccJKT),
		ExpiresIn:   int(c.AccessTokenTTL().Seconds()),
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

	oldHash := store.HashToken(req.RefreshToken)

	// The operator's token provider, about a refresh this engine would grant,
	// read without spending the token and asked before the transaction holds a
	// connection. A veto refused the authorization code and was then ignored
	// by every refresh after it (2.03); now it is refused here, and the token
	// is not rotated, so a provider that relents later is not met by a spent one.
	if peek, perr := store.LookupRefreshToken(ctx, s.db, oldHash); perr == nil &&
		peek.Active && peek.ClientID == c.ClientID {
		scopes := peek.Scopes
		if req.Scope != "" {
			scopes = splitScopes(req.Scope)
		}
		hookCtx, ok := s.consultTokenHook(ctx, w, c, store.TokenHookRequest{
			Subject: peek.UserID, ClientID: c.ClientID, Scopes: scopes,
			Grant: "refresh_token", OrgID: peek.OrgID})
		if !ok {
			return
		}
		ctx = hookCtx
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// FAPI 2.0 §5.3.2.1: "shall not use refresh token rotation except in
	// extraordinary circumstances". The token stays good and the answer carries no
	// new one, so an answer lost on the way back costs the client nothing.
	var grant *store.RefreshGrant
	var rerr error
	kept := c.FAPI2()
	if kept {
		ctx = withRefreshKept(ctx)
		grant, rerr = store.ReadRefreshGrant(ctx, tx, oldHash)
	} else {
		grant, rerr = store.RotateRefreshToken(ctx, tx, oldHash)
	}

	// A client that opted in gets one retry at the same answer, for an answer lost
	// on the way back. Everything below still holds: this replaces the rotation and
	// nothing else.
	var retried []byte
	if errors.Is(rerr, store.ErrRefreshReused) && c.RefreshReuseGrace > 0 {
		if g, sealed, gerr := store.RefreshRetry(ctx, tx, oldHash,
			time.Duration(c.RefreshReuseGrace)*time.Second); gerr == nil {
			grant, rerr, retried = g, nil, sealed
		} else if !errors.Is(gerr, store.ErrRefreshReused) {
			s.log.ErrorContext(ctx, "retrying a refresh", "err", gerr)
		}
	}

	if errors.Is(rerr, store.ErrRefreshReused) {
		holderOrg, holder, herr := store.RefreshTokenHolder(ctx, tx, oldHash)
		if herr != nil {
			s.log.ErrorContext(ctx, "reading the holder of a reused refresh token", "err", herr)
		}
		n, revErr := store.RevokeFamilyByToken(ctx, tx, oldHash, "reuse_detected")
		committed := false
		if revErr != nil {
			s.log.ErrorContext(ctx, "revoking family after refresh reuse", "err", revErr)
		} else if err := tx.Commit(ctx); err != nil {
			s.log.ErrorContext(ctx, "committing revocation after refresh reuse", "err", err)
		} else {
			committed = true
		}
		s.log.WarnContext(ctx, "refresh token reuse detected -- family revoked",
			"client_id", c.ClientID, "families_revoked", n)
		// The theft signal, recorded and published. Only the log said so before
		// 2.52. After the revocation commits, so that the revocation never
		// depends on the record of it.
		if committed {
			s.auditDetached(ctx, audit.Event{Type: audit.EventRefreshReused, OrgID: holderOrg,
				SubjectID: holder, ClientID: c.ClientID, CorrelationID: correlationID(ctx),
				Detail: map[string]any{"families_revoked": n}})
		}
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

	// An application refreshing is a use of the session it holds the token
	// under, as a browser presenting the cookie is: somebody working in the
	// application is not idle. In this transaction, so a refresh refused below
	// moves nothing.
	if err := store.TouchSession(ctx, tx, grant.SessionID); err != nil {
		s.log.ErrorContext(ctx, "recording a refresh as a use of its session", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	// The client's floor (clientacr.go), against the session the lineage was
	// authorized from, so raising it reaches the refresh tokens already issued.
	// Refused, not revoked: the token is not spent, and signing in again with a
	// second factor starts a lineage that meets it. A session that cannot be
	// read meets no floor (sessionFactors).
	if oauth.RequiredRung("", c.MinimumACR) >= 2 {
		if _, amr := sessionFactors(ctx, tx, grant.SessionID); !meetsClientFloor(c, amr) {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "this application requires a stronger sign-in than the one this " +
					"refresh token came from; sign in again",
				Status: http.StatusBadRequest})
			return
		}
	}

	// RFC 9449 §5, the sentence that is easy to skip: "The binding MUST be
	// validated when the refresh token is later presented to get new access
	// tokens."
	//
	// handleToken already verified the proof itself -- that it is well formed,
	// unexpired, unreplayed, and signed by the key it names. That is a check on
	// the PROOF. This is the check on the BINDING, and without it the proof
	// proves only that the presenter holds some key, which every attacker does.
	// A stolen refresh token would mint fresh access tokens bound to the thief.
	//
	// Public clients only, per §5's closing paragraph: refresh tokens issued to
	// confidential clients "are not bound to the DPoP proof public key because
	// they are already sender-constrained" by client authentication -- and the
	// RFC prefers that mechanism because it survives credential rotation. Binding
	// them here as well would be stricter than the specification and would break
	// exactly the flexibility it calls out.
	if grant.DPoPJKT != "" && c.Type != "confidential" {
		presented := dpopThumbprintFrom(ctx)
		if presented == "" {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_dpop_proof",
				Description: "this refresh token is bound to a DPoP key and must be " +
					"presented with a proof of possession for that key",
				Status: http.StatusBadRequest})
			return
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(grant.DPoPJKT)) != 1 {
			// Logged, because this is what a replayed refresh token looks like:
			// a valid proof of the wrong key.
			s.log.WarnContext(ctx, "refresh token presented with a DPoP key it is not bound to",
				"client_id", c.ClientID, "correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_dpop_proof",
				Description: "the DPoP proof is for a different key than the one " +
					"this refresh token is bound to",
				Status: http.StatusBadRequest})
			return
		}
	}

	// RFC 8705 §4, the mutual-TLS twin of the check above. §7.1 exempts
	// confidential clients for the same reason §5 of RFC 9449 does: a client
	// using `tls_client_auth` is already "indirectly certificate-bound by way of
	// the client ID and the associated requirement for ... authentication".
	if grant.CertThumbprint != "" && c.Type != "confidential" {
		presented := certThumbprintFrom(ctx)
		if presented == "" {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "this refresh token is bound to a client certificate " +
					"and must be presented over a mutually authenticated connection " +
					"using that certificate",
				Status: http.StatusBadRequest})
			return
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(grant.CertThumbprint)) != 1 {
			s.log.WarnContext(ctx, "refresh token presented with a certificate it is not bound to",
				"client_id", c.ClientID, "correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "the client certificate on this connection is not the " +
					"one this refresh token is bound to",
				Status: http.StatusBadRequest})
			return
		}
	}

	scopes := grant.Scopes
	if req.Scope != "" {
		requested := splitScopes(req.Scope)
		granted := map[string]bool{}
		for _, sc := range grant.Scopes {
			granted[sc] = true
		}
		for _, sc := range requested {
			if !granted[sc] {
				writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
					Description: "scope " + sc + " was not granted to this refresh " +
						"token; a refresh may narrow what was granted, never widen it",
					Status: http.StatusBadRequest})
				return
			}
		}
		// Narrowing away offline_access would end the refresh chain, because a
		// grant without it gets no successor token. Refused rather than obeyed:
		// some client libraries send a fixed `scope` on every refresh out of
		// habit, and silently consuming their last refresh token is a session
		// that dies for a reason nobody can find. Loud beats convenient.
		if containsScope(grant.Scopes, "offline_access") &&
			!containsScope(requested, "offline_access") {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
				Description: "this refresh token was granted offline_access and the " +
					"requested scope omits it, which would end the refresh chain; " +
					"include offline_access, or stop refreshing",
				Status: http.StatusBadRequest})
			return
		}
		scopes = requested
	}

	// The access policy, again, at every refresh. A person removed from the
	// group a rule demands, or a client a new deny rule names, used to keep
	// receiving tokens for as long as the lineage lived -- the policy was asked
	// once, at the authorization endpoint, and never after. Decided as
	// policy.Request.Refresh describes: who the person is and what their session
	// proved, not where the application's server is calling from. Not revoked on
	// refusal: the next refresh asks again, so restoring the membership restores
	// the grant.
	//
	// A lineage from another organisation's session is refused outright. The
	// authorization endpoint once issued codes across organisations, and a
	// family it left behind would otherwise be asked about by the session's
	// organisation's policy, not this client's.
	if grant.OrgID != c.OrgID {
		_ = tx.Rollback(ctx)
		s.log.WarnContext(ctx, "refused a refresh for a grant from another organisation",
			"client_id", c.ClientID, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "this grant does not belong to this client's organisation",
			Status:      http.StatusBadRequest})
		return
	}
	if c.HasAccessPolicy {
		mfa, amr := sessionFactors(ctx, tx, grant.SessionID)
		if pd := s.checkAccessPolicyIn(ctx, tx, nil, grant.OrgID, c.ClientID, grant.UserID,
			strings.Join(scopes, " "), mfa, amr); pd != nil {
			// Released before the refusal is recorded on a connection of its own;
			// nothing here is committed on a refusal anyway.
			_ = tx.Rollback(ctx)
			s.auditDetached(ctx, audit.Event{
				Type: audit.EventLoginFailed, OrgID: grant.OrgID, SubjectID: grant.UserID,
				ClientID: c.ClientID, CorrelationID: correlationID(ctx),
				Detail: map[string]any{"reason": "access_policy", "rule": pd.Rule, "via": "refresh"},
			})
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "the access policy no longer allows this grant: " + pd.Message,
				Status:      http.StatusBadRequest})
			return
		}
	}

	resp, newHash, err := s.mintFromGrant(ctx, tx, c, grant, scopes)
	if err != nil {
		s.log.ErrorContext(ctx, "minting from refresh", "err", err)
		writeMintError(w, err)
		return
	}
	if retried != nil {
		// The token this answer should have carried, and not a second line of
		// descent: a retry leaves one live token, as a rotation does.
		successor, oerr := store.OpenSuccessor(req.RefreshToken, retried)
		if oerr == nil {
			oerr = store.DiscardRefreshToken(ctx, tx, newHash)
		}
		if oerr == nil {
			oerr = audit.Write(ctx, tx, audit.Event{Type: audit.EventRefreshRetried, OrgID: grant.OrgID,
				SubjectID: grant.UserID, ClientID: c.ClientID, CorrelationID: correlationID(ctx)})
		}
		if oerr != nil {
			s.log.ErrorContext(ctx, "answering a retried refresh", "err", oerr)
			writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
			return
		}
		resp.RefreshToken = successor
	} else if !kept {
		var sealed []byte
		if c.RefreshReuseGrace > 0 && resp.RefreshToken != "" {
			var serr error
			if sealed, serr = store.SealSuccessor(req.RefreshToken, resp.RefreshToken); serr != nil {
				// A retry is a kindness. Without it the rotation is still sound.
				s.log.ErrorContext(ctx, "sealing a successor", "err", serr)
			}
		}
		if err := store.LinkSuccessor(ctx, tx, oldHash, newHash, sealed); err != nil {
			s.log.ErrorContext(ctx, "linking successor", "err", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleLoginPost verifies credentials and creates a session.
func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(withFlowAnswerMemo(r.Context()))
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	authzQuery := r.PostForm.Get("authz")
	identifier := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	// The single sign-on button (8.20): before any credential is looked up, since
	// none was offered. An address no provider signs in is told so.
	if r.PostForm.Get("sso") != "" {
		if !s.routeByAddress(w, r, s.loginOrg(ctx, authzQuery), identifier, authzQuery) {
			s.renderLogin(w, r, authzQuery, "Single sign-on is not set up for that address.")
		}
		return
	}

	// The challenge is checked BEFORE the credential lookup, so a solved
	// challenge is a precondition for spending an Argon2 evaluation rather than
	// a second opinion afterwards.
	//
	// A failure here counts as a login failure too. Otherwise an attacker could
	// hold the address's counter still by submitting a blank challenge forever,
	// and adaptive mode would never escalate.
	if s.captcha.Required(ctx, r.RemoteAddr) {
		if cerr := s.captcha.Verify(ctx, s.captchaResponse(r), r.RemoteAddr); cerr != nil {
			s.captcha.RecordFailure(ctx, r.RemoteAddr)
			s.recordSignInFailure(ctx, r)
			s.log.InfoContext(ctx, "captcha refused", "err", cerr,
				"correlation_id", correlationID(ctx))
			s.renderLogin(w, r, authzQuery,
				"That challenge was not completed. Please try again.")
			return
		}
	}

	// Whose sign-in page this is: the parked request's client, or the only
	// organisation. Empty on a bare page of a deployment with several.
	pageOrg := s.loginOrg(ctx, authzQuery)
	cred, ok, ambiguous, err := s.lookupCredential(ctx, identifier, pageOrg)
	if err != nil {
		s.log.ErrorContext(ctx, "looking up credential", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return
	}
	userID, orgID, stored := cred.userID, cred.orgID, cred.hash

	// The organisation's sign-in budget (6.10), before any password is
	// hashed: the page's organisation, or the account's on a bare page. An
	// address nobody has, on a bare page, names none and spends nothing.
	if budgetOrg := pageOrg; budgetOrg != "" || orgID != "" {
		if budgetOrg == "" {
			budgetOrg = orgID
		}
		if spent, berr := s.orgBudgetSpent(ctx, w, budgetOrg, store.BudgetSignIns); berr != nil || spent {
			if berr != nil {
				s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
				return
			}
			s.renderLoginStatus(w, r, authzQuery,
				"Too many sign-ins here right now. Please try again in a minute.", http.StatusTooManyRequests)
			return
		}
	}

	// One generic message for every failure -- unknown user, wrong password,
	// deactivated account. Distinguishing them is a user-enumeration oracle.
	generic := "Incorrect username or password."
	if pageOrg == "" {
		// A bare page on a deployment with several organisations says so on
		// every failure, not only an ambiguous one: saying it only then would
		// tell anybody typing an address that it is held in more than one.
		generic += " If you belong to more than one organisation, start from the " +
			"application you want to sign in to."
	}

	if ambiguous {
		// Same cost and the same answer as a wrong password.
		_, _ = s.hasher.Verify(ctx, dummyHash, password)
		s.auditDetached(ctx, audit.Event{
			Type:          audit.EventLoginFailed,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "identifier_in_several_organisations"},
		})
		s.captcha.RecordFailure(ctx, r.RemoteAddr)
		s.recordSignInFailure(ctx, r)
		s.renderLogin(w, r, authzQuery, generic)
		return
	}

	if !ok {
		// No local credential. Before treating this as "no such user", check
		// whether it is a user we imported whose password still lives at the
		// provider being migrated away from. Those two cases look identical at
		// this form and must be handled completely differently.
		if done := s.tryDelegated(w, r, pageOrg, identifier, password, authzQuery); done {
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
		// Counted like any other failure. Counting only real accounts would make
		// the appearance of a challenge an oracle for which usernames exist.
		s.captcha.RecordFailure(ctx, r.RemoteAddr)
		s.recordSignInFailure(ctx, r)
		s.renderLogin(w, r, authzQuery, generic)
		return
	}

	// Checked BEFORE spending an Argon2 evaluation. Verifying first would make
	// the throttle an amplifier: every rejected attempt would still cost the
	// server 19MB and a CPU burst, which is what the limiter exists to prevent.
	throttle, terr := store.ReserveLoginAttempt(ctx, s.db, userID)
	if terr != nil {
		// Refused, for the reason allowSignInAttempt gives: nothing was going to
		// work against a database that cannot answer this, and going on would be
		// a guess nobody counted.
		s.log.ErrorContext(ctx, "spending a guess at an account", "err", terr)
		s.renderLogin(w, r, authzQuery, generic)
		return
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
		s.captcha.RecordFailure(ctx, r.RemoteAddr)
		s.recordSignInFailure(ctx, r)
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
	// A correct password clears the address's pressure: the next person on that
	// office NAT should not inherit a challenge from somebody who mistyped.
	s.captcha.Clear(ctx, r.RemoteAddr)
	if err := store.ClearLoginThrottle(ctx, s.db, userID); err != nil {
		s.log.ErrorContext(ctx, "clearing login throttle", "err", err)
	}

	// Lazy rehash, before either branch: a successful password check upgrades a
	// foreign or below-policy hash whether or not a second factor follows.
	if needsRehash {
		if fresh, herr := s.hasher.Hash(ctx, password); herr == nil {
			if _, err := s.db.Exec(ctx, `
				UPDATE core.password_credentials
				SET hash = $2, algorithm = 'argon2id', is_current = true, updated_at = now()
				WHERE user_id = $1`, userID, fresh); err != nil {
				s.log.ErrorContext(ctx, "rehashing password", "err", err)
			}
			// A user imported by password hash has now finished migrating: the
			// foreign hash is gone and their credential is ours. Recording that
			// here is what makes a cutover dashboard truthful -- CompleteMigration
			// only runs on the DELEGATED path, so without this every
			// hash-imported user stayed 'pending' forever however many times they
			// signed in, and "% migrated" would read zero on a finished migration.
			//
			// migration_source_id stays NULL, accurately: there was no delegated
			// source, the hash came across in an export.
			if _, err := s.db.Exec(ctx, `
				UPDATE core.users
				SET migration_state = 'complete', migrated_at = now()
				WHERE id = $1 AND migration_state = 'pending'`, userID); err != nil {
				s.log.ErrorContext(ctx, "marking a hash-imported user migrated", "err", err)
			}
		}
	}

	// Re-check the corpus, at most once per interval per credential.
	//
	// This is the only moment the plaintext exists to check. Every comparable
	// implementation checks a password once, when it is chosen, and never again
	// -- so a password that was clean the day it was set stays "clean" forever,
	// however many corpora it turns up in afterwards. The control expires
	// silently on day two.
	//
	// Bounded so a third party is not on the critical path of every login, and
	// done AFTER the password has been verified so an attacker cannot use this
	// endpoint to ask whether an arbitrary string is breached.
	//
	// A hit flags rather than refuses: the person is at a login box with a
	// password that works, and the useful outcome is that they leave with a
	// different one, not that they are turned away with nowhere to go.
	if s.pwPolicy.Breach != nil && s.pwPolicy.RecheckEvery > 0 {
		if due, derr := store.BreachCheckDue(ctx, s.db, userID,
			s.pwPolicy.RecheckEvery); derr == nil && due {
			bad, berr := s.pwPolicy.Breach.Breached(ctx, password)
			// Stamped whatever the verdict, INCLUDING when the corpus was
			// unreachable -- otherwise an outage becomes a retry on every
			// sign-in by every user, and their bad hour becomes ours.
			if err := store.RecordBreachCheck(ctx, s.db, userID); err != nil {
				s.log.ErrorContext(ctx, "recording a breach check", "err", err)
			}
			if berr == nil && bad {
				// A KEY, not a sentence. The reason is written now and read on a
				// page rendered later, possibly in another language -- a sentence
				// stored here is frozen in whatever language the server was
				// speaking when the flag was set. See renderChangeReason.
				if ferr := store.RequirePasswordChange(ctx, s.db, userID,
					"reason.breached"); ferr != nil {
					s.log.ErrorContext(ctx, "flagging a breached password", "err", ferr)
				}
				s.auditDetached(ctx, audit.Event{
					Type: "password.breached", OrgID: orgID, SubjectID: userID,
					CorrelationID: correlationID(ctx),
				})
			}
		}
	}

	// A correct password does NOT create a session when a second factor is
	// enrolled. It creates a pending authentication that can do nothing but
	// present a code -- otherwise a stolen password alone has already produced
	// something usable, which is the whole thing MFA exists to prevent.
	// Which is now the flow's decision rather than a hardcoded `if enrolled`.
	// The built-in flow writes `when: user_has_second_factor`, so a deployment
	// that has not written a flow file gets exactly this behaviour.
	demanded, enrolled := s.FlowDemandsMFA(ctx, s.db, orgID, userID, authzQuery,
		[]string{oauth.AMRPassword})
	// A remembered device, where no client requires more: the walk passes the
	// mfa stage for the same reason (rememberdevice.go), so it is not begun.
	if demanded && s.deviceSkipsMFA(ctx, r, orgID, userID, authzQuery) {
		demanded = false
	}
	// Nothing enrolled, and the flow enrols a factor: the walk does that, and
	// refuses there if its mfa stage comes first. Refusing here would turn
	// away exactly the people an enrol_mfa stage was written for.
	if demanded && !enrolled && s.flowEnrols(ctx, orgID, userID, authzQuery) {
		demanded = false
	}
	if demanded && !enrolled {
		// The flow requires a second factor of everybody and this account has
		// none. Refused rather than waved through: silently skipping would mean
		// the requirement holds for every account except the ones it was written
		// to catch.
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "mfa_required_but_not_enrolled"},
		})
		s.renderLogin(w, r, authzQuery,
			"This account needs a second factor before it can be used to sign in. "+
				"Please contact your administrator.")
		return
	}
	failedOpen := false
	if demanded {
		if !s.beginMFAChallenge(w, r, userID, orgID, authzQuery, []string{oauth.AMRPassword}) {
			return
		}
		// Duo is unreachable, the deployment fails open, and this person has
		// nothing else to present: the sign-in carries on, on a password alone.
		failedOpen = true
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if failedOpen {
		s.recordDuoFailOpen(ctx, tx, orgID, userID)
		// So the walk completeSignIn starts does not reach the mfa stage, find
		// a password-only amr, and ask Duo again.
		r = withMFAWaivedByFailOpen(r)
	}
	s.completeSignIn(w, r, tx, userID, orgID, []string{oauth.AMRPassword}, authzQuery)
}

// authorizeParams reads an authorization request's parameters from wherever the
// method puts them.
//
// OIDC Core 3.1.2.1 makes BOTH methods mandatory: "The Authorization Server MUST
// support the use of the HTTP GET and POST methods". This endpoint accepted GET
// alone until this existed, which is a plain non-conformance -- and it also
// denied clients the reason POST is there at all. Parameters in a query string
// end up in access logs, in `Referer`, and in browser history; a request object
// or a long `claims` parameter can also exceed what a URL comfortably carries.
//
// A POST that ALSO carries a query string is refused rather than merged.
// `r.Form` would merge both, and a request naming `redirect_uri` once in the URL
// and once in the body is the same ambiguity refuseDuplicateParams exists to
// reject: the decision and the record of the decision must describe the same
// request. Merging would additionally let a parameter smuggled into the URL win
// against the body a client signed.
func authorizeParams(r *http.Request) (url.Values, error) {
	if r.Method != http.MethodPost {
		return r.URL.Query(), nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("the request body could not be parsed as " +
			"application/x-www-form-urlencoded")
	}
	if r.URL.RawQuery != "" {
		return nil, fmt.Errorf("an authorization request sent as POST must carry " +
			"its parameters in the body alone, not split across the body and the URL")
	}
	return r.PostForm, nil
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

	// Only an active account is signed in, decided here for every way in
	// rather than by each lookup remembering. A provider's sign-in found its
	// account by the link alone and came here for a deactivated one, which
	// wrote a session and a login.succeeded that the per-request check then
	// treated as nobody (ADR-007). A self-sign-up waiting for approval (5.19)
	// has proved its own credential, so it is told why. An account of a
	// suspended organisation is refused the same way (6.09), recorded as such.
	// And an account of another instance (6.12), which no way in should have
	// found here; this is where one that did is stopped.
	var status, locale string
	if err := tx.QueryRow(ctx, `
		SELECT CASE WHEN NOT `+store.InInstance("u.org_id", "$2")+` THEN 'other_instance'
		            WHEN `+store.OrgInService("u.org_id")+` THEN u.status ELSE 'org_suspended' END,
		       COALESCE(u.locale, '')
		  FROM core.users u WHERE u.id = $1::uuid`,
		userID, s.instanceID).Scan(&status, &locale); err != nil {
		s.log.ErrorContext(ctx, "reading the account's status at sign-in", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if status != "active" {
		_ = tx.Rollback(ctx)
		s.clearPending(w)
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx), Detail: map[string]any{"reason": "account_" + status},
		})
		msg := "You cannot sign in at the moment. Please contact your administrator."
		if status == "pending" {
			msg = s.tr(r).Text("login.pending")
		}
		s.renderLogin(w, r, authzQuery, msg)
		return
	}

	// Prompts, before the session exists.
	//
	// The check lives HERE rather than at each of the eight places that sign
	// somebody in, so a new authentication method cannot forget it. A terms
	// prompt that covers five routes out of six is a notice nobody agreed to on
	// the sixth, and that is discovered by a lawyer rather than a test.
	//
	// The transaction is abandoned rather than committed: the person is
	// authenticated but does not have a session yet, and will not until they
	// answer.
	//
	// Read through TX, not the pool. When this is re-entered after an answer,
	// that answer is written in this same transaction and not yet committed --
	// the pool cannot see it, so the prompt would come back, be answered again,
	// and come back again. An infinite loop that locks out every user, appearing
	// only once a prompt exists.
	// Which of these run, and in what order, is now the flow file's decision --
	// but the shape is unchanged, and so is the reason it works. Each stage
	// records its completion in the database the conditions are read from, so
	// re-entering here after one is answered walks past it and stops at the next.
	// See internal/httpapi/flowdrive.go.
	//
	// The reads still go through TX, not the pool. Same trap as before: an answer
	// written in this transaction and not yet committed is invisible to the pool,
	// so the prompt would come back, be answered again, and come back again --
	// an infinite loop that locks out every user, appearing only once a prompt
	// exists.
	switch s.advanceSignIn(w, r, tx, userID, orgID, amr, authzQuery) {
	case decisionHandled:
		// A stage took over the response. The transaction is abandoned rather
		// than committed: the person is authenticated but does not have a session
		// yet, and will not until they answer.
		return
	case decisionDeny:
		// The half-authenticated cookie is cleared, not left to expire. Every
		// path that could spend it funnels back through here and would be denied
		// again, so this is not closing a hole -- it is not leaving a live
		// credential in a browser we have just refused.
		//
		// The walk released the transaction on a denial; said again here, where
		// the refusal is rendered, so the order cannot drift.
		_ = tx.Rollback(ctx)
		s.clearPending(w)
		s.renderLogin(w, r, authzQuery,
			"You cannot sign in at the moment. Please contact your administrator.")
		return
	case decisionDone:
		// The flow finished deliberately without issuing a session.
		if err := tx.Commit(ctx); err != nil {
			s.log.ErrorContext(ctx, "committing a flow that issued no session", "err", err)
		}
		s.clearPending(w)
		writeJSON(w, http.StatusOK, map[string]string{"status": "done"})
		return
	case decisionSession:
		// Fall through.
	}

	// The walk's own marks stop here, the one place a session comes into
	// existence.
	amr = flow.Unmarked(amr)

	// The operator's provider, about a sign-in every step has passed, here for every
	// way in as the status check above is. It can only take this back.
	if hook := s.askHook(ctx, tx, orgID, provider.HookAuthenticate, store.AuthenticateHookRequest{
		Subject: userID, OrgID: orgID, AMR: amr, ClientIP: clientIP(r)}); hook.Vetoed {
		_ = tx.Rollback(ctx)
		s.clearPending(w)
		s.recordHookRefusal(ctx, provider.HookAuthenticate, orgID, userID, "", hook.Reason)
		s.renderLogin(w, r, authzQuery, "You cannot sign in at the moment. Please contact your administrator.")
		return
	}

	// ASVS 5.0.0 V7.2.4: "generates a new session token on user authentication,
	// including re-authentication, and TERMINATES THE CURRENT SESSION TOKEN."
	//
	// A fresh sid and cookie token are minted below every time, so session
	// fixation has never worked here. What did not happen is the second half: the
	// session this browser already held stayed live until not_after.
	//
	// Step-up is the case that matters. Someone signs in with a password (acr=1),
	// something asks for another factor, they re-authenticate, and they hold an
	// acr=2 session. The acr=1 session remained valid for hours -- so anyone
	// holding that earlier cookie kept a working password-only session, and the
	// user re-authenticated precisely because something warranted it.
	//
	// Terminated in THIS transaction, so the old session dies exactly when the
	// new one is born; a crash between the two cannot leave both live. Going
	// through TerminateSessions rather than an UPDATE also queues the CAEP
	// session-revoked notices, so relying parties holding tokens from the old
	// session learn it ended rather than discovering it at expiry.
	//
	// The sessions presented by THIS browser, and only those. A user signed in
	// on a phone and a laptop who re-authenticates on the laptop has not asked to
	// be signed out of the phone.
	//
	// And only this person's: another account this browser holds is not this
	// sign-in's to end, and is kept beside it (accounts.go, 5.17). Ending every
	// session the browser presented is what made a second account a sign-out of
	// the first. A parked session of this person's goes too, or it would stay
	// live with no cookie left to end it.
	for _, old := range append([]string{sessionCookie(r)}, parkedTokens(r)...) {
		if old == "" {
			continue
		}
		var oldSID string
		if err := tx.QueryRow(ctx, `
			SELECT sid FROM core.sessions
			WHERE cookie_hash = $1 AND revoked_at IS NULL AND user_id = $2::uuid`,
			store.HashToken(old), userID).Scan(&oldSID); err == nil && oldSID != "" {
			if _, terr := store.TerminateSessions(ctx, tx, oldSID, "",
				store.ReasonReauthenticated); terr != nil {
				s.log.ErrorContext(ctx, "terminating the superseded session", "err", terr,
					"correlation_id", correlationID(ctx))
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
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

	// acr is DERIVED from the factors actually used, never asserted. Writing a
	// literal here is how a password-only session ends up claiming multi-factor.
	acr := oauth.ACRFromAMR(amr)

	// The organisation's concurrent-session cap, applied BEFORE the row is
	// written so the count read is the count this insert adds to. Unlimited by
	// default, so most deployments do one extra cheap query and nothing else.
	evicted, lerr := store.EnforceSessionLimit(ctx, tx, orgID, userID)
	if errors.Is(lerr, store.ErrSessionLimitReached) {
		// The credential was correct; the policy refused. Audited as its own
		// event rather than as a login failure, because reading it as a bad
		// password would send somebody to reset a password that works.
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "session_limit"},
		}); aerr != nil {
			s.log.ErrorContext(ctx, "auditing a session-limit refusal", "err", aerr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			s.log.ErrorContext(ctx, "committing the session-limit refusal", "err", cerr)
		}
		s.renderLogin(w, r, "", "You are already signed in on the maximum number "+
			"of devices for this organisation. Sign out somewhere else and try again.")
		return
	}
	if lerr != nil {
		s.log.ErrorContext(ctx, "enforcing the session limit", "err", lerr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(evicted) > 0 {
		s.log.InfoContext(ctx, "sessions evicted to make room", "user_id", userID,
			"count", len(evicted), "correlation_id", correlationID(ctx))
	}

	// The organisation's lifetime, and its idle limit, from sign-in (0180): the
	// session ends at the sooner of the two unless it is used.
	// A device none of this person's recent sessions came from is told to
	// them (newdevice.go), read before this session is written and queued
	// with it, so a sign-in that does not hold tells nobody.
	if device, isNew := s.newDeviceSignIn(ctx, r, tx, userID, orgID); isNew {
		if err := store.EnqueueAccountNotice(ctx, tx, store.AccountNotice{UserID: userID,
			Notice: store.NoticeNewDevice, Device: device}); err != nil {
			s.log.ErrorContext(ctx, "queueing the new-device notice", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// What this sign-in showed, kept with it: a decision made later has only a relying
	// party's request to go on, with no browser behind it (11.07). Read before this
	// session's own location is recorded, or it would be its own history.
	device := s.posture.Evaluate(r)
	riskNow := s.riskScore(ctx, tx, userID, clientIP(r))

	// persistent records "stay signed in", where it was asked and is offered,
	// for whichever of this browser's cookies holds the session later (0185).
	userAgent, ipHash := s.sessionDevice(r)
	if tag, err := tx.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after,
		                           absolute_not_after, last_seen_at, user_agent, ip_hash, persistent,
		                           risk, device_managed, device_compliant)
		SELECT $1, $2, o.id, $4, $5, $6, now(),
		       now() + make_interval(secs => least(o.session_lifetime_s, coalesce(o.session_idle_s, o.session_lifetime_s))),
		       now() + make_interval(secs => o.session_lifetime_s), now(), $7, $8, $9 AND o.persistent_sessions,
		       $10, $11, $12
		  FROM core.organizations o WHERE o.id = $3::uuid`,
		sid, store.HashToken(cookieToken), orgID, userID, acr, amr,
		userAgent, ipHash, rememberAsked(r), riskNow, device.Managed,
		device.Managed && device.Compliant); err != nil || tag.RowsAffected() != 1 {
		s.log.ErrorContext(ctx, "creating session", "err", err, "rows", tag.RowsAffected())
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
		s.log.ErrorContext(ctx, "auditing login", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.clearPending(w)
	// A browser-session cookie, unless this sign-in asked to stay signed in
	// on this device and the organisation offers that (5.11). Read only then,
	// so an ordinary sign-in pays nothing for it.
	maxAge := 0
	if rememberAsked(r) {
		maxAge = s.persistentCookieAge(ctx, sid)
		s.forgetRemember(w, r)
	}
	// Whoever else this browser was signed in as stays signed in, parked
	// beside this one (accounts.go), unless it was this person.
	s.parkOthers(ctx, w, r, userID)
	s.setSessionCookie(w, cookieToken, maxAge)
	// The language this person chose, in whatever browser they chose it.
	if locale != "" && s.pageSet().Bundle().Has(locale) {
		setLanguageCookie(w, locale)
	}

	// Where this sign-in came from, for the next travel check.
	//
	// Recorded AFTER the session is committed and deliberately outside its
	// transaction: failing to note a position must never stop somebody signing
	// in. A risk signal that can deny access when its own bookkeeping fails is
	// worse than no signal.
	loc := s.geo.Resolve(clientIP(r))
	loc.At = time.Now()
	if lerr := store.RecordAuthLocation(ctx, s.db, userID, orgID, loc); lerr != nil {
		s.log.ErrorContext(ctx, "recording the sign-in location", "err", lerr)
	}

	// Back to whatever was parked, if anything was.
	if authzQuery != "" {
		answered := s.answerPrompts(ctx, authzQuery, oauth.PromptLogin, oauth.PromptSelectAccount)
		http.Redirect(w, r, resumeAfterSignIn(answered), http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed in"})
}

// dummyHash is a real Argon2id hash of a value nobody knows, used to keep the
// timing of "no such user" indistinguishable from "wrong password".
const dummyHash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"

// credential is one account a sign-in name could mean.
type credential struct {
	userID, orgID, hash string
	// status is active or pending: a self-sign-up waiting for approval is
	// found, so that its own correct password is answered by why it cannot
	// sign in yet (completeSignIn) rather than by "wrong password".
	status string
}

// lookupCredentials finds the accounts an identifier names: in orgID when it is
// given, and in every organisation when it is empty. At most a few -- a caller
// needs to tell one from several, not to enumerate.
//
// Sign-in names are unique per organisation (users_org_email_key), not across
// them. This used to ask across all of them with QueryRow, so the same address
// in two tenants signed in to whichever row the planner returned, or refused the
// right person when it met the other's hash.
func (s *Server) lookupCredentials(ctx context.Context, identifier, orgID string) ([]credential, error) {
	// The status check is in the query: a deactivated user must not be able to
	// sign in, and doing it here means there is no window where a caller forgets.
	// A pending one is found, and refused by completeSignIn once its password
	// is right, with the reason (5.19); recovery passes over it. So is one of a
	// suspended organisation (6.09), its status read as org_suspended.
	// "Every organisation" is this instance's (6.12): a name held in another
	// is neither found nor counted against the one held here.
	rows, err := s.db.Query(ctx, `
		SELECT u.id::text, u.org_id::text, pc.hash,
		       CASE WHEN `+store.OrgInService("u.org_id")+` THEN u.status ELSE 'org_suspended' END
		FROM core.users u
		JOIN core.password_credentials pc ON pc.user_id = u.id
		WHERE u.status IN ('active', 'pending')
		  AND ($2 = '' OR u.org_id = $4::uuid)
		  AND `+store.InInstance("u.org_id", "$3")+`
		  AND (u.email_fold = lower($1) OR u.username_fold = lower($1))
		ORDER BY u.org_id
		LIMIT 5`, identifier, orgID, s.instanceID, store.ExactUUIDOrNil(orgID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []credential
	for rows.Next() {
		var c credential
		if err := rows.Scan(&c.userID, &c.orgID, &c.hash, &c.status); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// lookupCredential finds the one account an identifier names. ambiguous is true
// when no organisation was given and the name is held in more than one: a page
// that cannot say whose it is cannot say which of them is meant, and choosing
// would sign somebody in to an account in the wrong tenant.
func (s *Server) lookupCredential(ctx context.Context, identifier, orgID string) (c credential, ok, ambiguous bool, err error) {
	found, err := s.lookupCredentials(ctx, identifier, orgID)
	switch {
	case err != nil:
		return credential{}, false, false, err
	case len(found) == 1:
		return found[0], true, false, nil
	case len(found) > 1:
		return credential{}, false, true, nil
	}
	return credential{}, false, false, nil
}

func (s *Server) verifyClientSecret(ctx context.Context, c *clients.Client, presented string) (bool, error) {
	if c.SecretHash == "" || presented == "" {
		return false, nil
	}
	// A client secret we generated is 256 bits of random data, so the property
	// protecting it is entropy rather than hash cost -- see internal/clients.
	// Argon2 here was costing 33 ms and a 512 MiB pool per request to defend
	// against a dictionary attack on a value with no dictionary.
	if clients.IsFastSecret(c.SecretHash) {
		return clients.VerifyFastSecret(c.SecretHash, presented)
	}
	// A secret whose entropy is not established -- imported verbatim from
	// another provider, say -- keeps the slow hash. Guessing wrong in that
	// direction is the expensive mistake.
	_, err := s.hasher.Verify(ctx, c.SecretHash, presented)
	if errors.Is(err, passwords.ErrMismatch) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// lookupClient loads a client for a request it makes or that is made in its
// name, and refuses a disabled one: this is the one place every endpoint a
// client calls loads it, so a disabled client stops working on the next
// request at all of them (ADR-007). Until October 2026 it returned the row and
// left the check to each caller; three made it, so a disabled client still
// refreshed its tokens, started device flows and revoked and introspected.
// The answer is the unknown client's, so nobody unauthenticated learns that
// the client exists; the log says which.
func (s *Server) lookupClient(ctx context.Context, clientID string) (*clients.Client, error) {
	c, err := s.lookupClientAnyState(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !c.Enabled {
		s.log.InfoContext(ctx, "a disabled client was refused", "client_id", clientID,
			"correlation_id", correlationID(ctx))
		return nil, clients.ErrDisabled
	}
	// And a client of a suspended organisation, the same way (6.09).
	if c.OrgSuspended {
		s.log.InfoContext(ctx, "a client of a suspended organisation was refused", "client_id", clientID,
			"org_id", c.OrgID, "correlation_id", correlationID(ctx))
		return nil, clients.ErrOrgSuspended
	}
	return c, nil
}

// lookupClientAnyState loads a client whether or not it is enabled, for the
// few callers that say why it is refused or only show it; nothing that grants,
// answers or acts for a client uses it, and
// TestEveryClientLookupThatAdmitsADisabledClientIsDeclared holds the list.
func (s *Server) lookupClientAnyState(ctx context.Context, clientID string) (*clients.Client, error) {
	if clientID == "" {
		return nil, clients.ErrNotFound
	}
	c, err := clients.Lookup(ctx, s.db, clientID)
	if err != nil {
		return nil, err
	}
	// Another instance's client is not one this issuer has (6.12): it was
	// registered with the other issuer, and its relying parties verify that
	// issuer's tokens. Answered as unknown, so nobody learns it exists there.
	if !s.serves(c.InstanceID) {
		s.log.InfoContext(ctx, "a client of another instance was refused", "client_id", clientID,
			"correlation_id", correlationID(ctx))
		return nil, clients.ErrNotFound
	}
	return c, nil
}

// writeAuthzError delivers an authorization error by whichever route its
// disposition permits. A direct error renders here; only a redirect-disposition
// error is sent to the client, and a client is what vouches for the redirect URI.
//
// It goes the way a code would have. OIDC Core §3.3.2.6 asks that of the hybrid flow,
// "unless a different Response Mode was specified", and JARM §2.1 of every response
// "even in case of an error response". `state` is echoed exactly as received, and `iss`
// is included (RFC 9207) so a client can tell which provider answered.
func (s *Server) writeAuthzError(w http.ResponseWriter, r *http.Request,
	req oauth.AuthzRequest, c *clients.Client, e *oauth.AuthzError) {

	if e.Disposition == oauth.DispositionRedirect && c != nil {
		s.deliverAuthzResponse(w, r, req, c, responseParams{Error: e.Code, ErrorDescription: e.Description,
			State: req.State, Issuer: s.issuerFor(c)})
		return
	}
	s.renderPageStatus(w, r, http.StatusBadRequest, "err", map[string]any{
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

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	s.endSession(w, r, "")
}

// endSession signs a person out and takes them on. registered is a landing the
// caller has held to a registration of its own, as WS-Federation holds a wreply to its
// reply URLs; without one, the request's post_logout_redirect_uri is held to a client's.
func (s *Server) endSession(w http.ResponseWriter, r *http.Request, registered string) {
	ctx := r.Context()

	// Confirmed, hinted, or nothing to do -- otherwise ask first.
	//
	// OWASP ASVS 5.0 V10.6.2: "Verify that the OpenID Provider mitigates denial
	// of service through forced logout. By obtaining explicit confirmation from
	// the end-user or, if present, validating parameters in the logout request
	// ... such as the id_token_hint."
	//
	// OIDC RP-Initiated Logout 1.0 §2 says the same thing from the other side:
	// the OP "SHOULD ask the End-User whether to log out" unless the request
	// carries a valid id_token_hint.
	//
	// Without this, `<img src="https://id.example.com/oauth2/logout">` on any
	// page signs out every visitor who has a session here, repeatedly, from
	// anywhere. It is not a credential compromise -- it is a denial of service
	// that costs an attacker one HTML tag, and the user cannot tell it from a
	// broken product.
	if !s.logoutConfirmed(w, r) {
		return
	}

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

	// Read BEFORE terminating: ending the session cascades session_clients away,
	// and with it the record of which relying parties to notify.
	frontChannel := s.frontChannelTargets(ctx, chainSID, s.cfg.Issuer)

	// The account in use, then every other this browser holds (accounts.go):
	// signing out of a shared computer leaves nobody signed in on it.
	for _, cookie := range append([]string{sessionCookie(r)}, parkedTokens(r)...) {
		if err := s.terminateOwnSession(ctx, cookie); err != nil {
			s.log.ErrorContext(ctx, "ending session", "err", err)
			// The cookies are still cleared: they are defence in depth for THIS
			// browser, and withholding them would leave the user with neither
			// outcome. But we do not redirect and do not claim success.
			s.clearSessionCookie(w)
			s.clearParked(w, r)
			writeError(w, http.StatusInternalServerError, "server_error",
				"sign-out could not be completed; your session may still be active")
			return
		}
	}

	// Clear the cookie even if there was no live session: the user asked to be
	// signed out, and leaving a stale cookie behind is confusing.
	s.clearSessionCookie(w)
	s.clearParked(w, r)
	s.forgetUpstream(w)

	// post_logout_redirect_uri must be REGISTERED before we redirect to it.
	// An unvalidated post-logout redirect is an open redirector reached from a
	// link that looks like a sign-out, which is a good phishing pretext.
	target := q.Get("post_logout_redirect_uri")
	if registered != "" {
		target = registered
	} else if target != "" {
		// Scoped to the CLIENT, not global. The previous query asked only whether
		// SOME client had registered this URI, so any client's registered
		// post-logout URI worked for every other client -- a redirect reachable
		// from a link that looks like a sign-out, which is a good phishing pretext.
		//
		// The client is identified by client_id, or derived from id_token_hint when
		// the caller follows the spec and sends one.
		clientID := q.Get("client_id")
		if clientID == "" {
			clientID = s.clientFromIDTokenHint(r.Context(), q.Get("id_token_hint"))
		}
		// And a client of this instance (6.12), as a client_id names here.
		var ok bool
		if err := s.db.QueryRow(ctx, `
			SELECT true FROM core.client_post_logout_redirect_uris p
			  JOIN core.clients c ON c.client_id = p.client_id
			WHERE p.redirect_uri = $1 AND p.client_id = $2
			  AND `+store.InInstance("c.org_id", "$3"),
			target, clientID, s.instanceID).Scan(&ok); err != nil || !ok {
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
	}
	if target != "" {
		// The post-logout target is now VALIDATED, so it is safe to hand to the
		// SAML chain as the place to land once propagation finishes. The provider
		// the person came through, when it asks to be told, is the last stop before
		// it, since nothing here can resume once the browser has left.
		if upstream := s.upstreamLogout(ctx, r, chainSID, target); upstream != "" {
			target = upstream
		}
		if chain := s.beginSAMLLogoutChain(ctx, chainSID, chainUser, chainOrg, target); chain != "" {
			// SAML first: its chain needs the browser, and the front channel would
			// otherwise navigate away mid-chain.
			http.Redirect(w, r, chain, http.StatusSeeOther)
			return
		}
		if len(frontChannel) > 0 {
			s.renderFrontChannelLogout(w, r, frontChannel, target)
			return
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}

	// No post-logout redirect: propagate, then report, or leave for the provider.
	if upstream := s.upstreamLogout(ctx, r, chainSID, ""); upstream != "" {
		if chain := s.beginSAMLLogoutChain(ctx, chainSID, chainUser, chainOrg, upstream); chain != "" {
			http.Redirect(w, r, chain, http.StatusSeeOther)
			return
		}
		if len(frontChannel) > 0 {
			s.renderFrontChannelLogout(w, r, frontChannel, upstream)
			return
		}
		http.Redirect(w, r, upstream, http.StatusSeeOther)
		return
	}
	if chain := s.beginSAMLLogoutChain(ctx, chainSID, chainUser, chainOrg, ""); chain != "" {
		http.Redirect(w, r, chain, http.StatusSeeOther)
		return
	}
	if len(frontChannel) > 0 {
		s.renderFrontChannelLogout(w, r, frontChannel, "/login")
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
	sid, _, err := store.ResolveSessionCookie(ctx, s.db, store.HashToken(cookie), s.instanceID)
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

	var orgID, userID string
	if err := tx.QueryRow(ctx, `SELECT org_id::text, user_id::text FROM core.sessions WHERE sid = $1`,
		sid).Scan(&orgID, &userID); err != nil {
		return fmt.Errorf("reading the session: %w", err)
	}
	term, err := store.TerminateSessions(ctx, tx, sid, "", store.ReasonLogout)
	if err != nil {
		return fmt.Errorf("terminating session: %w", err)
	}
	// The commit is what makes the revocation AND the queued back-channel logout
	// notifications durable -- they share this transaction by design, so a failed
	// commit means neither happened.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing logout: %w", err)
	}
	// Recorded after the sign-out is durable, never as a condition of it: an
	// audit write that failed must not leave somebody signed in. Nothing
	// recorded a sign-out before 2.52.
	detail := map[string]any{"sid": sid}
	if term != nil {
		detail["sessions_ended"], detail["notices_queued"] = term.Sessions, term.Notices
	}
	s.auditDetached(ctx, audit.Event{Type: audit.EventLogout, OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx), Detail: detail})
	return nil
}

// clientFromIDTokenHint reads the audience of an id_token_hint.
//
// The hint is used ONLY to identify which client is asking, never to authorise
// anything: the post-logout URI is still checked against that client's registered
// set. A hint that fails to verify yields "" and the redirect is refused, which is
// the safe direction.
func (s *Server) clientFromIDTokenHint(ctx context.Context, hint string) string {
	if hint == "" {
		return ""
	}
	claims, err := tokens.VerifyIDTokenAudience(s.cfg.Keys, s.cfg.Issuer, hint)
	if err != nil {
		s.log.InfoContext(ctx, "id_token_hint did not verify", "err", err)
		return ""
	}
	return claims
}

// logoutConfirmed reports whether this logout may proceed without asking.
//
// Returns false having already written a response -- either the confirmation
// page or an error.
func (s *Server) logoutConfirmed(w http.ResponseWriter, r *http.Request) bool {
	// A POST carrying a valid CSRF token IS the confirmation: it can only have
	// come from the form this server rendered into this browser.
	if r.Method == http.MethodPost {
		if checkCSRF(r) {
			return true
		}
		writeError(w, http.StatusForbidden, "invalid_request",
			"the sign-out form has expired; open the sign-out link again")
		return false
	}

	// A verified id_token_hint identifies the relying party that asked, and is
	// what the specification accepts in place of asking the person. Verified,
	// not merely present: an unverified hint is a string the attacker chose.
	if hint := r.URL.Query().Get("id_token_hint"); hint != "" {
		if s.clientFromIDTokenHint(r.Context(), hint) != "" {
			return true
		}
	}

	// No session to end means nothing to confirm, and rendering a page that
	// says "sign out?" to somebody who is not signed in is worse than useless.
	if sessionCookie(r) == "" && len(parkedTokens(r)) == 0 {
		return true
	}

	s.renderLogoutConfirmation(w, r)
	return false
}

// renderLogoutConfirmation asks the person whether they meant to sign out.
//
// The form POSTs back to the same URL, so every query parameter the relying
// party sent -- post_logout_redirect_uri, state, client_id -- survives the
// round trip untouched and is validated exactly as before.
func (s *Server) renderLogoutConfirmation(w http.ResponseWriter, r *http.Request) {
	tok, err := s.csrfToken(w, r)
	if err != nil {
		s.log.ErrorContext(r.Context(), "issuing a CSRF token for the sign-out confirmation", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	htmlPageHeaders(w)
	// The action is the current URL including its query, so the parameters are
	// resubmitted rather than re-derived.
	s.renderPage(w, r, "logout", map[string]any{
		"Action": r.URL.RequestURI(),
		"CSRF":   tok,
		"Field":  csrfFormField,
	})
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

// verifyByProvider asks a `hook` source's provider, answering as delegator.Verify does,
// so an outage there is handled as an outage anywhere else: not a wrong password, and
// not charged to the person.
func (s *Server) verifyByProvider(ctx context.Context, orgID, identifier, password string) error {
	verified, err := store.ConsultPasswordProvider(ctx, s.db, s.cfg.Root, s.outboundClient, orgID, identifier, password)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", delegated.ErrUnavailable, err)
	case !verified:
		return delegated.ErrRejected
	}
	return nil
}

func (s *Server) tryDelegated(w http.ResponseWriter, r *http.Request,
	pageOrg, identifier, password, authzQuery string) bool {

	ctx := r.Context()
	if s.cfg.Root == nil {
		return false
	}
	pending, ok, err := store.LookupMigrationCandidate(ctx, s.db, pageOrg, s.instanceID, identifier, s.cfg.Root)
	if err != nil {
		s.log.ErrorContext(ctx, "looking up migration candidate", "err", err)
		return false
	}
	if !ok {
		return false
	}

	// A realm is asked about the person as it knows them. Somebody who typed their
	// address has a name in the realm, not an address, and being asked about the one
	// they typed would call their right password wrong.
	asked := identifier
	if pending.Source.Kind == "kerberos" && pending.Username != "" {
		asked = pending.Username
	}

	var verr error
	if pending.Source.Kind == "hook" {
		verr = s.verifyByProvider(ctx, pending.OrgID, identifier, password)
	} else {
		verr = s.delegator.Verify(ctx, pending.Source, asked, password)
	}
	switch {
	case errors.Is(verr, delegated.ErrUnavailable):
		// The OLD provider is broken, not the user. Reported as a temporary
		// failure and NOT counted against the account -- otherwise someone
		// else's outage locks out every user still to be migrated.
		store.RecordDelegationFailure(ctx, s.db, pending.Source.ID, verr.Error())
		s.log.ErrorContext(ctx, "migration source unavailable", "source", pending.Source.DisplayName,
			"err", verr, "correlation_id", correlationID(ctx))
		s.renderLogin(w, r, authzQuery,
			"Sign-in is temporarily unavailable. Please try again shortly.")
		return true

	case verr != nil:
		store.RecordDelegationFailure(ctx, s.db, pending.Source.ID, "rejected")
		// Charged like any wrong password, to the address, the account and the
		// captcha. It was charged to none of them, so guessing an account that
		// had not migrated yet was unlimited, and every guess was forwarded to
		// the old provider in this server's name.
		s.captcha.RecordFailure(ctx, r.RemoteAddr)
		s.recordSignInFailure(ctx, r)
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: pending.OrgID, SubjectID: pending.UserID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "delegated_rejected", "source": pending.Source.DisplayName},
		})
		s.renderLogin(w, r, authzQuery, "Incorrect username or password.")
		return true
	}

	// A realm is not being migrated from. It stays the authority, so no hash is
	// taken: one kept here would go on working after the realm had changed the
	// password or disabled the account, which is the whole of what asking it gets.
	if pending.Source.Kind == "kerberos" {
		tx, err := s.db.Begin(ctx)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return true
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.RecordDelegationSuccess(ctx, tx, pending.Source.ID); err != nil {
			_ = tx.Rollback(ctx)
			s.log.ErrorContext(ctx, "counting a sign-in through a realm", "err", err)
			s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
			return true
		}
		s.completeSignIn(w, r, tx, pending.UserID, pending.OrgID, []string{oauth.AMRPassword}, authzQuery)
		return true
	}

	// Accepted by the old provider. Take a local hash NOW, in the same
	// transaction as the session -- so this user never needs the old system
	// again, and the migration shrinks by one.
	//
	// The policy is deliberately NOT enforced here. This password was already
	// theirs and the old provider just accepted it; refusing it would lock
	// somebody out of an account they have proved they own, in the middle of a
	// migration, which is how a migration gets rolled back. What we do instead
	// is check and flag: they sign in, and are asked to change it at the door.
	migratedBreach := ""
	if s.pwPolicy.Breach != nil {
		if bad, berr := s.pwPolicy.Breach.Breached(ctx, password); berr == nil && bad {
			// A key rather than a sentence; see renderChangeReason.
			migratedBreach = "reason.migratedbreach"
		}
	}

	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		s.log.ErrorContext(ctx, "hashing a migrated password", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return true
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if migratedBreach != "" {
		if ferr := store.RequirePasswordChange(ctx, tx, pending.UserID,
			migratedBreach); ferr != nil {
			s.log.ErrorContext(ctx, "flagging a migrated breached password", "err", ferr)
		}
	}
	if err := store.CompleteMigration(ctx, tx, pending.UserID, pending.OrgID,
		pending.Source.ID, hash); err != nil {
		_ = tx.Rollback(ctx)
		s.log.ErrorContext(ctx, "completing migration", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return true
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "account.migrated", OrgID: pending.OrgID, SubjectID: pending.UserID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"source": pending.Source.DisplayName},
	}); err != nil {
		_ = tx.Rollback(ctx)
		s.log.ErrorContext(ctx, "auditing migration", "err", err)
		s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
		return true
	}

	s.log.InfoContext(ctx, "user migrated on first sign-in", "source", pending.Source.DisplayName,
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
// deployment's issuer plus the legacy aliases registered and not retired.
//
// Read per request. It was read once at startup, so an alias registered with
// `instance add-alias` was refused until a restart and one past its
// retirement went on being honoured until one -- accepting tokens under an
// issuer this deployment had stopped claiming. A failed read accepts the
// deployment's own issuer only.
func (s *Server) acceptedIssuers(ctx context.Context) []string {
	out := []string{s.cfg.Issuer}
	if s.db == nil || s.instanceID == "" {
		return out
	}
	aliases, err := store.LiveIssuerAliases(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading issuer aliases; accepting this deployment's own issuer only", "err", err)
		return out
	}
	return append(out, aliases...)
}

// decodeDetailClaim reads the RFC 9396 §9.1 claim back off a verified token.
//
// An absent claim is not an error and yields nothing: most tokens carry no rich
// permissions, and treating that as a decode failure would make every ordinary
// exchange fail.
func decodeDetailClaim(raw json.RawMessage) ([]rar.Detail, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var out []rar.Detail
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
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

	var subject *tokens.AccessTokenClaims
	var foreign *assertionStatement
	var ok bool
	if s.subjectTokenIsForeign(ctx, ex) {
		subject, foreign, ok = s.foreignSubject(ctx, w, c, ex)
	} else {
		subject, ok = s.ownSubject(w, r, c, ex)
	}
	if !ok {
		return
	}

	// RFC 8693 §4.1 delegation. The actor token names the party actually doing
	// the acting, when that is somebody other than the calling client.
	//
	// Verified exactly as the subject token is -- signature, issuer, revocation,
	// session liveness. §2.1 makes that a MUST: the server "MUST perform the
	// appropriate validation procedures" for the actor token too. An actor token
	// that is expired, revoked, or from an ended session names a party who can no
	// longer act, and recording them in the `act` chain would put a name in the
	// audit trail that the credential no longer supports.
	actorSubject := ""
	if ex.ActorToken != "" {
		actor, aerr := s.verifyPresented(ctx, s.acceptedIssuers(ctx), ex.ActorToken)
		if aerr != nil {
			s.log.InfoContext(ctx, "token exchange: actor token rejected", "err", aerr,
				"caller", c.ClientID, "correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
				Description: "the actor token is not valid", Status: http.StatusBadRequest})
			return
		}
		if s.issuanceOnly(actor) {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
				Description: "the actor token is good for issuing a credential and nothing else",
				Status:      http.StatusBadRequest})
			return
		}
		if terr := s.exchangeRefusal(ctx, actor, "actor", "invalid_request"); terr != nil {
			writeTokenError(w, terr)
			return
		}
		actorSubject = actor.Subject
	}

	// RFC 8693 §4.4. Only bites when the subject token actually carries the
	// claim; an absent may_act leaves the per-client permission and audience
	// allow-list as the bound, which is what they were always for.
	//
	// `actorSubject` is the ACTOR's subject, empty when no actor token was
	// presented. It used to be the subject token's own `sub` -- the user being
	// acted for -- so `may_act: {"sub": "<that user>"}` compared a value against
	// itself and passed. CheckMayAct now treats an absent actor subject as an
	// unevaluable constraint rather than a satisfied one.
	if err := oauth.CheckMayAct(subject.MayAct, c.ClientID, actorSubject,
		s.cfg.Issuer); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: err.Error(), Status: http.StatusBadRequest})
		return
	}

	granted, audience, terr := oauth.ValidateExchange(ex, c.Type == "confidential", c.MayExchange, c.ExchangeAudiences,
		c.ClientID, splitScopes(subject.Scope))
	if terr != nil {
		writeTokenError(w, terr)
		return
	}
	// As the jwt-bearer grant says: somebody else authenticated this person.
	if foreign != nil && containsScope(granted, "openid") {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
			Description: "openid is not available from a token issued elsewhere: the " +
				"authentication was performed by its issuer, not here",
			Status: http.StatusBadRequest})
		return
	}

	// The exchanged token is for the subject, issued to this client, so it is
	// this client's question to put to the access policy, with the factors of
	// the session the subject token came from. And the subject must be in this
	// client's organisation: a token audienced here from another tenant's
	// client was otherwise exchangeable into one issued under this tenant.
	if s.grantRefusedByPolicy(w, r, c.OrgID, c.ClientID, subject.Subject, subject.SessionID,
		strings.Join(granted, " "), "token_exchange") {
		return
	}

	key, err := s.cfg.Keys.Active(keys.Algorithm(c.AccessTokenAlg()))
	if err != nil {
		s.log.ErrorContext(ctx, "token exchange: no active key", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	jti, err := newSID()
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	// The actor chain. The acting party is recorded, and any chain the subject
	// token already carried is nested beneath -- so a token three delegations deep
	// still names every party, in order.
	//
	// The actor is the ACTOR TOKEN's subject when one was presented, and the
	// calling client otherwise. §4.1's example shows a human in `act.sub`, which
	// is only expressible once a delegated actor can be named; before that every
	// link in the chain was a client id.
	actorName := c.ClientID
	if actorSubject != "" {
		actorName = actorSubject
	}
	if subject.Act.Depth() >= tokens.MaxActorDepth {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: fmt.Sprintf("the subject token has been delegated %d times, the most allowed", tokens.MaxActorDepth),
			Status:      http.StatusBadRequest})
		return
	}
	act := &tokens.Actor{Subject: actorName, Act: subject.Act}

	// The subject token's rich permissions come WITH it.
	//
	// Scope is narrowed above and authorization_details were simply dropped,
	// which quietly made exchange the widest hole in the product: a token
	// constrained to "move EUR 123.50 to this account" exchanged into one
	// carrying `scope=payments` and no details at all. A resource server reading
	// no details has nothing left to enforce but the scope, so the exchange
	// laundered a single-transaction grant into a standing capability -- and
	// exchange exists precisely to hand that token to somebody else.
	//
	// Carried, then narrowed if the caller asked for less. Never widened: Narrow
	// refuses anything the subject token did not already authorize, which is the
	// same rule §6 applies at the token endpoint.
	subjectDetails, derr := decodeDetailClaim(subject.AuthorizationDetails)
	if derr != nil {
		s.log.ErrorContext(ctx, "token exchange: decoding the subject token's details", "err", derr)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	exchangedDetails := subjectDetails
	if raw := r.PostForm.Get(rar.Param); raw != "" {
		requested, _, perr := rar.Parse(raw)
		if perr != nil {
			writeTokenError(w, &oauth.TokenError{Code: rar.ErrorCode,
				Description: perr.Error(), Status: http.StatusBadRequest})
			return
		}
		narrowed, nerr := rar.Narrow(subjectDetails, requested)
		if nerr != nil {
			writeTokenError(w, &oauth.TokenError{Code: rar.ErrorCode,
				Description: nerr.Error(), Status: http.StatusBadRequest})
			return
		}
		exchangedDetails = narrowed
	}
	var exchangedDetailClaim json.RawMessage
	if forAudience := rar.FilterByAudience(exchangedDetails, audience); len(forAudience) > 0 {
		encoded, merr := json.Marshal(forAudience)
		if merr != nil {
			s.log.ErrorContext(ctx, "token exchange: encoding authorization_details", "err", merr)
			writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
			return
		}
		exchangedDetailClaim = encoded
	}

	exchangeJKT := dpopThumbprintFrom(ctx)

	// About the person the token is still for, issued to the calling client.
	hookCtx, ok := s.consultTokenHook(ctx, w, c, store.TokenHookRequest{
		Subject: subject.Subject, ClientID: c.ClientID, Scopes: granted,
		Grant: oauth.GrantTypeTokenExchange, OrgID: c.OrgID})
	if !ok {
		return
	}

	// The calling client's lifetime, and never past the subject token's own
	// expiry: exchange delegates what the subject token carries, it does not
	// extend it. Five minutes for everybody hid the question; a per-client
	// hour would otherwise turn a token about to expire into one good for an
	// hour more.
	now := time.Now()
	expiry := now.Add(c.AccessTokenTTL()).Unix()
	if subject.Expiry > 0 && subject.Expiry < expiry {
		expiry = subject.Expiry
	}
	// A token from elsewhere buys one token here, in the transaction that issues it.
	var issuing store.SubjectDB = s.db
	var spent pgx.Tx
	if foreign != nil {
		if spent, err = s.db.Begin(hookCtx); err != nil {
			writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
			return
		}
		defer func() { _ = spent.Rollback(hookCtx) }()
		if !s.spendAssertion(hookCtx, w, spent, c, foreign, "invalid_request") {
			return
		}
		issuing = spent
	}
	at, err := issueAccessToken(hookCtx, issuing, c, tokens.NewSigner(key), tokens.AccessTokenClaims{
		Issuer:   s.issuerFor(c),
		Subject:  subject.Subject, // still the USER; exchange delegates, it does not impersonate
		Audience: audience,
		Expiry:   expiry,
		IssuedAt: now.Unix(),
		JTI:      jti,
		ClientID: c.ClientID,
		Scope:    joinScopes(granted),
		// The session is carried through deliberately: an exchanged token must
		// die when the user signs out, exactly like the token it came from.
		SessionID: subject.SessionID,
		Act:       act,

		// Sender-constrained when the caller proved possession of a key on THIS
		// request. handleToken already verified the proof before dispatching the
		// grant, so the thumbprint was sitting on the context and this path simply
		// did not read it -- every other mint site does.
		//
		// Bound to the CALLER's key, not the subject token's: exchange delegates
		// to a different party, and that party is the one who will present the new
		// token. RFC 9449 §5 lets an AS elect not to bind at all, so the previous
		// behaviour was permitted rather than wrong -- but it meant a client using
		// DPoP everywhere else silently received an ordinary bearer token from the
		// one endpoint whose purpose is handing credentials to someone else.
		Cnf: bindingFor(exchangeJKT, ""),

		AuthorizationDetails: exchangedDetailClaim,
	})
	if err != nil {
		s.log.ErrorContext(ctx, "token exchange: signing", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	detail := map[string]any{"acting_for": subject.ClientID, "audience": audience, "scope": granted}
	if foreign != nil {
		// Committed before it is written, so a failure spends nothing.
		if err := spent.Commit(hookCtx); err != nil {
			s.log.ErrorContext(ctx, "token exchange: committing the spent token", "err", err)
			writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
			return
		}
		detail["subject_issuer"] = foreign.claims.Issuer
	}

	s.auditDetached(ctx, audit.Event{
		Type: "oauth.token_exchanged", SubjectID: subject.Subject, ClientID: c.ClientID,
		CorrelationID: correlationID(ctx),
		Detail:        detail,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": at,
		// RFC 8693 §2.2.1 requires issued_token_type. token_type follows the
		// binding: RFC 9449 §5 makes "DPoP" a MUST once the token is bound to a
		// key, because a client told "Bearer" sends no proof and every request it
		// makes with the token is refused.
		"issued_token_type": oauth.TokenTypeAccess,
		"token_type":        bearerOrDPoP(exchangeJKT),
		"expires_in":        int(expiry - now.Unix()),
		"scope":             joinScopes(granted),
	})
}

// ownSubject reads a subject token this deployment issued, and refuses one that does
// not still stand. RFC 8693 §2.2.2 is a MUST on the code: "if either the subject_token or
// actor_token are invalid for any reason, or are unacceptable based on policy", the
// error is invalid_request.
func (s *Server) ownSubject(w http.ResponseWriter, r *http.Request, c *clients.Client,
	ex oauth.ExchangeRequest) (*tokens.AccessTokenClaims, bool) {

	ctx := r.Context()
	// Verified first. Everything downstream reasons about what this token
	// actually says, not what the request claims about it.
	subject, err := s.verifyPresented(ctx, s.acceptedIssuers(ctx), ex.SubjectToken)
	if err != nil {
		s.log.InfoContext(ctx, "token exchange: subject token rejected", "err", err,
			"caller", c.ClientID, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "the subject token is not valid", Status: http.StatusBadRequest})
		return nil, false
	}
	if s.issuanceOnly(subject) {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "the subject token is good for issuing a credential and nothing else",
			Status:      http.StatusBadRequest})
		return nil, false
	}

	// A bound subject token may only be exchanged by whoever holds its key.
	// Without this the token endpoint is the one door where possession alone
	// suffices, and an attacker only needs the weakest door.
	if berr := s.requireSubjectTokenBinding(r, subject); berr != nil {
		s.log.InfoContext(ctx, "token exchange: subject token binding not proved", "err", berr,
			"caller", c.ClientID, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_dpop_proof",
			Description: berr.Error(), Status: http.StatusBadRequest})
		return nil, false
	}

	// A revoked or signed-out token must not be exchangeable. Otherwise
	// exchange becomes a way to launder a dead credential into a live one --
	// the token the user revoked yesterday still produces working tokens today.
	if terr := s.exchangeRefusal(ctx, subject, "subject", "invalid_request"); terr != nil {
		writeTokenError(w, terr)
		return nil, false
	}

	if c.ExchangeRequiresAudienceMatch &&
		subject.ClientID != c.ClientID && !audienceIncludes(subject.Audience, c.ClientID) {
		s.log.InfoContext(ctx, "token exchange: caller is neither the holder nor in the subject token's audience",
			"caller", c.ClientID, "token_client", subject.ClientID,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "this client may only exchange subject tokens it holds or " +
				"is named in the audience of",
			Status: http.StatusBadRequest})
		return nil, false
	}
	return subject, true
}

// subjectTokenIsForeign reports a JWT naming an issuer that is not this deployment. The
// issuer is read unverified, to choose the path and nothing else, and an access token by
// that name is not one: what a token that is opaque to us means is its issuer's to say.
func (s *Server) subjectTokenIsForeign(ctx context.Context, ex oauth.ExchangeRequest) bool {
	if ex.SubjectTokenType != oauth.TokenTypeJWT {
		return false
	}
	issuer, err := oauth.PeekAssertionIssuer(ex.SubjectToken)
	return err == nil && !slices.Contains(s.acceptedIssuers(ctx), issuer)
}

// foreignSubject reads a subject token from a registered issuer (8.32), as the jwt-bearer
// grant reads an assertion: the same pairing of client and issuer, the same claims, the same
// one sentence for every refusal. What it speaks for is the local account it is linked to,
// and its ceiling is the calling client's registered scope: a `scope` it carries means
// whatever that issuer meant by it, and there is no session behind it to end.
func (s *Server) foreignSubject(ctx context.Context, w http.ResponseWriter, c *clients.Client,
	ex oauth.ExchangeRequest) (*tokens.AccessTokenClaims, *assertionStatement, bool) {

	// Whether this client may exchange at all, before anybody's keys are fetched for it.
	if _, _, terr := oauth.ValidateExchange(ex, c.Type == "confidential", c.MayExchange, c.ExchangeAudiences,
		c.ClientID, c.Scopes); terr != nil {
		writeTokenError(w, terr)
		return nil, nil, false
	}
	statement, ok := s.readAssertion(ctx, w, c, ex.SubjectToken, "invalid_request")
	if !ok {
		return nil, nil, false
	}
	if s.assertionConsentRefused(ctx, w, c, statement, "invalid_request") {
		return nil, nil, false
	}
	// Who it says may act, and who has acted, hold wherever it was issued.
	var carried struct {
		Act    *tokens.Actor  `json:"act"`
		MayAct map[string]any `json:"may_act"`
	}
	if err := json.Unmarshal(statement.payload, &carried); err != nil {
		s.log.InfoContext(ctx, "token exchange: unreadable act or may_act", "provider", statement.provider.Slug,
			"err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request", Description: assertionRefused,
			Status: http.StatusBadRequest})
		return nil, nil, false
	}
	return &tokens.AccessTokenClaims{Subject: statement.userID, Expiry: statement.claims.Expiry,
		Scope: joinScopes(c.Scopes), Act: carried.Act, MayAct: carried.MayAct}, statement, true
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
	return oidc.PathAuthorize + "?" + consumeReauthPrompt(authzQuery)
}

// consumeReauthPrompt drops the prompt values that this sign-in has just
// satisfied.
//
// `prompt=login` is unconditional at the authorization endpoint: SessionSufficient
// returns StepUpForced for it however fresh the session is, which is right on the
// way in and fatal on the way back. Replaying the query verbatim re-asks for a
// re-authentication that has this instant been performed, so the sign-in form is
// rendered again, and again -- an infinite loop in which no correct password ever
// completes the request. `prompt=select_account` loops for the same reason.
//
// It is safe to consume them here and only here. This runs on the single path
// where the session has already been committed and the login audited, and the
// query itself arrives from the SIGNED pending token rather than from the
// browser, so neither the marker nor the moment can be forged by a caller who
// did not actually authenticate.
//
// Everything else in `prompt` survives. `consent` in particular must: a client
// asking for `prompt=login consent` wants both, and answering only the first
// would grant scopes the person was never shown.
func consumeReauthPrompt(authzQuery string) string {
	return consumePrompt(authzQuery, oauth.PromptLogin, oauth.PromptSelectAccount)
}

// consumePrompt removes prompt values that have just been satisfied.
//
// Shared by the two resume paths because they have the same shape and the same
// failure. Each `prompt` value is unconditional at the authorization endpoint --
// that is what makes it a prompt rather than a preference -- so replaying the
// query verbatim asks again for whatever was just done, and the browser bounces
// between the same two pages for ever.
//
// Safe on both paths and nowhere else: each runs only after the thing it
// consumes has actually happened and been committed, and the query arrives from
// server-held state rather than from the browser.
func consumePrompt(authzQuery string, consumed ...string) string {
	values, err := url.ParseQuery(authzQuery)
	if err != nil || values.Get("prompt") == "" {
		return authzQuery
	}
	drop := make(map[string]bool, len(consumed))
	for _, c := range consumed {
		drop[c] = true
	}
	var kept []string
	for _, p := range strings.Fields(values.Get("prompt")) {
		if !drop[p] {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		values.Del("prompt")
	} else {
		values.Set("prompt", strings.Join(kept, " "))
	}
	return values.Encode()
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

// samlStepUpQuery is what a SAML request's demand for a second factor looks like to
// the sign-in flow, which reads it as an authorization request's: the flow has one
// condition for this, and SAML has no parked query of its own to answer it from.
const samlStepUpQuery = "acr_values=2"

// parkLoginForMFA parks like parkLogin and says a second factor is wanted.
func parkLoginForMFA(dest string) string {
	return "/login?authz=" + url.QueryEscape(url.Values{"return": {dest}, "acr_values": {"2"}}.Encode())
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
	sid, _, err := store.ResolveSessionCookie(ctx, s.db, store.HashToken(cookie), s.instanceID)
	if err != nil || sid == "" {
		return "", "", ""
	}
	_ = s.db.QueryRow(ctx,
		`SELECT user_id::text, org_id::text FROM core.sessions WHERE sid = $1`, sid).
		Scan(&userID, &orgID)
	return sid, userID, orgID
}

// captchaResponse reads whichever field the configured widget submits.
//
// The three providers use three different names for the same value, and a
// deployment that switches provider should not have to change anything here. A
// Siteverify widget names its own, and that one is read alone: a form field the
// service never set is nothing it was asked about.
func (s *Server) captchaResponse(r *http.Request) string {
	if field := s.captcha.Widget().ResponseField; field != "" {
		return r.PostForm.Get(field)
	}
	for _, f := range []string{
		"cf-turnstile-response",
		"h-captcha-response",
		"g-recaptcha-response",
	} {
		if v := r.PostForm.Get(f); v != "" {
			return v
		}
	}
	return ""
}
