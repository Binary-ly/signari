package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/store"
)

// Signing in with an external identity provider.
//
//	GET /login/with/{slug}      start
//	GET /login/callback/{slug}  the provider sends the browser back here
//	GET /account/link/{slug}    a signed-in user adds a provider
//
// The security work is split deliberately. internal/federation decides WHAT to
// do with an external identity and is a pure function, so every account-takeover
// scenario is a table entry rather than an integration test nobody writes. This
// file does the parts that need a request: binding the flow to one browser, and
// making sure the "link" intent cannot be supplied by the caller.

const (
	// FederationCookieName holds the browser-binding value. __Host- prefixed:
	// this cookie must never be sent to another host, and unlike the forward-auth
	// cookie there is no reason it would need to be.
	FederationCookieName = "__Host-signari_fed"

	federationTimeout = 15 * time.Second
)

func (s *Server) handleFederatedStart(w http.ResponseWriter, r *http.Request) {
	s.startFederation(w, r, false)
}

// handleFederatedLink is the ONLY entry point that can attach an external
// account to an existing local one, and it requires a live session.
func (s *Server) handleFederatedLink(w http.ResponseWriter, r *http.Request) {
	s.startFederation(w, r, true)
}

func (s *Server) startFederation(w http.ResponseWriter, r *http.Request, linking bool) {
	ctx := r.Context()
	slug := r.PathValue("slug")

	provider, err := store.LoadIdentityProvider(ctx, s.db, s.cfg.Root, slug)
	if err != nil {
		if errors.Is(err, store.ErrProviderUnknown) {
			s.federationError(w, r, "That sign-in method is not available.")
			return
		}
		s.log.Error("loading identity provider", "slug", slug, "err", err)
		s.federationError(w, r, "That sign-in method is not available.")
		return
	}

	// The link intent is decided HERE, from the route and a live session, and
	// then stored server-side. It is never read from a parameter on the way
	// back -- a callback that could be told "this is a link" by adding a query
	// string would let an attacker attach their own external account to whoever
	// happened to be signed in.
	var linkUserID string
	if linking {
		_, userID, orgID, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, parkLogin("/account/link/"+url.PathEscape(slug)), http.StatusSeeOther)
			return
		}
		if orgID != provider.OrgID {
			s.federationError(w, r, "That sign-in method is not available.")
			return
		}
		linkUserID = userID
	}

	nonce, err := randomToken()
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	verifier, err := randomToken()
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	state, binding, err := store.BeginFederatedLogin(ctx, tx, store.PendingLogin{
		ProviderID: provider.ID, OrgID: provider.OrgID,
		Nonce: nonce, CodeVerifier: verifier, LinkUserID: linkUserID,
		ReturnTo: s.validFederationReturn(r.URL.Query().Get("return")),
	})
	if err != nil {
		s.log.Error("beginning federated login", "err", err)
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: FederationCookieName, Value: binding, Path: "/",
		Secure: true, HttpOnly: true,
		// Lax, not Strict: the provider sends the browser back with a top-level
		// GET, and Strict would withhold the cookie on that navigation and break
		// every login.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, provider.AuthorizeURL(s.federationRedirectURI(slug), state, nonce, verifier),
		http.StatusSeeOther)
}

func (s *Server) handleFederatedCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")
	q := r.URL.Query()

	if e := q.Get("error"); e != "" {
		// The provider refused. Shown as-is is wrong -- it is attacker-influenced
		// text -- so it is logged and the user gets a plain message.
		s.log.Info("external provider returned an error", "slug", slug, "error", e,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, "The sign-in was cancelled or refused by the provider.")
		return
	}

	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		s.federationError(w, r, "That sign-in link is incomplete.")
		return
	}

	c, err := r.Cookie(FederationCookieName)
	if err != nil || c.Value == "" {
		s.federationError(w, r, "This sign-in was started in a different browser, or the "+
			"link is more than ten minutes old. Please try again.")
		return
	}
	// Cleared immediately: it is single-use, and leaving it in place lets a
	// failed attempt be retried with a fresh state.
	s.clearFederationCookie(w)

	provider, err := store.LoadIdentityProvider(ctx, s.db, s.cfg.Root, slug)
	if err != nil {
		s.federationError(w, r, "That sign-in method is not available.")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	pending, err := store.ConsumeFederatedLogin(ctx, tx, state, c.Value)
	if err != nil {
		s.log.Info("federated callback refused", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, err.Error())
		return
	}
	if pending.ProviderID != provider.ID {
		// The state belongs to a different provider. Continuing would exchange a
		// code at one provider using state issued for another.
		s.federationError(w, r, "That sign-in link does not match this provider.")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	hc := &http.Client{Timeout: federationTimeout}
	tokens, err := provider.ExchangeCode(ctx, hc, s.federationRedirectURI(slug), code, pending.CodeVerifier)
	if err != nil {
		s.log.Error("exchanging the external authorization code", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, "The provider would not complete the sign-in.")
		return
	}

	ext, err := provider.FetchIdentity(ctx, hc, tokens, pending.Nonce)
	if err != nil {
		s.log.Error("reading the external identity", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, "The provider's response could not be verified.")
		return
	}

	s.completeFederation(w, r, provider, pending, ext)
}

func (s *Server) completeFederation(w http.ResponseWriter, r *http.Request,
	provider *federation.Config, pending *store.PendingLogin, ext federation.ExternalIdentity) {

	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := store.FindFederatedIdentity(ctx, tx, provider.ID, ext.Subject)
	if err != nil {
		s.log.Error("looking up the federated identity", "err", err)
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	// Looked up ONLY so the decision can refuse helpfully. It is never a reason
	// to link -- see internal/federation.
	var sameEmail string
	if existing == "" && ext.Email != "" {
		sameEmail, err = store.FindLocalUserByEmail(ctx, tx, provider.OrgID, ext.Email)
		if err != nil {
			s.log.Error("checking for a local account with that address", "err", err)
			s.federationError(w, r, "Something went wrong. Please try again.")
			return
		}
	}

	decision, err := federation.Decide(ext, provider.Policy, federation.Context{
		ExistingLinkUserID:     existing,
		LocalUserWithSameEmail: sameEmail,
		CurrentUserID:          pending.LinkUserID,
		LinkRequested:          pending.LinkUserID != "",
	})
	if err != nil {
		s.federationError(w, r, "The provider did not return enough information to sign you in.")
		return
	}

	email, verified := federation.EmailToRecord(ext, provider.Policy)
	var userID string

	switch decision.Outcome {
	case federation.SignIn:
		userID = decision.UserID
		if err := store.LinkFederatedIdentity(ctx, tx, provider.ID, userID, provider.OrgID, ext, verified); err != nil {
			s.log.Error("refreshing the federated identity", "err", err)
		}

	case federation.LinkToCurrentUser:
		userID = decision.UserID
		if err := store.LinkFederatedIdentity(ctx, tx, provider.ID, userID, provider.OrgID, ext, verified); err != nil {
			s.log.Error("linking the external account", "err", err)
			s.federationError(w, r, "That account is already linked to someone else.")
			return
		}
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "federation.account_linked", OrgID: provider.OrgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"provider": provider.Slug, "verified_email": verified},
		}); aerr != nil {
			s.log.Error("recording the link", "err", aerr)
		}

	case federation.CreateUser:
		ext.Email = email
		userID, err = store.CreateUserFromExternal(ctx, tx, provider.OrgID, ext, verified)
		if err != nil {
			s.log.Error("creating a user from an external identity", "err", err)
			s.federationError(w, r, "Something went wrong. Please try again.")
			return
		}
		if err := store.LinkFederatedIdentity(ctx, tx, provider.ID, userID, provider.OrgID, ext, verified); err != nil {
			s.log.Error("linking a newly created user", "err", err)
			s.federationError(w, r, "Something went wrong. Please try again.")
			return
		}
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "federation.user_created", OrgID: provider.OrgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"provider": provider.Slug, "verified_email": verified},
		}); aerr != nil {
			s.log.Error("recording the creation", "err", aerr)
		}

	default:
		// RequireLocalSignIn and Refuse. The reason is written for the person
		// reading it, and says what to do next.
		s.log.Info("external sign-in refused", "slug", provider.Slug,
			"outcome", decision.Outcome.String(), "correlation_id", correlationID(ctx))
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "federation.refused", OrgID: provider.OrgID,
			CorrelationID: correlationID(ctx),
			Detail: map[string]any{
				"provider": provider.Slug, "outcome": decision.Outcome.String(),
			},
		}); aerr == nil {
			_ = tx.Commit(ctx)
		}
		s.federationError(w, r, decision.Reason)
		return
	}

	// A link performed by an already signed-in user does NOT re-establish the
	// session -- they already have one, and minting a second would rotate their
	// sid for no reason.
	if decision.Outcome == federation.LinkToCurrentUser {
		if err := tx.Commit(ctx); err != nil {
			s.federationError(w, r, "Something went wrong. Please try again.")
			return
		}
		s.redirectAfterFederation(w, r, pending.ReturnTo, "/account")
		return
	}

	// amr says how they actually authenticated: at another provider, federated.
	// Claiming `pwd` here would tell relying parties a password was checked when
	// none was.
	s.completeSignIn(w, r, tx, userID, provider.OrgID,
		[]string{"fed"}, federationAuthzQuery(pending.ReturnTo))
}

// federationAuthzQuery turns a stored return target into the parked-request
// form completeSignIn understands.
func federationAuthzQuery(returnTo string) string {
	if returnTo == "" {
		return ""
	}
	return url.Values{"return": {returnTo}}.Encode()
}

func (s *Server) redirectAfterFederation(w http.ResponseWriter, r *http.Request, returnTo, fallback string) {
	if returnTo == "" {
		returnTo = fallback
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// validFederationReturn keeps a return target on this origin.
func (s *Server) validFederationReturn(raw string) string {
	if raw == "" {
		return ""
	}
	if dest, ok := parkedReturn(url.Values{"return": {raw}}.Encode()); ok {
		return dest
	}
	return ""
}

func (s *Server) federationRedirectURI(slug string) string {
	return s.cfg.Issuer + "/login/callback/" + url.PathEscape(slug)
}

func (s *Server) clearFederationCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: FederationCookieName, Value: "", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// federationError renders a refusal.
//
// Through html/template, because the reason can include text derived from what
// a provider returned, and a message concatenated into HTML is a cross-site
// scripting hole on the sign-in page of an identity provider.
func (s *Server) federationError(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = federationErrorPage.Execute(w, map[string]string{
		"Reason":        reason,
		"CorrelationID": correlationID(r.Context()),
	})
}

var federationErrorPage = template.Must(template.New("federr").Parse(`<!DOCTYPE html>
<html><head><title>Sign-in could not be completed</title></head>
<body>
<h1>Sign-in could not be completed</h1>
<p>{{.Reason}}</p>
<p><a href="/login">Back to sign in</a></p>
<p>Reference: <code>{{.CorrelationID}}</code></p>
</body></html>`))
