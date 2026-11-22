package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/oauth"
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
	// "Stay signed in", kept across the provider's round trip (5.11).
	s.noteRemember(w, r)
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

	provider, err := s.loadIdentityProvider(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrProviderUnknown) {
			s.federationRefusal(w, r, "federr.unavailable")
			return
		}
		s.log.ErrorContext(ctx, "loading identity provider", "slug", slug, "err", err)
		s.federationRefusal(w, r, "federr.unavailable")
		return
	}

	// The link intent is decided HERE, from the route and a live session, and
	// then stored server-side. It is never read from a parameter on the way
	// back -- a callback that could be told "this is a link" by adding a query
	// string would let an attacker attach their own external account to whoever
	// happened to be signed in.
	var linkUserID string
	if linking {
		sid, userID, orgID, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, parkLogin("/account/link/"+url.PathEscape(slug)), http.StatusSeeOther)
			return
		}
		// A linked external account signs in as this person from then on.
		if s.credentialChangeRefused(w, r, sid, "/account/link/"+url.PathEscape(slug), false) {
			return
		}
		if orgID != provider.OrgID {
			s.federationRefusal(w, r, "federr.unavailable")
			return
		}
		linkUserID = userID
	}

	nonce, err := randomToken()
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	verifier, err := randomToken()
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	state, binding, err := store.BeginFederatedLogin(ctx, tx, store.PendingLogin{
		ProviderID: provider.ID, OrgID: provider.OrgID,
		Nonce: nonce, CodeVerifier: verifier, LinkUserID: linkUserID,
		ReturnTo: s.validFederationReturn(r.URL.Query().Get("return")),
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		s.log.ErrorContext(ctx, "beginning federated login", "err", err)
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationRefusal(w, r, "federr.generic")
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
	http.Redirect(w, r, provider.AuthorizeURL(s.federationRedirectURI(slug), state, nonce, verifier,
		upstreamAsks(provider, s.validFederationReturn(r.URL.Query().Get("return")))), http.StatusSeeOther)
}

// upstreamAsks is what a sign-in brought here passes on to the provider it goes
// through, read from the request parked on the way. The stage still decides what was
// done: a provider that ignores an acr it is asked for gets no credit for one.
func upstreamAsks(provider *federation.Config, returnTo string) url.Values {
	parked, err := url.Parse(returnTo)
	if err != nil {
		return nil
	}
	request := parked.Query()
	return provider.Asks(request, oauth.RequiredRung(request.Get("acr_values"), "") >= 2)
}

func (s *Server) handleFederatedCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")
	q := r.URL.Query()

	if e := q.Get("error"); e != "" {
		// The provider refused. Shown as-is is wrong -- it is attacker-influenced
		// text -- so it is logged and the user gets a plain message.
		s.log.InfoContext(ctx, "external provider returned an error", "slug", slug, "error", e,
			"correlation_id", correlationID(ctx))
		s.federationRefusal(w, r, "federr.cancelled")
		return
	}

	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		s.federationRefusal(w, r, "federr.linkincomplete")
		return
	}

	c, err := r.Cookie(FederationCookieName)
	if err != nil || c.Value == "" {
		s.federationRefusal(w, r, "federr.otherbrowser")
		return
	}
	// Cleared immediately: it is single-use, and leaving it in place lets a
	// failed attempt be retried with a fresh state.
	s.clearFederationCookie(w)

	provider, err := s.loadIdentityProvider(ctx, slug)
	if err != nil {
		s.federationRefusal(w, r, "federr.unavailable")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	pending, err := store.ConsumeFederatedLogin(ctx, tx, state, c.Value)
	if err != nil {
		// Released before the error page: rendering takes a connection of its
		// own, and this is reached by anybody with a callback URL.
		_ = tx.Rollback(ctx)
		s.log.InfoContext(ctx, "federated callback refused", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationRefusal(w, r, federatedLoginRefusal(err))
		return
	}
	if pending.ProviderID != provider.ID {
		// The state belongs to a different provider. Continuing would exchange a
		// code at one provider using state issued for another.
		_ = tx.Rollback(ctx)
		s.federationRefusal(w, r, "federr.linkmismatch")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}

	hc := s.outboundClient(federationTimeout)
	tokens, err := provider.ExchangeCode(ctx, hc, s.federationRedirectURI(slug), code, pending.CodeVerifier)
	if err != nil {
		s.log.ErrorContext(ctx, "exchanging the external authorization code", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationRefusal(w, r, "federr.providerrefused")
		return
	}

	ext, err := provider.FetchIdentity(ctx, hc, tokens, pending.Nonce)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the external identity", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationRefusal(w, r, "federr.unverified")
		return
	}

	ext.Tokens = tokens
	s.completeFederation(w, r, provider, pending, ext)
}

func (s *Server) completeFederation(w http.ResponseWriter, r *http.Request,
	provider *federation.Config, pending *store.PendingLogin, ext federation.ExternalIdentity) {

	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Every refusal from here releases the transaction before rendering, which
	// takes a connection of its own.
	fail := func(key string) {
		_ = tx.Rollback(ctx)
		s.federationRefusal(w, r, key)
	}

	existing, err := store.FindFederatedIdentity(ctx, tx, provider.ID, ext.Subject)
	if err != nil {
		s.log.ErrorContext(ctx, "looking up the federated identity", "err", err)
		fail("federr.generic")
		return
	}

	// Looked up ONLY so the decision can refuse helpfully. It is never a reason
	// to link -- see internal/federation.
	var sameEmail string
	if existing == "" && ext.Email != "" {
		sameEmail, err = store.FindLocalUserByEmail(ctx, tx, provider.OrgID, ext.Email)
		if err != nil {
			s.log.ErrorContext(ctx, "checking for a local account with that address", "err", err)
			fail("federr.generic")
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
		fail("federr.notenough")
		return
	}
	// A sign-in confirmed by one account's emailed code ends as that account, read in
	// this transaction: a link moved or removed since the code was sent does not make
	// it sign in somebody else, or make anybody new.
	if pending.RequireUserID != "" && (decision.Outcome != federation.SignIn || decision.UserID != pending.RequireUserID) {
		s.log.InfoContext(ctx, "a confirmed sign-in no longer leads to the account it was confirmed by",
			"slug", provider.Slug, "outcome", decision.Outcome.String(), "correlation_id", correlationID(ctx))
		fail("federr.crossnoaccount")
		return
	}

	email, verified := federation.EmailToRecord(ext, provider.Policy)
	var userID string

	switch decision.Outcome {
	case federation.SignIn:
		userID = decision.UserID
		if err := store.LinkFederatedIdentity(ctx, tx, provider.ID, userID, provider.OrgID, ext, verified); err != nil {
			s.log.ErrorContext(ctx, "refreshing the federated identity", "err", err)
		}

	case federation.LinkToCurrentUser:
		userID = decision.UserID
		if err := store.LinkFederatedIdentity(ctx, tx, provider.ID, userID, provider.OrgID, ext, verified); err != nil {
			s.log.ErrorContext(ctx, "linking the external account", "err", err)
			fail("federr.linkedelsewhere")
			return
		}
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "federation.account_linked", OrgID: provider.OrgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"provider": provider.Slug, "verified_email": verified},
		}); aerr != nil {
			s.log.ErrorContext(ctx, "recording the link", "err", aerr)
		}
		// A new way into the account: the holder is told on every channel,
		// queued in the transaction the sign-in below commits, so a link that
		// does not hold tells nobody.
		if nerr := store.EnqueueAccountNotice(ctx, tx, store.AccountNotice{UserID: userID,
			Notice: store.NoticeProviderLinked, Provider: provider.DisplayName}); nerr != nil {
			s.log.ErrorContext(ctx, "queueing the link notice", "err", nerr)
			fail("federr.generic")
			return
		}

	case federation.CreateUser:
		ext.Email = email
		// A person made from an upstream is known here by the address it sent, and by
		// nothing else (store.CreateUserFromExternal). With none, the account could
		// only fail the database's own rule, which surfaced as "something went wrong".
		if strings.TrimSpace(email) == "" {
			_ = tx.Rollback(ctx)
			s.log.InfoContext(ctx, "an upstream sent no address to make an account with", "slug", provider.Slug,
				"correlation_id", correlationID(ctx))
			fail("federr.notenough")
			return
		}
		// The operator's provider, about somebody arriving from an identity provider
		// who has no account here. Through the transaction this callback holds.
		if reason, refused := s.userCreateRefused(ctx, tx, provider.OrgID, email, "federation"); refused {
			_ = tx.Rollback(ctx)
			s.recordFederatedRefusal(ctx, provider.OrgID, reason)
			fail("federr.nosignup")
			return
		}
		userID, err = store.CreateUserFromExternal(ctx, tx, provider.OrgID, ext)
		if err != nil {
			s.log.ErrorContext(ctx, "creating a user from an external identity", "err", err)
			fail("federr.generic")
			return
		}
		if err := store.LinkFederatedIdentity(ctx, tx, provider.ID, userID, provider.OrgID, ext, verified); err != nil {
			s.log.ErrorContext(ctx, "linking a newly created user", "err", err)
			fail("federr.generic")
			return
		}
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "federation.user_created", OrgID: provider.OrgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"provider": provider.Slug, "verified_email": verified},
		}); aerr != nil {
			s.log.ErrorContext(ctx, "recording the creation", "err", aerr)
		}

	default:
		// RequireLocalSignIn and Refuse. The reason is written for the person
		// reading it, and says what to do next.
		s.log.InfoContext(ctx, "external sign-in refused", "slug", provider.Slug,
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
		// The decision's English reason is for the log; the page says its key.
		s.log.InfoContext(ctx, "the reason given", "reason", decision.Reason, "correlation_id", correlationID(ctx))
		key := decision.Key
		if key == "" {
			key = "federr.generic"
		}
		fail(key)
		return
	}

	// What the provider handed over, if the operator asked to keep it. In this
	// transaction, so a sign-in that does not finish keeps nothing.
	if provider.StoreTokens && ext.Tokens != nil && userID != "" {
		if err := store.KeepFederatedTokens(ctx, tx, s.root, provider.ID, userID, provider.OrgID, *ext.Tokens); err != nil {
			s.log.ErrorContext(ctx, "keeping a provider's tokens", "err", err, "provider", provider.Slug,
				"correlation_id", correlationID(ctx))
			fail("federr.generic")
			return
		}
	}

	// The provider's mapped attributes, if the operator configured any.
	//
	// Advisory: a failure is logged and the sign-in continues. Somebody who just
	// authenticated correctly at their provider must not be refused entry
	// because an optional profile field could not be written -- the sign-in is
	// the security decision, and the attribute is decoration on it.
	//
	// Only claims the operator NAMED are read. Nothing else in the upstream
	// payload is decoded, so whoever runs that provider cannot write local state
	// by adding a claim to their tokens.
	if s.root != nil && userID != "" {
		applied, skipped, aerr := store.ApplyIDPAttributeMapping(ctx, tx, userID,
			provider.OrgID, provider.ID, ext.RawClaims, s.root)
		switch {
		case aerr != nil:
			s.log.ErrorContext(ctx, "applying the provider's attribute mapping", "err", aerr,
				"provider", provider.Slug, "correlation_id", correlationID(ctx))
		case skipped > 0:
			// Named, because a value silently dropped for being over-length is
			// a profile field an operator will otherwise chase for an afternoon.
			s.log.WarnContext(ctx, "some mapped attributes were refused",
				"provider", provider.Slug, "applied", applied, "skipped", skipped,
				"correlation_id", correlationID(ctx))
		}
	}

	// Not advisory, unlike the attributes: a group is what somebody may reach, and
	// a sign-in that could not take away a group the provider took away would keep
	// a privilege past its revocation.
	if userID != "" {
		joined, left, gerr := store.ApplyIdPGroups(ctx, tx, userID, provider.OrgID, provider.ID, ext.RawClaims)
		if gerr != nil {
			s.log.ErrorContext(ctx, "applying the provider's group mapping", "err", gerr,
				"provider", provider.Slug, "correlation_id", correlationID(ctx))
			fail("federr.generic")
			return
		}
		if joined+left > 0 {
			if aerr := audit.Write(ctx, tx, audit.Event{
				Type: "federation.groups_synced", OrgID: provider.OrgID, SubjectID: userID,
				CorrelationID: correlationID(ctx),
				Detail:        map[string]any{"provider": provider.Slug, "joined": joined, "left": left},
			}); aerr != nil {
				s.log.ErrorContext(ctx, "recording the group sync", "err", aerr)
			}
		}
	}

	// A link performed by an already signed-in user does NOT re-establish the
	// session -- they already have one, and minting a second would rotate their
	// sid for no reason.
	if decision.Outcome == federation.LinkToCurrentUser {
		if err := tx.Commit(ctx); err != nil {
			s.federationRefusal(w, r, "federr.generic")
			return
		}
		s.redirectAfterFederation(w, r, pending.ReturnTo, "/account")
		return
	}

	// amr says how they actually authenticated: at another provider, federated.
	// Claiming `pwd` here would tell relying parties a password was checked when
	// none was. `mfa` is added when the provider's verified ID token says it
	// authenticated with more than one factor in a way the operator chose to
	// trust (`idp trust-mfa`); without it, a flow's unconditional `mfa` stage
	// refused everybody who signs in through a provider and has no factor here.
	amr := []string{"fed"}
	if provider.UpstreamMFA(ext.RawClaims) {
		amr = append(amr, oauth.AMRMFA)
	}
	s.rememberUpstream(w, provider)
	s.completeSignIn(w, r.WithContext(withFederatedProvider(ctx, provider.Slug)), tx, userID, provider.OrgID, amr,
		federationAuthzQuery(pending.ReturnTo))
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

// federationRefusal renders a refusal, said in the reader's language: key names the
// message. It took the English sentence until November 2026, so every reader was
// shown English, and a store error's own text could reach the page.
//
// Through html/template, so a value in the message is escaped like any other.
func (s *Server) federationRefusal(w http.ResponseWriter, r *http.Request, key string) {
	s.renderPageStatus(w, r, http.StatusBadRequest, "federr", map[string]any{
		"Reason":        s.tr(r).Text(key),
		"CorrelationID": correlationID(r.Context()),
	})
}

// federatedLoginRefusal is the message for a sign-in an upstream provider sent back
// that store.ConsumeFederatedLogin would not take.
func federatedLoginRefusal(err error) string {
	switch {
	case errors.Is(err, store.ErrFederatedLoginOtherBrowser):
		return "federr.otherbrowser"
	case errors.Is(err, store.ErrFederatedLoginGone):
		return "federr.linkused"
	}
	return "federr.generic"
}
