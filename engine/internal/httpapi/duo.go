package httpapi

import (
	"errors"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/duo"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// Duo Universal Prompt as a second factor.
//
// The browser leaves this engine, answers a prompt at Duo, and comes back with
// a code. Two things make that safe, and both are easy to leave out:
//
//	the state       ties the answer to the browser that started the flow, and
//	                is single-use
//	the username    Duo says WHO it authenticated, and that has to be the
//	                person signing in here -- see internal/duo
//
// # Where the health check goes
//
// Before the redirect, never after. Once the browser has left, a Duo outage
// leaves the person on a page that will not load and leaves this engine unable
// to apply its own fail-open decision, because there is nothing left to decide.

// duoChallengeTTL bounds how long a prompt may be outstanding.
//
// Five minutes: Duo pushes time out well inside that, and a longer window is a
// longer period in which a captured code is worth something.
const duoChallengeTTL = 5 * time.Minute

// startDuo sends the browser to Duo, or reports why it cannot.
//
// Returns true when it has taken over the response.
func (s *Server) startDuo(w http.ResponseWriter, r *http.Request,
	userID, orgID, authzQuery string, amr []string) bool {

	ctx := r.Context()

	cfg, err := store.LoadDuoIntegration(ctx, s.db, orgID, s.cfg.Root,
		s.duoRedirectURI(), s.cfg.AllowInsecureIssuer)
	switch {
	case errors.Is(err, store.ErrNoDuoIntegration):
		// Not configured. Nothing to do, and the other factors follow.
		return false
	case err != nil:
		// Configured and BROKEN -- an unsealable secret, an override refused, a
		// database error. Falling through here was the first version's
		// behaviour and it is wrong: a user enrolled in Duo and nothing else is
		// then shown a code prompt no factor can answer, and the honest answer
		// "the second factor is misconfigured" never reaches anybody.
		//
		// Found by pointing the engine at a stand-in with the wrong environment
		// variable name: the log said what was wrong, and the sign-in showed a
		// form instead.
		s.log.Error("the Duo integration is configured but unusable", "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r,
			"Second-factor authentication is misconfigured on this server, so this "+
				"sign-in cannot be completed. Please tell an administrator.")
		return true
	}

	duoUsername, err := store.DuoUsernameFor(ctx, s.db, userID)
	if err != nil {
		// Not enrolled is ordinary: this organisation uses Duo and this person
		// has another factor. A real error is not, and is logged.
		if !errors.Is(err, store.ErrNoDuoEnrollment) {
			s.log.Error("reading the Duo enrollment", "err", err)
		}
		return false
	}

	// Health check BEFORE the redirect.
	if herr := cfg.HealthCheck(ctx); herr != nil {
		s.log.Error("Duo is unreachable", "err", herr, "fail_open", cfg.FailOpen,
			"correlation_id", correlationID(ctx))
		s.auditDetached(ctx, audit.Event{
			Type: "mfa.duo_unavailable", OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"fail_open": cfg.FailOpen},
		})
		if cfg.FailOpen {
			// The deployment has chosen this, in a setting named FailOpen. It is
			// recorded as an event with its own type so "how often did we sign
			// people in without a second factor" is a question the audit trail
			// can answer.
			//
			// Returning false here alone was WRONG, and only running it showed
			// why: the caller then rendered a code prompt, and a user whose only
			// factor is Duo has nothing to type into it. Fail-open produced a
			// dead end with a 200 -- fail-closed, with a confusing page instead
			// of the honest message.
			//
			// So: if anything else can be presented, ask for that. It is a
			// working factor and it is strictly better than none. Only when
			// there is nothing else does fail-open actually mean sign them in.
			other, oerr := store.HasFactorOtherThanDuo(ctx, s.db, userID)
			if oerr != nil {
				s.log.Error("checking for another factor", "err", oerr)
				s.federationError(w, r, "Something went wrong. Please try again.")
				return true
			}
			if other {
				return false // the code prompt follows, and it can be answered
			}
			return s.completeAfterDuoFailOpen(w, r, userID, orgID, authzQuery, amr)
		}
		s.federationError(w, r,
			"The second-factor service is not responding, so this sign-in cannot be "+
				"completed. Please try again shortly.")
		return true
	}

	state, err := duo.NewState()
	if err != nil {
		s.log.Error("generating Duo state", "err", err)
		return false
	}
	target, err := cfg.AuthorizeURL(state, duoUsername)
	if err != nil {
		s.log.Error("building the Duo authorization URL", "err", err)
		return false
	}

	if err := store.BeginDuoChallenge(ctx, s.db, store.DuoChallenge{
		State: state, UserID: userID, OrgID: orgID, DuoUsername: duoUsername,
		Authz: authzQuery, AMRSoFar: amr,
	}, duoChallengeTTL); err != nil {
		s.log.Error("recording the Duo challenge", "err", err)
		return false
	}

	http.Redirect(w, r, target, http.StatusSeeOther)
	return true
}

// handleDuoCallback completes a Duo prompt.
func (s *Server) handleDuoCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("duo_code")
	if code == "" {
		// Older integrations receive it as `code`. Both are read; neither is
		// guessed at when both are absent.
		code = r.URL.Query().Get("code")
	}
	if state == "" || code == "" {
		s.federationError(w, r, "That sign-in could not be completed.")
		return
	}

	// Claimed exactly once. A replayed callback finds nothing.
	ch, err := store.ConsumeDuoChallenge(ctx, s.db, state)
	if err != nil {
		s.log.Info("no Duo challenge in progress", "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, "That sign-in has expired. Please start again.")
		return
	}

	cfg, err := store.LoadDuoIntegration(ctx, s.db, ch.OrgID, s.cfg.Root, s.duoRedirectURI(), s.cfg.AllowInsecureIssuer)
	if err != nil {
		s.log.Error("loading the Duo integration for a callback", "err", err)
		s.federationError(w, r, "That sign-in could not be completed.")
		return
	}

	// The username recorded when the challenge STARTED, not one from this
	// request. Duo's answer is checked against what we asked about, and a
	// request parameter would let the browser choose the question.
	res, err := cfg.Exchange(ctx, code, ch.DuoUsername)
	if err != nil {
		s.log.Warn("Duo refused or answered about somebody else", "err", err,
			"correlation_id", correlationID(ctx))
		s.auditDetached(ctx, audit.Event{
			Type: "mfa.duo_failed", OrgID: ch.OrgID, SubjectID: ch.UserID,
			CorrelationID: correlationID(ctx),
		})
		s.federationError(w, r, "That sign-in could not be completed.")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.duo_succeeded", OrgID: ch.OrgID, SubjectID: ch.UserID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"duo_username": res.Username, "factor": res.Factor, "device": res.Device,
		},
	}); aerr != nil {
		s.log.Error("recording the Duo result", "err", aerr)
	}

	// amr records what actually happened: the password proven before the
	// redirect, plus Duo. RFC 8176 has no "duo" value; "mfa" is the honest one
	// for a service that will not say which factor it used, and the audit event
	// above carries the detail.
	full := append(append([]string{}, ch.AMRSoFar...), oauth.AMRMFA)
	s.completeSignIn(w, r, tx, ch.UserID, ch.OrgID, full, ch.Authz)
}

// duoRedirectURI is where Duo sends the browser back.
//
// Derived from the issuer rather than stored: a stored copy of this
// deployment's own address is a second copy, and the copies drift.
func (s *Server) duoRedirectURI() string {
	return s.cfg.Issuer + "/login/duo/callback"
}

// completeAfterDuoFailOpen signs somebody in with no second factor at all.
//
// Reached only when Duo is unreachable, the deployment has set fail-open, and
// the person has no other factor to offer. The amr carries only what was
// actually proven -- a password -- so acr stays single-factor and every policy
// that asked for MFA still refuses. Fail-open decides whether the sign-in
// continues; it does not get to claim a factor that never happened.
func (s *Server) completeAfterDuoFailOpen(w http.ResponseWriter, r *http.Request,
	userID, orgID, authzQuery string, amr []string) bool {

	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return true
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.skipped_duo_unavailable", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
	}); aerr != nil {
		s.log.Error("recording a fail-open sign-in", "err", aerr)
	}
	s.log.Warn("signed in WITHOUT a second factor because Duo is unreachable",
		"user_id", userID, "correlation_id", correlationID(ctx))

	s.completeSignIn(w, r, tx, userID, orgID, amr, authzQuery)
	return true
}
