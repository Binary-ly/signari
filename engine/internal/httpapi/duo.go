package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

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

// duoOutcome is what startDuo did.
type duoOutcome int

const (
	// duoNotUsed: no integration, no enrolment, or another factor the person
	// can present instead. The code prompt follows.
	duoNotUsed duoOutcome = iota
	// duoTookOver: the browser was sent to Duo, or a refusal was rendered.
	duoTookOver
	// duoFailedOpen: Duo is unreachable, the deployment fails open, and the
	// person has nothing else to present. The caller carries on WITHOUT a
	// second factor and records why (recordDuoFailOpen).
	//
	// Reported, not acted on. startDuo used to finish the sign-in itself, by
	// opening a transaction and calling completeSignIn -- whose mfa stage, still
	// unsatisfied by a password, called startDuo again, which failed open again
	// and opened another transaction, each level holding its own, until the pool
	// was empty and every sign-in in the deployment waited on a Duo outage.
	duoFailedOpen
)

// startDuo sends the browser to Duo, or reports why it cannot.
func (s *Server) startDuo(w http.ResponseWriter, r *http.Request,
	userID, orgID, authzQuery string, amr []string) duoOutcome {
	return s.actOnDuo(w, r, s.probeDuo(r.Context(), s.db, userID, orgID),
		userID, orgID, authzQuery, amr)
}

// duoProbe is everything startDuo has to know before it acts: whether Duo
// applies to this person, and whether it answers.
//
// Gathered apart from acting so the sign-in walk can ask through its own
// transaction and act only after releasing it. The walk has to know whether
// Duo fails open before it lets go, because then it carries on in that
// transaction; every other outcome takes over the response, and rendering,
// redirecting and auditing each take a connection of their own.
type duoProbe struct {
	kind        duoProbeKind
	cfg         *duo.Config
	username    string
	err         error // what made it broken, or the health check's error
	otherFactor bool
	otherErr    error
}

type duoProbeKind int

const (
	probeNotUsed duoProbeKind = iota
	probeBroken
	probeUnreachable
	probeReady
)

// failsOpen reports the one outcome that lets a sign-in carry on without a
// second factor.
func (p duoProbe) failsOpen() bool {
	return p.kind == probeUnreachable && p.cfg.FailOpen && p.otherErr == nil && !p.otherFactor
}

// probeDuo reads through q and asks Duo's health endpoint. It writes no
// response and records nothing.
func (s *Server) probeDuo(ctx context.Context, q dbReader, userID, orgID string) duoProbe {
	cfg, err := store.LoadDuoIntegration(ctx, q, orgID, s.cfg.Root,
		s.duoRedirectURI(), s.cfg.AllowInsecureIssuer)
	switch {
	case errors.Is(err, store.ErrNoDuoIntegration):
		return duoProbe{kind: probeNotUsed}
	case err != nil:
		return duoProbe{kind: probeBroken, err: err}
	}
	username, err := store.DuoUsernameFor(ctx, q, userID)
	if err != nil {
		// Not enrolled is ordinary: this organisation uses Duo and this person
		// has another factor. A real error is not, and is logged.
		if !errors.Is(err, store.ErrNoDuoEnrollment) {
			s.log.Error("reading the Duo enrollment", "err", err)
		}
		return duoProbe{kind: probeNotUsed}
	}
	p := duoProbe{kind: probeReady, cfg: cfg, username: username}
	if herr := cfg.HealthCheck(ctx); herr != nil {
		p.kind, p.err = probeUnreachable, herr
		if cfg.FailOpen {
			p.otherFactor, p.otherErr = store.HasFactorOtherThanDuo(ctx, q, userID)
		}
	}
	return p
}

// actOnDuo does what the probe found: sends the browser to Duo, renders the
// refusal, or reports that the code prompt follows or that Duo failed open.
func (s *Server) actOnDuo(w http.ResponseWriter, r *http.Request, p duoProbe,
	userID, orgID, authzQuery string, amr []string) duoOutcome {

	ctx := r.Context()
	cfg, duoUsername := p.cfg, p.username
	switch p.kind {
	case probeNotUsed:
		// Not configured, or not enrolled. The other factors follow.
		return duoNotUsed
	case probeBroken:
		err := p.err
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
		return duoTookOver
	}

	// Health checked BEFORE the redirect, by the probe.
	if p.kind == probeUnreachable {
		herr := p.err
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
			other, oerr := p.otherFactor, p.otherErr
			if oerr != nil {
				s.log.Error("checking for another factor", "err", oerr)
				s.federationError(w, r, "Something went wrong. Please try again.")
				return duoTookOver
			}
			if other {
				return duoNotUsed // the code prompt follows, and it can be answered
			}
			return duoFailedOpen
		}
		s.federationError(w, r,
			"The second-factor service is not responding, so this sign-in cannot be "+
				"completed. Please try again shortly.")
		return duoTookOver
	}

	state, err := duo.NewState()
	if err != nil {
		s.log.Error("generating Duo state", "err", err)
		return duoNotUsed
	}
	target, err := cfg.AuthorizeURL(state, duoUsername)
	if err != nil {
		s.log.Error("building the Duo authorization URL", "err", err)
		return duoNotUsed
	}

	if err := store.BeginDuoChallenge(ctx, s.db, store.DuoChallenge{
		State: state, UserID: userID, OrgID: orgID, DuoUsername: duoUsername,
		Authz: authzQuery, AMRSoFar: amr,
	}, duoChallengeTTL); err != nil {
		s.log.Error("recording the Duo challenge", "err", err)
		return duoNotUsed
	}

	http.Redirect(w, r, target, http.StatusSeeOther)
	return duoTookOver
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

// recordDuoFailOpen records, in the sign-in's own transaction, that the mfa
// stage was passed with no second factor at all.
//
// Reached only when Duo is unreachable, the deployment has set fail-open, and
// the person has no other factor to offer. The amr carries only what was
// actually proven -- a password -- so acr stays single-factor and every policy
// that asked for MFA still refuses. Fail-open decides whether the sign-in
// continues; it does not get to claim a factor that never happened.
//
// In the caller's transaction rather than one of its own, so the record lands
// with the session or not at all, and the sign-in holds one connection.
func (s *Server) recordDuoFailOpen(ctx context.Context, tx pgx.Tx, orgID, userID string) {
	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.skipped_duo_unavailable", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
	}); aerr != nil {
		s.log.Error("recording a fail-open sign-in", "err", aerr)
	}
	s.log.Warn("signing in WITHOUT a second factor because Duo is unreachable",
		"user_id", userID, "correlation_id", correlationID(ctx))
}

// mfaWaivedKey marks a request whose mfa stage was already answered by Duo
// failing open, so the walk that completeSignIn starts does not ask Duo again.
// Unexported and set in exactly one place (handleLoginPost); nothing outside
// this package can put it on a request.
type mfaWaivedKey struct{}

func withMFAWaivedByFailOpen(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), mfaWaivedKey{}, true))
}

func mfaWaivedByFailOpen(ctx context.Context) bool {
	v, _ := ctx.Value(mfaWaivedKey{}).(bool)
	return v
}
