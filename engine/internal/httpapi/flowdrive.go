package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/store"
)


// flowRefresh matches the policy cache. A flow change should be live within half
// a minute without every sign-in paying for a query.
const flowRefresh = 30 * time.Second

type flowCache struct {
	mu       sync.RWMutex
	byOrg    map[string]*flow.File
	loadedAt time.Time
	// everLoaded distinguishes "no organisation has a flow" from "nothing has
	// been read yet". Without it an empty map is ambiguous and the first sign-in
	// after a restart cannot tell whether to block on a read.
	everLoaded bool
	// refreshing is held by the one goroutine doing a background refresh, so a
	// hundred concurrent sign-ins produce one query rather than a hundred.
	refreshing sync.Mutex
	inFlight   bool
}

func newFlowCache() *flowCache { return &flowCache{byOrg: map[string]*flow.File{}} }

// flowFor returns the authentication flow in force for an organisation.
//
// Falls back to the built-in flow, which reproduces the journey the server ran
// when the sequence was fixed Go. A deployment that has never heard of flow
// files gets exactly what it had before.
// # Why a stale read is served rather than a fresh one
//
// This is called from completeSignIn, which holds an OPEN TRANSACTION. A
// synchronous reload there takes a second pool connection while the first is
// still held -- and because loadedAt is shared, every concurrent sign-in sees the
// cache expire in the same instant. Under load that is every in-flight
// transaction simultaneously waiting for a connection that only another
// in-flight transaction can release: a deadlock, arriving on a thirty-second
// cycle, only under concurrency.
//
// So: block only when nothing has ever been read, which happens once per
// process. After that a stale entry is returned immediately and ONE goroutine
// refreshes in the background. The window is already thirty seconds wide by
// design; making it thirty seconds and a bit, rather than deadlocking, is not a
// trade worth agonising over.
func (s *Server) flowFor(ctx context.Context, orgID string, on flow.Designation) *flow.Flow {
	s.flows.mu.RLock()
	fresh := time.Since(s.flows.loadedAt) < flowRefresh
	everLoaded := s.flows.everLoaded
	f := s.flows.byOrg[orgID]
	s.flows.mu.RUnlock()

	switch {
	case !everLoaded:
		// Once per process. Serving the built-in flow here instead would mean the
		// first sign-ins after a restart silently ran a different journey than the
		// operator applied.
		s.reloadFlows(ctx)
		s.flows.mu.RLock()
		f = s.flows.byOrg[orgID]
		s.flows.mu.RUnlock()
	case !fresh:
		s.refreshFlowsInBackground()
	}
	if f != nil {
		if fl, ok := f.For(on); ok {
			return fl
		}
	}
	// The built-in file is embedded and covered by the package's own tests, so
	// this cannot fail in a released binary. If it somehow does, returning nil
	// makes the caller fall back to the fixed sequence rather than refusing to
	// sign anybody in.
	def, err := flow.Default()
	if err != nil {
		s.log.Error("the built-in flows did not load", "err", err)
		return nil
	}
	fl, ok := def.For(on)
	if !ok {
		return nil
	}
	return fl
}

// refreshFlowsInBackground reloads at most once at a time, detached from the
// caller's request.
//
// context.Background, not the request's: the request is about to finish, and a
// refresh cancelled by its completion would leave the cache stale forever while
// appearing to have been scheduled.
func (s *Server) refreshFlowsInBackground() {
	s.flows.refreshing.Lock()
	if s.flows.inFlight {
		s.flows.refreshing.Unlock()
		return
	}
	s.flows.inFlight = true
	s.flows.refreshing.Unlock()

	go func() {
		defer func() {
			s.flows.refreshing.Lock()
			s.flows.inFlight = false
			s.flows.refreshing.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.reloadFlows(ctx)
	}()
}

func (s *Server) reloadFlows(ctx context.Context) {
	rows, err := s.db.Query(ctx, `SELECT org_id::text, document FROM core.sign_in_flows`)
	if err != nil {
		s.log.Error("loading sign-in flows", "err", err)
		return
	}
	defer rows.Close()

	loaded := map[string]*flow.File{}
	for rows.Next() {
		var orgID, doc string
		if err := rows.Scan(&orgID, &doc); err != nil {
			continue
		}
		f, perr := flow.Parse([]byte(doc))
		if perr != nil {
			// Written straight to the table, bypassing `signari flow apply`. The
			// PREVIOUS flow is kept rather than dropped: dropping it falls back to
			// the built-in journey, which is a different journey than the operator
			// believes is running, changing under them without a word.
			s.log.Error("the stored sign-in flow will not load; keeping the previous one",
				"org_id", orgID, "err", perr)
			s.flows.mu.RLock()
			if prev := s.flows.byOrg[orgID]; prev != nil {
				loaded[orgID] = prev
			}
			s.flows.mu.RUnlock()
			continue
		}
		loaded[orgID] = f
	}

	s.flows.mu.Lock()
	s.flows.byOrg = loaded
	s.flows.loadedAt = time.Now()
	s.flows.everLoaded = true
	s.flows.mu.Unlock()
}

// signInState reads the conditions a flow can branch on.
//
// Read through the caller's handle -- which during completeSignIn is the open
// TRANSACTION, not the pool. That is not a detail: an answered prompt is written
// in that transaction and not yet committed, so reading the pool would report it
// still pending, ask it again, and loop forever. The fixed sequence had the same
// requirement and the same comment; moving the reads here moves the trap with
// them, so it is restated rather than assumed.
//
// A read that fails yields false rather than an error. Every condition here
// gates an ADDITIONAL step, so false is the value that lets somebody sign in --
// and a database hiccup that locks out a deployment is worse than one that skips
// a prompt. The two conditions where that reasoning does not hold, because false
// would weaken rather than shorten the journey, are handled at their stage: see
// the mfa case in nextSignInStage.
func (s *Server) signInState(ctx context.Context, db signInReader,
	orgID, userID string, clientWantsMFA bool) (flow.State, []prompts.Prompt) {

	st := flow.State{}
	var pending []prompts.Prompt

	if enrolled, err := store.HasSecondFactor(ctx, db, userID); err != nil {
		s.log.Error("checking second factor", "err", err)
	} else {
		st[string(flow.CondHasSecondFactor)] = enrolled
	}

	if ps, err := store.PendingPrompts(ctx, db, orgID, userID); err != nil {
		s.log.Error("reading prompts", "err", err)
	} else {
		pending = ps
		st[string(flow.CondPromptsPending)] = len(ps) > 0
	}

	if must, _, err := store.PasswordChangeRequired(ctx, db, userID); err != nil {
		s.log.Error("checking whether a password change is required", "err", err)
	} else {
		st[string(flow.CondPasswordChangeRequired)] = must
	}

	st[string(flow.CondClientRequiresMFA)] = clientWantsMFA
	return st, pending
}

// signInReader is what signInState reads through: the open transaction during
// completeSignIn, the pool elsewhere. Narrower than either, so the "read through
// the transaction" requirement above cannot be met by accident with a *pgxpool.Pool
// that happens to satisfy the same methods.
type signInReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// clientRequiresMFA reports whether the parked authorization request asked for
// multi-factor through acr_values.
//
// Derived from the request rather than stored on the client, because that is
// where OIDC Core puts it and because the same client legitimately wants
// different assurance for different operations. A client that always wants it
// sends it every time.
//
// This feeds the `client_requires_mfa` condition. Without it that condition
// would be a name a flow could branch on that was never true -- a control an
// operator configures and which does nothing, which is the failure this
// codebase keeps finding in other people's.
func clientRequiresMFA(authzQuery string) bool {
	if authzQuery == "" {
		return false
	}
	q, err := url.ParseQuery(strings.TrimPrefix(authzQuery, "?"))
	if err != nil {
		return false
	}
	for _, v := range oauth.ParseACRValues(q.Get("acr_values")) {
		if v == oauth.ACRMultiFactor || v == oauth.ACRPapeMultiFactor {
			return true
		}
	}
	return false
}

// signInDecision is what the sequencer concluded.
type signInDecision int

const (
	// decisionSession -- every stage is satisfied; issue the session.
	decisionSession signInDecision = iota
	// decisionHandled -- a stage took over the response.
	decisionHandled
	// decisionDeny -- the flow refuses this sign-in.
	decisionDeny
	// decisionDone -- the flow finished without issuing a session.
	decisionDone
)

// advanceSignIn walks the flow and acts on the first stage still outstanding.
//
// Stages that establish the subject are skipped: reaching here means one of them
// already ran, and the amr says which. Re-running a password stage after the
// password has been checked would ask for it twice.
func (s *Server) advanceSignIn(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	userID, orgID string, amr []string, authzQuery string) signInDecision {

	ctx := r.Context()
	fl := s.flowFor(ctx, orgID, flow.Authentication)
	if fl == nil {
		// No flow at all, not even the built-in one. Fall through to the session:
		// the subject has already been proved by the time this is called, so
		// refusing here would lock out a deployment over a configuration read.
		s.log.Error("no authentication flow is available; issuing the session")
		return decisionSession
	}

	st, pending := s.signInState(ctx, tx, orgID, userID, clientRequiresMFA(authzQuery))

	c := fl.Cursor()
	for {
		stage, ok := c.Next(st)
		if !ok {
			// The flow ran out of stages without reaching a terminal. Parse refuses
			// such a file, so this needs a file that bypassed it -- refuse rather
			// than guess, because the guess would be a session.
			s.log.Error("the sign-in flow ended without a terminal stage",
				"flow", fl.Name, "correlation_id", correlationID(ctx))
			return decisionDeny
		}

		switch stage {
		case flow.StageSession:
			return decisionSession

		case flow.StageDeny:
			s.auditDetached(ctx, audit.Event{
				Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
				CorrelationID: correlationID(ctx),
				Detail:        map[string]any{"reason": "flow_denied", "flow": fl.Name},
			})
			return decisionDeny

		case flow.StageDone:
			return decisionDone

		case flow.StagePrompt:
			if len(pending) == 0 {
				// The stage is unconditional in this file but nothing is
				// outstanding. Skipping is right: a prompt with no question is not
				// a step, and holding the sign-in for one would be a dead end.
				continue
			}
			s.beginPrompt(w, r, userID, orgID, amr, authzQuery, pending[0])
			return decisionHandled

		case flow.StagePasswordChange:
			must, reason, err := store.PasswordChangeRequired(ctx, tx, userID)
			if err != nil {
				s.log.Error("checking whether a password change is required", "err", err)
				continue
			}
			if !must {
				continue
			}
			if reason == "" {
				reason = "Your password needs to be changed before you continue."
			}
			s.beginPasswordChange(w, r, userID, orgID, amr, authzQuery, reason)
			return decisionHandled

		case flow.StageMFA:
			// Decided by the CALLER, before the transaction opens -- see
			// FlowDemandsMFA. Not here, and the reason is worth stating because the
			// obvious refactor is to move it here.
			//
			// completeSignIn has ten callers. Exactly one of them, the password
			// path, checks for a second factor today; passkey, Kerberos, Duo and
			// the federated sources go straight through. Acting on this stage here
			// would therefore start demanding a code from, say, a Kerberos user who
			// happens to have TOTP enrolled -- arguably an improvement, and
			// certainly not one to arrive as a side effect of moving the sequence
			// into a file. Whether the other nine paths should gate on a second
			// factor is a separate decision with its own consequences.
			continue

		default:
			// Every other stage either proved the subject before this point
			// (password, passkey, certificate, kerberos, federated, delegated),
			// or belongs to a different part of the request (captcha at the form,
			// consent at the authorization endpoint, identify in the same form as
			// the password). Nothing to do here.
			continue
		}
	}
}

// FlowDemandsMFA reports whether the flow puts an mfa stage in this sign-in's
// path, given what is already proved.
//
// Called before the session transaction opens, by the one path that gates on a
// second factor today. It replaces a hardcoded `if enrolled`, so the operator
// now controls the question -- `when: user_has_second_factor` for today's
// behaviour, `when: client_requires_mfa` to demand it only when a relying party
// asks, or unconditionally to require it of everybody.
//
// The second return value is the honest answer to "required, but this account
// has nothing enrolled". Carrying on would mean the control an operator
// configured does nothing for exactly the accounts that lack a factor; the
// caller refuses instead. The built-in flow writes `when:
// user_has_second_factor`, so it is unreachable unless somebody chose it.
func (s *Server) FlowDemandsMFA(ctx context.Context, db signInReader,
	orgID, userID, authzQuery string, amr []string) (demanded, enrolled bool) {

	fl := s.flowFor(ctx, orgID, flow.Authentication)
	if fl == nil {
		return false, false
	}
	st, _ := s.signInState(ctx, db, orgID, userID, clientRequiresMFA(authzQuery))
	enrolled = st[string(flow.CondHasSecondFactor)]

	if hasSecondFactorAMR(amr) {
		return false, enrolled
	}
	c := fl.Cursor()
	for {
		stage, ok := c.Next(st)
		if !ok {
			return false, enrolled
		}
		switch stage {
		case flow.StageMFA:
			return true, enrolled
		case flow.StageSession, flow.StageDeny, flow.StageDone:
			// Reached the end of the journey without an mfa stage.
			return false, enrolled
		}
	}
}

// hasSecondFactorAMR reports whether the factors already proved include one that
// satisfies an mfa stage.
//
// Read from the amr rather than from a flag, for the same reason acr is derived
// from it: the amr is the record of what actually happened, and anything else is
// a second opinion that can disagree with it.
func hasSecondFactorAMR(amr []string) bool {
	for _, m := range amr {
		switch m {
		case oauth.AMROTP, oauth.AMRMFA, oauth.AMRHardwareKey,
			oauth.AMRSMS, oauth.AMRUserPresence:
			return true
		}
	}
	return false
}
