package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// reported remembers which documents have already had their inert conditions
	// reported, so a thirty-second reload does not repeat the message forever.
	reportedMu sync.Mutex
	reported   map[string]bool
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
		s.reportInertConditions(orgID, doc, f)
		loaded[orgID] = f
	}

	s.flows.mu.Lock()
	s.flows.byOrg = loaded
	s.flows.loadedAt = time.Now()
	s.flows.everLoaded = true
	s.flows.mu.Unlock()
}

// signInFacts answers the conditions a flow can branch on, reading the database
// only for the ones a given flow actually mentions.
//
// # Why this is lazy
//
// The obvious version evaluates every condition up front and hands back a map.
// It is three queries, and the code it replaced ran one -- so every sign-in in
// the product would have paid for two lookups that most flows never consult. The
// built-in flow does branch on all three, but a flow of `password -> session`
// branches on none, and it should cost nothing to have asked.
//
// flow.Conditions() reports exactly what a file mentions, so the queries can be
// driven from the file rather than from the list of things that are knowable.
//
// # Read through the caller's handle
//
// Which during completeSignIn is the open TRANSACTION, not the pool. That is not
// a detail: an answered prompt is written in that transaction and not yet
// committed, so reading the pool would report it still pending, ask it again, and
// come back again -- an infinite loop that locks out every user, appearing only
// once a prompt exists. The fixed sequence carried the same requirement and the
// same comment; moving the reads here moves the trap with them.
//
// # A failed read yields false
//
// Every condition here gates an ADDITIONAL step, so false is the value that lets
// somebody sign in, and a database hiccup that locks out a deployment is worse
// than one that skips a prompt. The one place that reasoning does not hold --
// where false would weaken the journey rather than shorten it -- is the mfa
// stage, and it is handled at the stage rather than here.
type signInFacts struct {
	s      *Server
	ctx    context.Context
	db     signInReader
	orgID  string
	userID string

	promptsOnce bool
	prompts     []prompts.Prompt

	// known memoises every answer, and carries the ones the caller decided
	// before the walk began.
	known map[string]bool

	// changeReason is the message the password-change stage shows, captured on
	// the way past so the stage does not repeat the query that produced it.
	changeKnown  bool
	changeReason string
}

// Holds answers one condition, querying only if asked and only once.
//
// This is the whole reason signInFacts is an Evaluator rather than a map. The
// eager version evaluated every condition the FILE mentioned; the built-in file
// mentions four, so a plain password sign-in that reaches none of the branches
// still paid three round trips -- and it paid them twice, once for the mfa
// decision and once inside the transaction. Six queries where the fixed sequence
// it replaced ran three.
//
// Asked on demand, the walker only ever enquires about conditions guarding
// stages it actually reaches, and memoisation makes the second walk free.
func (f *signInFacts) Holds(name string) bool {
	if v, ok := f.known[name]; ok {
		return v
	}
	var v bool
	switch flow.Condition(name) {
	case flow.CondHasSecondFactor:
		enrolled, err := store.HasSecondFactor(f.ctx, f.db, f.userID)
		if err != nil {
			f.s.log.Error("checking second factor", "err", err)
		}
		v = enrolled
	case flow.CondPromptsPending:
		v = len(f.pendingPrompts()) > 0
	case flow.CondPasswordChangeRequired:
		must, reason, err := store.PasswordChangeRequired(f.ctx, f.db, f.userID)
		if err != nil {
			f.s.log.Error("checking whether a password change is required", "err", err)
		}
		v, f.changeReason = must, reason
		f.changeKnown = true
	default:
		// A condition this path does not answer: either it is decided earlier
		// (captcha, at the form) or the signal is not wired into sign-in yet
		// (device posture, risk, network). False, so the stage it guards is
		// skipped.
		//
		// NOT logged here. This runs on every sign-in, and the built-in file
		// itself mentions captcha_required -- so a warning here fired on every
		// successful login of every deployment, about the default configuration.
		// The same information is reported once at load, by
		// reportInertConditions.
		v = false
	}
	if f.known == nil {
		f.known = map[string]bool{}
	}
	f.known[name] = v
	return v
}

// setKnown records a condition the caller has already decided.
func (f *signInFacts) setKnown(c flow.Condition, v bool) {
	if f.known == nil {
		f.known = map[string]bool{}
	}
	f.known[string(c)] = v
}

// pendingPrompts reads once and remembers, because the condition and the stage
// both need it.
func (f *signInFacts) pendingPrompts() []prompts.Prompt {
	if f.promptsOnce {
		return f.prompts
	}
	f.promptsOnce = true
	ps, err := store.PendingPrompts(f.ctx, f.db, f.orgID, f.userID)
	if err != nil {
		f.s.log.Error("reading prompts", "err", err)
		return nil
	}
	f.prompts = ps
	return ps
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

	facts := &signInFacts{s: s, ctx: ctx, db: tx, orgID: orgID, userID: userID}
	facts.setKnown(flow.CondClientRequiresMFA, clientRequiresMFA(authzQuery))
	// Settled at the sign-in form, before the flow is walked. Recording it as
	// known keeps the walker from treating it as an unanswerable condition.
	facts.setKnown(flow.CondCaptchaRequired, false)

	c := fl.Cursor()
	for {
		stage, ok := c.Next(facts)
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
			pending := facts.pendingPrompts()
			if len(pending) == 0 {
				// The stage is unconditional in this file but nothing is
				// outstanding. Skipping is right: a prompt with no question is not
				// a step, and holding the sign-in for one would be a dead end.
				continue
			}
			s.beginPrompt(w, r, userID, orgID, amr, authzQuery, pending[0])
			return decisionHandled

		case flow.StagePasswordChange:
			// Reuses the answer from the condition if the walker already asked --
			// which it did whenever the stage carries `when:
			// password_change_required`, as the built-in flow does. Only an
			// UNCONDITIONAL password_change stage pays for a query here.
			if !facts.changeKnown {
				facts.Holds(string(flow.CondPasswordChangeRequired))
			}
			if !facts.known[string(flow.CondPasswordChangeRequired)] {
				continue
			}
			reason := facts.changeReason
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
	facts := &signInFacts{s: s, ctx: ctx, db: db, orgID: orgID, userID: userID}
	facts.setKnown(flow.CondClientRequiresMFA, clientRequiresMFA(authzQuery))
	facts.setKnown(flow.CondCaptchaRequired, false)

	if hasSecondFactorAMR(amr) {
		// Already satisfied, so no lookup is needed to answer the question asked.
		return false, true
	}

	// WillRun rather than a walk: it evaluates the conditions of the mfa stages
	// and nothing else. Walking instead cost three queries on the built-in flow
	// -- the mfa condition, then the prompt and password-change conditions the
	// walker passed on its way to the end after the mfa stage was skipped -- to
	// answer a question neither of those bears on.
	if !fl.WillRun(flow.StageMFA, facts) {
		return false, facts.known[string(flow.CondHasSecondFactor)]
	}
	return true, facts.Holds(string(flow.CondHasSecondFactor))
}

// hasSecondFactorAMR reports whether the factors already proved satisfy an mfa
// stage.
//
// Delegated to oauth.ACRFromAMR rather than deciding here, and that is not
// tidiness. ACRFromAMR is what the SESSION's acr claim is computed from, so
// answering this any other way lets the sequencer and the session disagree about
// whether a sign-in was multi-factor -- one skipping a stage the other does not
// claim to have run.
//
// The hand-written version this replaces got a real case wrong. It counted
// AMRUserPresence, and a passkey used WITHOUT user verification reports
// ["user", "hwk"] (see amrForPasskey) -- so a single possession factor would
// have satisfied a stage that exists to demand a second one. ACRFromAMR already
// says why that is wrong, in a comment predating this package: "Presence alone
// is not a factor. A passkey that reports `user` without a hardware key or PIN
// proves someone touched a device, not which someone."
//
// Currently reachable only with amr=["pwd"], because the password path is the
// one caller. It was still wrong, and the moment another path is routed through
// the sequencer it would have become reachable and quiet.
func hasSecondFactorAMR(amr []string) bool {
	return oauth.ACRFromAMR(amr) == oauth.ACRMultiFactor
}

// evaluatedConditions are the conditions the sign-in path actually answers.
//
// The language defines more than this. That is deliberate -- a flow can be
// written against a signal before the signal is wired in -- but the gap has to be
// visible, or an operator configures a control that silently does nothing, which
// is the failure this codebase keeps finding in other systems.
var evaluatedConditions = map[flow.Condition]bool{
	flow.CondHasSecondFactor:        true,
	flow.CondPromptsPending:         true,
	flow.CondPasswordChangeRequired: true,
	flow.CondClientRequiresMFA:      true,
}

// conditionsDecidedElsewhere are answered before the flow is consulted, so
// reporting them as inert would be wrong -- the stage they guard did run, just
// not under the sequencer.
var conditionsDecidedElsewhere = map[flow.Condition]string{
	flow.CondCaptchaRequired: "decided at the sign-in form, before the flow is walked",
}

// reportInertConditions says once, at load, which parts of a flow do nothing.
//
// Once per distinct document, not once per reload: the cache refreshes every
// thirty seconds, and a message repeated twice a minute forever is noise rather
// than information.
func (s *Server) reportInertConditions(orgID, doc string, f *flow.File) {
	sum := sha256.Sum256([]byte(doc))
	key := orgID + ":" + hex.EncodeToString(sum[:8])

	s.flows.reportedMu.Lock()
	if s.flows.reported == nil {
		s.flows.reported = map[string]bool{}
	}
	already := s.flows.reported[key]
	s.flows.reported[key] = true
	s.flows.reportedMu.Unlock()
	if already {
		return
	}

	for i := range f.Flows {
		fl := &f.Flows[i]
		for _, c := range fl.Conditions() {
			cond := flow.Condition(c)
			if evaluatedConditions[cond] {
				continue
			}
			if why, ok := conditionsDecidedElsewhere[cond]; ok {
				s.log.Debug("flow condition is settled before the flow runs",
					"org_id", orgID, "flow", fl.Name, "condition", c, "reason", why)
				continue
			}
			s.log.Warn("this flow branches on a condition the sign-in path does not "+
				"evaluate; the stage it guards will never run. Remove it, or the "+
				"control it looks like is not one",
				"org_id", orgID, "flow", fl.Name, "condition", c)
		}
	}
}
