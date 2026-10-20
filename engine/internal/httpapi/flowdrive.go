package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
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
	// reported remembers which stored documents have already been reported as
	// refused, so a thirty-second reload does not repeat the message forever.
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
//
// q is what the first load of the process reads through: the caller's own
// transaction when it holds one, since loading from the pool there takes a
// second connection.
func (s *Server) flowFor(ctx context.Context, q dbReader, orgID string, on flow.Designation) *flow.Flow {
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
		s.reloadFlowsFrom(ctx, q)
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

func (s *Server) reloadFlows(ctx context.Context) { s.reloadFlowsFrom(ctx, s.db) }

// reloadFlowsFrom is reloadFlows reading through q, for the first load a
// sign-in walk makes while it holds its transaction.
func (s *Server) reloadFlowsFrom(ctx context.Context, q dbReader) {
	rows, err := q.Query(ctx, `SELECT org_id::text, document FROM core.sign_in_flows`)
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
			// Written straight to the table, bypassing `signari flow apply`, or
			// applied before a rule that now refuses it -- a condition no journey
			// evaluates, since 2.20. The PREVIOUS flow is kept rather than
			// dropped: dropping it falls back to the built-in journey, which is a
			// different journey than the operator believes is running. A process
			// that never loaded this document has no previous one and serves the
			// built-in flow; the log says which, and `signari doctor` reports it.
			s.flows.mu.RLock()
			prev := s.flows.byOrg[orgID]
			s.flows.mu.RUnlock()
			if prev != nil {
				loaded[orgID] = prev
			}
			if s.firstReport(orgID, doc) {
				serving := "the built-in flows"
				if prev != nil {
					serving = "the previous flow"
				}
				s.log.Error("the stored sign-in flow will not load; serving "+serving,
					"org_id", orgID, "err", perr)
			}
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
	// authzQuery is the parked authorization request, which answers
	// client_requires_mfa. Empty where there is none, as for a bind.
	authzQuery string
	// amr is what the sign-in proved so far, which answers the proved_by
	// conditions.
	amr []string

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
	// A condition with no evaluator reads false. Parse refuses a sign-in flow
	// that branches on one, except captcha_required guarding the captcha
	// stage, which the form has already settled; so false here is either that
	// or a stored document that bypassed Parse.
	var v bool
	if eval, ok := signInConditions[flow.Condition(name)]; ok {
		v = eval(f)
	}
	if f.known == nil {
		f.known = map[string]bool{}
	}
	f.known[name] = v
	return v
}

// signInConditions are the evaluators behind flow.Answered(flow.Authentication),
// and TestEveryConditionAFlowCanUseIsAnswered holds the two to the same set: a
// condition answered here and not there is refused at parse for no reason, and
// one listed there and not answered here reads false while the flow that names
// it believes it is guarded.
var signInConditions = map[flow.Condition]func(f *signInFacts) bool{
	// Which way the person came in, from amr; no query.
	flow.CondProvedByPassword:  func(f *signInFacts) bool { return primaryProof(f.amr) == flow.StagePassword },
	flow.CondProvedByPasskey:   func(f *signInFacts) bool { return primaryProof(f.amr) == flow.StagePasskey },
	flow.CondProvedByKerberos:  func(f *signInFacts) bool { return primaryProof(f.amr) == flow.StageKerberos },
	flow.CondProvedByFederated: func(f *signInFacts) bool { return primaryProof(f.amr) == flow.StageFederated },
	flow.CondHasSecondFactor: func(f *signInFacts) bool {
		enrolled, err := store.HasSecondFactor(f.ctx, f.db, f.userID)
		if err != nil {
			f.s.log.Error("checking second factor", "err", err)
		}
		return enrolled
	},
	flow.CondHasPasskey: func(f *signInFacts) bool {
		has, err := store.HasPasskey(f.ctx, f.db, f.userID)
		if err != nil {
			f.s.log.Error("checking for a passkey", "err", err)
		}
		return has
	},
	flow.CondPromptsPending: func(f *signInFacts) bool {
		return len(f.pendingPrompts()) > 0
	},
	flow.CondPasswordChangeRequired: func(f *signInFacts) bool {
		must, reason, err := store.PasswordChangeRequired(f.ctx, f.db, f.userID)
		if err != nil {
			f.s.log.Error("checking whether a password change is required", "err", err)
		}
		f.changeReason = reason
		f.changeKnown = true
		return must
	},
	flow.CondClientRequiresMFA: func(f *signInFacts) bool {
		return clientRequiresMFA(f.authzQuery) || f.authzClientFloorIsMFA()
	},
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
	fl := s.flowFor(ctx, tx, orgID, flow.Authentication)
	if fl == nil {
		// No flow at all, not even the built-in one. Fall through to the session:
		// the subject has already been proved by the time this is called, so
		// refusing here would lock out a deployment over a configuration read.
		s.log.Error("no authentication flow is available; issuing the session")
		return decisionSession
	}

	facts := &signInFacts{s: s, ctx: ctx, db: tx, orgID: orgID, userID: userID, authzQuery: authzQuery, amr: amr}
	// Settled at the sign-in form, before the flow is walked, which is why
	// Parse lets it guard nothing but the captcha stage.
	facts.setKnown(flow.CondCaptchaRequired, false)

	// Whether Duo already failed open for this sign-in -- on the password path,
	// before this walk began, or at an earlier mfa stage of this walk.
	waived := mfaWaivedByFailOpen(ctx)

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
			// The caller abandons the transaction on a denial, so it is released
			// here, before the refusal is recorded on a connection of its own.
			// Recording it first held two connections, which deadlocks the pool.
			_ = tx.Rollback(ctx)
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
			// The walk's transaction is abandoned once a stage takes the
			// response, and released before that stage renders.
			_ = tx.Rollback(ctx)
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
			_ = tx.Rollback(ctx)
			s.beginPasswordChange(w, r, userID, orgID, amr, authzQuery, reason)
			return decisionHandled

		case flow.StageEnrolMFA:
			// Somebody with a factor has nothing to enrol, whatever the stage's
			// condition said; somebody without one is held until they have one
			// (enrolmfa.go). It never replaces a factor.
			if facts.Holds(string(flow.CondHasSecondFactor)) {
				continue
			}
			_ = tx.Rollback(ctx)
			s.beginEnrolMFA(w, r, userID, orgID, amr, authzQuery)
			return decisionHandled

		case flow.StageMFA:
			// Acted on HERE, so the stage binds every way in.
			//
			// This used to be decided by the caller, and the reason it was not done
			// here was recorded in this spot: completeSignIn has ten callers, only
			// the password path checked, and acting on the stage would start
			// demanding a code from a Kerberos or federated user who happens to have
			// a factor enrolled. That was called "arguably an improvement" and
			// deferred as a separate decision. It has now been taken.
			//
			// What the old arrangement meant in practice: an operator who wrote an
			// unconditional `mfa` stage and enrolled passkeys believed the whole
			// deployment had MFA, while passkey, Kerberos, Duo, the federated
			// sources and the second password path at flow.go:2207 all reached a
			// session without consulting it. A control that binds one route out of
			// ten is not a control.
			if waived {
				// Duo failed open earlier in this sign-in, and that was recorded.
				// Asking again would ask Duo again: see duoFailedOpen for the
				// recursion this used to be.
				continue
			}
			if hasSecondFactorAMR(amr) {
				// Already multi-factor, so the stage is satisfied by what has been
				// proved. Delegated to the same predicate the session's acr claim is
				// derived from, so the sequencer and the session cannot disagree
				// about whether this sign-in was multi-factor.
				continue
			}
			if !facts.Holds(string(flow.CondHasSecondFactor)) {
				// Demanded of everybody, and this account has nothing enrolled.
				// Refused rather than waved through: skipping would mean the control
				// holds for every account except the ones it was written to catch.
				// Same answer the password path gave before this moved. The caller
				// abandons the transaction on this path; released first, as above.
				_ = tx.Rollback(ctx)
				s.auditDetached(ctx, audit.Event{
					Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
					CorrelationID: correlationID(ctx),
					Detail:        map[string]any{"reason": "mfa_required_but_not_enrolled"},
				})
				s.clearPending(w)
				s.renderLogin(w, r, authzQuery,
					"This account needs a second factor before it can be used to sign in. "+
						"Please contact your administrator.")
				return decisionHandled
			}
			// Duo is asked through this transaction first, because one answer
			// keeps the walk in it: unreachable, failing open, and nothing else
			// to present. Then it is recorded here and the walk carries on to the
			// session, on a password alone and saying so.
			probe := s.probeDuo(ctx, tx, userID, orgID)
			if probe.failsOpen() {
				if aerr := audit.Write(ctx, tx, audit.Event{
					Type: "mfa.duo_unavailable", OrgID: orgID, SubjectID: userID,
					CorrelationID: correlationID(ctx),
					Detail:        map[string]any{"fail_open": true},
				}); aerr != nil {
					s.log.Error("recording Duo's absence", "err", aerr)
				}
				s.recordDuoFailOpen(ctx, tx, orgID, userID)
				waived = true
				continue
			}
			// Every other answer takes over the response: a redirect to Duo, a
			// refusal, or the code prompt, which sends codes and renders. The
			// walk's transaction is abandoned on these paths, so it is released
			// before any of them takes a connection of its own.
			_ = tx.Rollback(ctx)
			if s.challengeMFA(w, r, probe, userID, orgID, authzQuery, amr) {
				// The probe said Duo would not fail open, and challengeMFA acts on
				// that probe, so this is unreachable. Refused rather than signed
				// in if it ever is: the transaction is gone.
				s.renderLogin(w, r, authzQuery, "Something went wrong. Please try again.")
			}
			return decisionHandled

		default:
			if _, settled := signInSettledStages[stage]; settled {
				// A proving stage is passed only by the proof it names (2.49).
				// The walker passed every settled stage whatever amr held, so
				// `passkey, session` admitted a password and a one_of branch
				// chosen for a passkey holder let them in on a password.
				if _, proving := flow.ProofCondition(stage); proving && primaryProof(amr) != stage {
					_ = tx.Rollback(ctx)
					s.auditDetached(ctx, audit.Event{
						Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
						CorrelationID: correlationID(ctx),
						Detail: map[string]any{"reason": "flow_requires_another_proof", "flow": fl.Name,
							"required": string(stage), "presented": string(primaryProof(amr))},
					})
					return decisionDeny
				}
				continue
			}
			// Parse refuses a sign-in flow naming any other stage, so reaching
			// here needs a flow that bypassed it. Walking past was the old
			// answer, and it made `password, kerberos, session` a password
			// sign-in; refusing is the one that cannot be weaker than the file.
			_ = tx.Rollback(ctx)
			s.log.Error("the sign-in flow names a stage this engine does not run; refusing",
				"flow", fl.Name, "stage", stage, "correlation_id", correlationID(ctx))
			return decisionDeny
		}
	}
}

// signInSettledStages are the sign-in stages decided before the walk, by the
// page or endpoint that reached it, so the walker passes them. With the cases
// advanceSignIn acts on they are flow.Drivable(flow.Authentication), and
// TestEveryStageAFlowCanUseIsDriven holds the two to the same set.
var signInSettledStages = map[flow.StageName]string{
	flow.StageIdentify:  "the sign-in form, with the password",
	flow.StageCaptcha:   "the sign-in form, by the address's counter",
	flow.StagePassword:  "the sign-in form",
	flow.StagePasskey:   "the sign-in page's passkey ceremony",
	flow.StageKerberos:  "the Negotiate exchange",
	flow.StageFederated: "an upstream provider's callback",
	flow.StageConsent:   "the authorization endpoint, whenever a client asks for more than was granted",
}

// primaryProof is the proving stage the route that reached the walk settled,
// read from what it recorded in amr. Every route records one: the sign-in form
// and a migration's delegated check `pwd`, the passkey ceremony `user` with
// `hwk` or `swk`, Kerberos `krb`, a provider `fed`. What follows in amr is a
// second factor -- a security key there also reads `hwk` -- so the earlier
// routes are looked for first, and a passkey is what remains.
//
// It names a route, not a strength: whether a sign-in is multi-factor is
// oauth.IsMultiFactor's question alone.
func primaryProof(amr []string) flow.StageName {
	for _, r := range routeMarkers {
		for _, v := range r.values {
			if slices.Contains(amr, v) {
				return r.stage
			}
		}
	}
	return ""
}

// routeMarkers are the amr values each route records, in the order they are
// looked for.
var routeMarkers = []struct {
	stage  flow.StageName
	values []string
}{
	{flow.StageFederated, []string{"fed"}},
	{flow.StageKerberos, []string{"krb"}},
	{flow.StagePassword, []string{oauth.AMRPassword}},
	{flow.StagePasskey, []string{oauth.AMRUserPresence, oauth.AMRHardwareKey, "swk"}},
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

	// Called before the sign-in's transaction opens, so the first load of the
	// process, if this is it, reads from the pool as it always did.
	fl := s.flowFor(ctx, s.db, orgID, flow.Authentication)
	if fl == nil {
		return false, false
	}
	facts := &signInFacts{s: s, ctx: ctx, db: db, orgID: orgID, userID: userID, authzQuery: authzQuery, amr: amr}
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

// BindDemandsMFA reports whether the sign-in flow would ask this person for a
// second factor after a password, for the protocols that can carry nothing
// else (LDAPAuthenticator.WithMFAGate).
//
// Not FlowDemandsMFA, because that one treats a failed enrolment lookup as "no
// factor" -- harmless on the browser path, where completeSignIn asks again
// inside its transaction, and a bypass here, where nothing asks again. The
// lookup is made first and its error returned, and the caller refuses on it.
func (s *Server) BindDemandsMFA(ctx context.Context, orgID, userID string) (bool, error) {
	enrolled, err := store.HasSecondFactor(ctx, s.db, userID)
	if err != nil {
		return false, err
	}
	fl := s.flowFor(ctx, s.db, orgID, flow.Authentication)
	if fl == nil {
		return enrolled, nil
	}
	facts := &signInFacts{s: s, ctx: ctx, db: s.db, orgID: orgID, userID: userID}
	facts.setKnown(flow.CondHasSecondFactor, enrolled)
	// No relying party asked for anything: a bind has no authorization request.
	facts.setKnown(flow.CondClientRequiresMFA, false)
	facts.setKnown(flow.CondCaptchaRequired, false)
	return fl.WillRun(flow.StageMFA, facts), nil
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
// It was unreachable while the password path was the one caller, and became
// reachable once every caller walked the sequencer. A federated sign-in reaches
// it as ["fed", "mfa"] when the provider's MFA is trusted (`idp trust-mfa`).
func hasSecondFactorAMR(amr []string) bool {
	return oauth.IsMultiFactor(amr)
}

// firstReport reports whether this organisation's document has not been
// reported as refused before.
//
// Once per distinct document, not once per reload: the cache refreshes every
// thirty seconds, and a message repeated twice a minute forever is noise rather
// than information.
func (s *Server) firstReport(orgID, doc string) bool {
	sum := sha256.Sum256([]byte(doc))
	key := orgID + ":" + hex.EncodeToString(sum[:8])

	s.flows.reportedMu.Lock()
	defer s.flows.reportedMu.Unlock()
	if s.flows.reported == nil {
		s.flows.reported = map[string]bool{}
	}
	already := s.flows.reported[key]
	s.flows.reported[key] = true
	return !already
}
