package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// Account recovery over HTTP. The security properties live in internal/store;
// this is the surface, and it has two rules of its own.
//
// FIRST: THE RESPONSE NEVER REVEALS WHETHER AN ACCOUNT EXISTS. Same page, same
// status, same timing, whatever address is submitted. A recovery form that says
// "no such account" is a free account enumerator, and it is the most common way
// this endpoint leaks -- usually via a helpful error message someone added to
// improve the user experience.
//
// SECOND: EVERY REGISTERED CHANNEL IS NOTIFIED, not just the one used to
// request. The whole design assumes the requester may be an attacker holding one
// mailbox; telling only that mailbox would defeat it entirely.
//
// THIRD: REQUESTS ARE PACED. Each one writes a row, supersedes the link before
// it, and sends mail and possibly an SMS, and there was no limit at all. Anyone
// could fill a person's inbox, run up the SMS bill, and keep the victim's own
// link from ever working by superseding it every few seconds. A request over
// the pace does nothing (no row, no supersede, no message) and answers with the
// same page, so the limit is not an oracle either.
const (
	recoveryPerAccountMinute = 1 // and the earlier link stays valid
	recoveryPerAccountHour   = 5
	recoveryPerAddressLimit  = 20
	recoveryPerAddressWindow = time.Hour
)

// recoveryRequestFallback is the request half's plan when no recovery flow is
// configured.
var recoveryRequestFallback = []flow.StageName{flow.StageIdentify, flow.StageEmailOTP,
	flow.StagePasswordChange, flow.StageDone}

// recoveryOffered reports whether the sign-in page should link to recovery: not
// when the operator's recovery flow denies it, and not when it needs a stage
// this engine cannot drive, which would answer 501. Read under the default
// organisation, as the request itself is (see recoverflow.go).
func (s *Server) recoveryOffered(ctx context.Context) bool {
	if s.db == nil {
		return false // as loginOrg and externalProviders: a server with no store offers nothing
	}
	orgID, _ := s.defaultOrg(ctx)
	plan, unsupported, _ := s.recoveryPlan(ctx, orgID, flow.State{}, recoveryRequestFallback)
	return unsupported == "" && !recoveryDenied(plan)
}

// recoveryFacts answers the conditions a recovery flow may branch on:
// flow.Answered(flow.Recovery), which TestEveryConditionAFlowCanUseIsAnswered
// holds this to.
func (s *Server) recoveryFacts(ctx context.Context, remoteAddr string) flow.State {
	return flow.State{
		string(flow.CondCaptchaRequired): s.captcha.Required(ctx, remoteAddr),
	}
}

// handleRecoverGet shows the "forgot password" form.
func (s *Server) handleRecoverGet(w http.ResponseWriter, r *http.Request) {
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	s.renderPage(w, r, "recover", map[string]any{"CSRF": csrf, "CSRFField": csrfFormField})
}

// handleRecoverPost creates a request and notifies the account.
func (s *Server) handleRecoverPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	identifier := strings.TrimSpace(r.PostForm.Get("username"))

	// The operator's recovery flow governs this half: whether a challenge runs
	// before a row is written and mail is sent. Read under the default
	// organisation, never the account's -- see recoverflow.go for why that is a
	// security requirement and not a shortcut.
	orgID, _ := s.defaultOrg(ctx)
	plan, unsupported, flowName := s.recoveryPlan(ctx, orgID,
		s.recoveryFacts(ctx, r.RemoteAddr), recoveryRequestFallback)
	if unsupported != "" {
		s.refuseRecoveryStage(w, r, unsupported, flowName)
		return
	}
	if recoveryDenied(plan) {
		// An operator who has closed recovery. Refused plainly, and identically
		// for every identifier, because whether recovery is open is a property of
		// the deployment rather than of the account.
		writeError(w, http.StatusForbidden, "recovery_closed",
			"account recovery is not available here")
		return
	}

	for _, stage := range plan {
		if stage != flow.StageCaptcha {
			// identify is the form that has just been submitted; everything after it
			// belongs to the reset half, which runs when the link is followed.
			continue
		}
		// In the plan means required: the default stage carries `when:
		// captcha_required`, so Plan includes it exactly when a challenge is owed.
		if !s.recoverCaptcha(w, r) {
			return // the challenge failed; the form was re-rendered with a fresh one
		}
	}

	// The work happens regardless of whether the account exists, and the same
	// page is always returned. See the file comment. The address is paced
	// before anything is looked up, so a sweep across many addresses costs a
	// lookup only within its allowance.
	if identifier != "" && s.allowRecovery(ctx, "recover:ip:"+budgetIP(clientIP(r)),
		recoveryPerAddressLimit, recoveryPerAddressWindow) {
		if err := s.beginRecovery(ctx, identifier); err != nil {
			// Logged, never surfaced: the error text distinguishes "no such user"
			// from "SMTP is down", and only one of those is the caller's business.
			s.log.Error("beginning recovery", "err", err, "correlation_id", correlationID(ctx))
		}
	}

	s.renderPage(w, r, "sent", map[string]any{})
}

// beginRecovery does the work for an identifier that may not exist.
//
// Every account the name holds is sent its own link. Sign-in names are unique
// per organisation, so one address can hold accounts in several; this used to
// pick one of them at random, and the person reset whichever account the
// planner returned. The page answers the same whatever is found, so writing to
// each discloses nothing the address's owner does not already receive.
func (s *Server) beginRecovery(ctx context.Context, identifier string) error {
	found, err := s.lookupCredentials(ctx, identifier, "")
	if err != nil {
		return err
	}
	var first error
	for _, c := range found {
		if c.status != "active" {
			// Waiting for approval: a reset could sign nobody in, and the page
			// answers the same whatever is found.
			continue
		}
		// Paced per account, both windows charged, before the earlier request is
		// superseded: an account over the pace keeps the link it already has.
		minute := s.allowRecovery(ctx, "recover:user:min:"+c.userID, recoveryPerAccountMinute, time.Minute)
		hour := minute && s.allowRecovery(ctx, "recover:user:hour:"+c.userID, recoveryPerAccountHour, time.Hour)
		if !hour {
			continue
		}
		if err := s.beginRecoveryFor(ctx, c.userID, c.orgID); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// allowRecovery charges one request to a bucket and reports whether it was
// within the limit. A database error refuses: nothing is sent, and the person
// asks again, which is better than an unmetered window opened by a fault.
func (s *Server) allowRecovery(ctx context.Context, key string, limit int, window time.Duration) bool {
	res, err := store.AllowRate(ctx, s.db, key, limit, window)
	if err != nil {
		s.log.Error("checking the recovery pace", "err", err, "correlation_id", correlationID(ctx))
		return false
	}
	return res.Allowed
}

// beginRecoveryFor starts recovery for one account.
func (s *Server) beginRecoveryFor(ctx context.Context, userID, orgID string) error {
	token, tokenHash, err := newRecoveryToken()
	if err != nil {
		return err
	}
	cancelTok, cancelHash, err := newRecoveryToken()
	if err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// No waiver here: this path is reached by someone who proved only that they
	// can read an address. A proven second factor may waive the delay, and no
	// path proves one before recovery yet (5.12), so this is the only caller and
	// every reset waits it out.
	req, err := store.CreateRecoveryRequest(ctx, tx, userID, orgID,
		tokenHash, cancelHash, "", time.Now())
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "account.recovery_requested", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"effective_at": req.EffectiveAt.UTC().Format(time.RFC3339)},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Sent AFTER the commit. Emailing first would mean a rolled-back transaction
	// leaves a user holding a link that never worked -- alarming, and impossible
	// for support to explain.
	return s.notifyRecovery(ctx, userID, token, cancelTok, req.EffectiveAt)
}

// notifyRecovery tells every notification channel on the account.
//
// Fans out through notifyAccount (see notify.go), so the notice reaches the
// account email AND a verified SMS number when one exists -- the two independent
// channels NIST SP 800-63B-4 asks a CSP to support. The email carries the
// actionable links; the SMS is a short alert pointing at the email, because two
// long tokenised URLs do not belong in a 160-character message -- and alerting
// the independent channel is the point regardless of where the action lives.
func (s *Server) notifyRecovery(ctx context.Context, userID, token, cancelTok string, effective time.Time) error {
	wait := time.Until(effective).Round(time.Minute)

	// The account holder's language, not the requester's. The requester here may
	// be the attacker -- that is the whole reason this notice exists.
	tr := s.notifierFor(ctx, userID)
	data := map[string]any{
		"Wait":      wait.String(),
		"ResetURL":  fmt.Sprintf("%s/recover/reset?token=%s", s.cfg.Issuer, token),
		"CancelURL": fmt.Sprintf("%s/recover/cancel?token=%s", s.cfg.Issuer, cancelTok),
	}

	return s.notifyAccount(ctx, userID,
		tr.Text("mail.recovery.requested.subject"),
		tr.Text("mail.recovery.requested.body", data),
		tr.Text("sms.recovery.requested"))
}

// handleRecoverCancel kills a pending request. No sign-in required, by design:
// the person who needs it most is the one who cannot sign in.
func (s *Server) handleRecoverCancel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, hash, err := hashRecoveryToken(r.URL.Query().Get("token"))
	if err != nil {
		s.renderPage(w, r, "cancelled", map[string]any{})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	userID, cancelled, err := store.CancelRecovery(ctx, tx, hash)
	if err != nil {
		s.log.Error("cancelling recovery", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if cancelled {
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "account.recovery_cancelled", SubjectID: userID,
			CorrelationID: correlationID(ctx),
		}); err != nil {
			s.log.Error("auditing recovery cancellation", "err", err)
		}
		if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing recovery cancellation", "err", err)
		}
	}
	// Released before rendering, which takes a connection of its own.
	_ = tx.Rollback(ctx)

	// The same page either way. A cancel link is clicked from an email, sometimes
	// twice, sometimes by a scanner that prefetches it; "already cancelled" would
	// alarm someone who did exactly the right thing, and confirming a token was
	// real would help someone guessing.
	s.renderPage(w, r, "cancelled", map[string]any{})
}

// handleResetGet shows the new-password form once the delay has elapsed.
func (s *Server) handleResetGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_, hash, err := hashRecoveryToken(token)
	if err != nil {
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.invalid")})
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	req, lerr := s.lookupRecovery(r.Context(), tx, hash)
	// Released before anything is rendered. Rendering reads the brand from the
	// pool, and this page is reached with no account, no CSRF token and no
	// limit: a few dozen requests each holding one connection and waiting for
	// another stalled every endpoint that needs the database.
	_ = tx.Rollback(r.Context())
	csrf, cerr := s.csrfToken(w, r)
	if cerr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	if lerr != nil && !errors.Is(lerr, store.ErrRecoveryPending) {
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
		return
	}
	plan, unsupported, flowName := s.recoveryResetPlan(r.Context(), req.OrgID)
	if unsupported != "" {
		s.refuseRecoveryStage(w, r, unsupported, flowName)
		return
	}
	s.renderReset(w, r, req, token, csrf, errors.Is(lerr, store.ErrRecoveryPending), plan, "", "")
}

// recoveryResetFallback is the reset half's plan when no recovery flow is
// configured.
var recoveryResetFallback = []flow.StageName{flow.StageIdentify, flow.StageEmailOTP,
	flow.StagePasswordChange, flow.StageDone}

// recoveryResetPlan is the reset half's plan, under the organisation of the
// account the link names.
func (s *Server) recoveryResetPlan(ctx context.Context, orgID string) ([]flow.StageName, flow.StageName, string) {
	return s.recoveryPlan(ctx, orgID, flow.State{string(flow.CondCaptchaRequired): false}, recoveryResetFallback)
}

// renderReset shows what the link leads to now (5.12): the wait, with a second
// factor offered to skip it; a second factor the flow's mfa stage requires; or
// the new-password form.
//
// A second factor is offered only to whoever holds the link, which already
// proved the mailbox, so saying the account has one tells them nothing the
// account's own sign-in page would not. Email is never one of them: it is what
// the link came by.
func (s *Server) renderReset(w http.ResponseWriter, r *http.Request, req *store.RecoveryRequest,
	token, csrf string, pending bool, plan []flow.StageName, msg, notice string) {
	ctx := r.Context()
	factors, err := store.RecoveryFactorsOf(ctx, s.db, req.UserID)
	if err != nil {
		s.log.Error("reading the recovering person's second factors", "err", err)
	}
	data := map[string]any{"Token": token, "CSRF": csrf, "CSRFField": csrfFormField,
		"Error": msg, "Notice": notice, "SMS": factors.SMS}
	needFactor := planHasStage(plan, flow.StageMFA) && req.WaivedBy == ""
	switch {
	case pending:
		// Told exactly when, because "try again later" with no time is advice
		// nobody can act on.
		data["Pending"] = true
		data["When"] = req.EffectiveAt.UTC().Format("15:04 MST on 2 January")
		data["Wait"] = time.Until(req.EffectiveAt).Round(time.Minute).String()
		data["Factor"] = factors.Any()
	case needFactor && !factors.Any():
		data["Error"] = s.tr(r).T("error.reset.nofactor")
	case needFactor:
		data["Factor"], data["FactorRequired"] = true, true
	default:
		data["Ready"] = true
	}
	s.renderPage(w, r, "reset", data)
}

// handleResetFactor takes a second factor from whoever holds the link (5.12):
// a waiver of the delay, and the proof an mfa stage before the reset needs.
// The second-factor budget applies, keyed by the account, as at sign-in: the
// link holder is the one guessing.
func (s *Server) handleResetFactor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	token := r.PostForm.Get("token")
	_, hash, err := hashRecoveryToken(token)
	if err != nil {
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.invalid")})
		return
	}
	rtx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	req, lerr := s.lookupRecovery(ctx, rtx, hash)
	_ = rtx.Rollback(ctx)
	if lerr != nil && !errors.Is(lerr, store.ErrRecoveryPending) {
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
		return
	}
	pending := errors.Is(lerr, store.ErrRecoveryPending)
	plan, unsupported, flowName := s.recoveryResetPlan(ctx, req.OrgID)
	if unsupported != "" {
		s.refuseRecoveryStage(w, r, unsupported, flowName)
		return
	}
	csrf, cerr := s.csrfToken(w, r)
	if cerr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if r.PostForm.Get("send") == "sms" {
		s.sendSMSOTPIfEnrolled(ctx, req.UserID)
		s.renderReset(w, r, req, token, csrf, pending, plan, "", s.tr(r).Text("reset.factor.smssent"))
		return
	}

	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	if !s.allowSecondFactorAttempt(ctx, w, req.UserID, ip) {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	res, err := s.verifyCode(ctx, tx, req.UserID, strings.TrimSpace(r.PostForm.Get("code")), false)
	switch {
	case err != nil:
		_ = tx.Rollback(ctx)
		s.log.Error("verifying a second factor during recovery", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	case res.Replayed:
		_ = tx.Rollback(ctx)
		s.renderReset(w, r, req, token, csrf, pending, plan, s.tr(r).Text("error.reset.factor.replayed"), "")
		return
	case !res.OK:
		// Committed, as at sign-in: the failure counters must outlive the refusal.
		if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing a failed second factor during recovery", "err", err)
		}
		s.recordSecondFactorFailure(ctx, req.UserID, ip)
		s.factorsDisabled(ctx, req.OrgID, req.UserID, res.Disabled)
		s.renderReset(w, r, req, token, csrf, pending, plan, s.tr(r).Text("error.reset.factor"), "")
		return
	}
	factor := strings.Join(res.AMR, ",")
	if err := store.WaiveRecoveryDelay(ctx, tx, req.ID, factor); err != nil {
		_ = tx.Rollback(ctx)
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "account.recovery_factor_proven", OrgID: req.OrgID, SubjectID: req.UserID,
		CorrelationID: correlationID(ctx), Detail: map[string]any{"factor": factor, "was_pending": pending},
	}); err != nil {
		s.log.Error("auditing a second factor proven during recovery", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	http.Redirect(w, r, "/recover/reset?token="+url.QueryEscape(token), http.StatusSeeOther)
}

// handleResetPost sets the new password.
func (s *Server) handleResetPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	password := r.PostForm.Get("password")

	_, hash, err := hashRecoveryToken(r.PostForm.Get("token"))
	if err != nil {
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.invalid")})
		return
	}

	// The token is read in a transaction of its own and released at once. What
	// follows renders, reads the flow and the password history, and hashes, and
	// none of it may hold a connection while it takes another: this page is
	// reached by anybody holding a link. The write at the end is its own short
	// transaction, and ConsumeRecovery re-checks the token there, so a link
	// spent or cancelled in between is still refused.
	rtx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	req, err := s.lookupRecovery(ctx, rtx, hash)
	_ = rtx.Rollback(ctx)
	if err != nil {
		// Pending and invalid are shown the same way here. By the time a form is
		// being submitted, the difference only matters to someone probing.
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
		return
	}

	// The operator's flow governs this half. The account is known now -- the token
	// named it -- so its own organisation's flow is read, and the enumeration
	// concern that forces the default organisation in the request half does not
	// apply here: reaching this point already required holding the link.
	//
	// Checked BEFORE the password is validated or anything is written. A flow
	// naming a stage this engine cannot run must refuse the journey with the
	// account untouched, not after the credential has been replaced.
	plan, unsupported, flowName := s.recoveryResetPlan(ctx, req.OrgID)
	if unsupported != "" {
		s.refuseRecoveryStage(w, r, unsupported, flowName)
		return
	}
	if recoveryDenied(plan) {
		writeError(w, http.StatusForbidden, "recovery_closed",
			"account recovery is not available here")
		return
	}
	if !planHasStage(plan, flow.StagePasswordChange) {
		// A recovery flow that never changes a credential recovers nothing. Safety
		// permits it -- nothing is handed out, so there is nothing to prove -- but
		// consuming the token and rendering success would tell somebody their
		// password was reset when it was not.
		s.log.Error("the recovery flow has no password_change stage", "flow", flowName,
			"correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error",
			"account recovery is misconfigured: the recovery flow changes no credential")
		return
	}
	csrf, cerr := s.csrfToken(w, r)
	if cerr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	// The flow's mfa stage, before the reset (5.12): a second factor proven on
	// the link's page, or nothing is changed.
	if planHasStage(plan, flow.StageMFA) && req.WaivedBy == "" {
		s.renderReset(w, r, req, r.PostForm.Get("token"), csrf, false, plan, s.tr(r).Text("error.reset.factorfirst"), "")
		return
	}

	// The full policy runs HERE rather than at the top, because reuse and
	// context checks need to know whose password this is -- and that is only
	// known once the token has been looked up.
	//
	// The cost of that ordering is that a too-short password is reported after
	// the token is validated rather than before. That is the right way round: a
	// message about password length must not tell somebody holding a stale link
	// that it was otherwise valid.
	previous, perr := store.RecentPasswordHashes(ctx, s.db, req.UserID, s.pwPolicy.HistoryDepth)
	if perr != nil {
		s.log.Error("reading password history", "err", perr)
	}
	identity, _ := store.EmailForUser(ctx, s.db, req.UserID)
	if res, cerr := s.pwPolicy.Check(ctx, password, identity, previous, s.hasher); cerr != nil {
		// With the CSRF token: the form was re-rendered without one, so the
		// second password a person tried after a refused first could never be
		// submitted.
		s.renderPage(w, r, "reset", map[string]any{
			"Ready": true, "Token": r.PostForm.Get("token"), "Error": cerr.Error(),
			"CSRF": csrf, "CSRFField": csrfFormField,
		})
		return
	} else if s.pwPolicy.Breach != nil && !res.BreachCheckRan {
		s.log.Warn("the breach check did not run for a password reset",
			"correlation_id", correlationID(ctx))
	}

	newHash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		s.log.Error("hashing the new password", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The outgoing hash is recorded BEFORE it is replaced. Doing it afterwards
	// would file the new password as a previous one and refuse it next time.
	if s.pwPolicy.HistoryDepth > 0 {
		if err := store.RetirePassword(ctx, tx, req.UserID, req.OrgID); err != nil {
			s.log.Error("recording the retired password", "err", err)
		}
	}
	if err := store.ConsumeRecovery(ctx, tx, req.ID, req.UserID, newHash); err != nil {
		_ = tx.Rollback(ctx)
		s.log.Error("consuming recovery", "err", err)
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
		return
	}
	// The link came to the address, so reaching here proves it: it is verified
	// and an outstanding confirmation ends (0177), which is the way back for one
	// past its ceiling of wrong codes.
	if err := store.AddressProvedByRecovery(ctx, tx, req.ID, req.UserID); err != nil {
		s.log.Error("recording the address the reset proved", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "account.password_reset", OrgID: req.OrgID, SubjectID: req.UserID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"waived_by": req.WaivedBy},
	}); err != nil {
		s.log.Error("auditing password reset", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	// Told after the fact, on every channel: a completed reset is exactly what a
	// victim needs to know about immediately, on an address the attacker may not
	// hold.
	trChanged := s.notifierFor(ctx, req.UserID)
	_ = s.notifyAccount(ctx, req.UserID,
		trChanged.Text("mail.password.changed.subject"),
		trChanged.Text("mail.password.changed.body"),
		trChanged.Text("sms.password.changed"))

	// Ending signed in, where the flow says `session` (5.12). After the reset
	// has committed and in a transaction of its own, because completeSignIn
	// abandons its transaction when a prompt is owed, and the new password
	// must not go with it. It is the organisation's sign-in from here, so a
	// sign-in flow that wants more -- a second factor not proven here -- asks.
	// The person now knows the password they just chose, which is what amr says;
	// a factor proven on the way adds itself, and two make it multi-factor.
	if planHasStage(plan, flow.StageSession) {
		amr := []string{"pwd"}
		if req.WaivedBy != "" {
			amr = append(append(amr, strings.Split(req.WaivedBy, ",")...), oauth.AMRMFA)
		}
		stx, err := s.db.Begin(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		defer func() { _ = stx.Rollback(ctx) }()
		s.completeSignIn(w, r, stx, req.UserID, req.OrgID, amr, "")
		return
	}
	// Or to the operator's page (5.24), where the flow ends in a redirect.
	if planHasStage(plan, flow.StageRedirect) {
		if target := s.flowFor(ctx, s.db, req.OrgID, flow.Recovery).RedirectTarget(); target != "" {
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
	}
	s.renderPage(w, r, "done", map[string]any{})
}

// newRecoveryToken returns the token and its hash.
func newRecoveryToken() (token string, hash []byte, err error) {
	token, err = newSID()
	if err != nil {
		return "", nil, err
	}
	return token, store.HashToken(token), nil
}

func hashRecoveryToken(token string) (string, []byte, error) {
	if !validCSRFValue(token) { // same shape: 32 random bytes, base64url
		return "", nil, errors.New("malformed recovery token")
	}
	return token, store.HashToken(token), nil
}

// One page for every outcome. Saying "we sent it" only when the account exists
// turns this form into an account enumerator.
