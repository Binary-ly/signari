package httpapi

import (
	"context"
	"html/template"
	"net/http"

	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/qr"
	"signari.dev/engine/internal/store"
)

// The `enrol_mfa` stage: a sign-in held until the person enrols a second
// factor.
//
// An operator could demand a factor (`mfa`) of everybody, and somebody with
// none was refused with "contact your administrator", which is a support
// ticket per person on the day the rule is switched on. The stage was in the
// language and refused at parse, because nothing drove it. Now the person is
// shown the authenticator-app enrolment on the pending sign-in, then their
// recovery codes, and the sign-in continues through the same walk.
//
// Only for somebody with no factor. The pending token carries the stage's
// name, so the pages answer only a sign-in this stage held: the code step's
// pending sign-in is for somebody who HAS a factor, and if these pages took it,
// a password alone would replace their authenticator with an attacker's. And
// enrolling here proves nothing about who is signing in -- the secret was made
// for whoever holds the password -- so it adds nothing to the sign-in's amr. A
// later `mfa` stage asks for the new authenticator's code like any other.

// flowEnrols reports whether the organisation's flow would run enrol_mfa for
// somebody with nothing enrolled.
func (s *Server) flowEnrols(ctx context.Context, orgID, userID, authzQuery string) bool {
	fl := s.flowFor(ctx, s.db, orgID, flow.Authentication)
	if fl == nil {
		return false
	}
	facts := &signInFacts{s: s, ctx: ctx, db: s.db, orgID: orgID, userID: userID,
		authzQuery: authzQuery, amr: []string{oauth.AMRPassword}}
	facts.setKnown(flow.CondHasSecondFactor, false)
	facts.setKnown(flow.CondCaptchaRequired, false)
	return fl.WillRun(flow.StageEnrolMFA, facts)
}

// beginEnrolMFA holds the sign-in and shows the enrolment's first page.
func (s *Server) beginEnrolMFA(w http.ResponseWriter, r *http.Request,
	userID, orgID string, amr []string, authzQuery string) {

	if err := s.setPendingCookieFor(w, userID, orgID, amr, authzQuery,
		string(flow.StageEnrolMFA)); err != nil {
		s.log.Error("issuing the pending token for an enrolment", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "enrol", map[string]any{
		"Begin": true, "SignIn": true, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// enrolPending reads the sign-in an enrol_mfa stage held, or sends the person
// back to the start.
func (s *Server) enrolPending(w http.ResponseWriter, r *http.Request) (*pendingClaims, bool) {
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; sign in again")
		return nil, false
	}
	pending, err := s.readPending(r)
	if err != nil || pending.Stage != string(flow.StageEnrolMFA) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	return pending, true
}

// hasFactorAlready continues the sign-in, and reports true, for somebody who
// has a factor after all -- one added elsewhere since the walk held them.
// Nothing here may replace it.
func (s *Server) hasFactorAlready(w http.ResponseWriter, r *http.Request, pending *pendingClaims) bool {
	ctx := r.Context()
	has, err := store.HasSecondFactor(ctx, s.db, pending.Subject)
	if err != nil {
		s.log.Error("checking for a factor before enrolling one", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	if !has {
		return false
	}
	s.continueEnrolledSignIn(w, r, pending)
	return true
}

// handleEnrolMFAStart makes a secret and shows it.
func (s *Server) handleEnrolMFAStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pending, ok := s.enrolPending(w, r)
	if !ok || s.hasFactorAlready(w, r, pending) {
		return
	}
	secret, encoded, err := mfa.GenerateSecret()
	if err != nil {
		s.log.Error("generating a TOTP secret", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartTOTPEnrolment(ctx, tx, pending.Subject, pending.OrgID, secret,
		mfa.DefaultDigits, mfa.DefaultPeriod, s.cfg.Root); err != nil {
		s.log.Error("starting a TOTP enrolment", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The clock restarts here: scanning and typing a code is longer than the
	// few minutes a pending sign-in otherwise lasts.
	if err := s.setPendingCookieFor(w, pending.Subject, pending.OrgID, pending.AMR,
		pending.Authz, pending.Stage); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	uri := mfa.ProvisioningURI(s.orgLabel(ctx, pending.OrgID), s.accountLabel(ctx, pending.Subject),
		encoded, mfa.DefaultDigits, mfa.DefaultPeriod)
	var qrSVG string
	if code, qerr := qr.Encode([]byte(uri)); qerr == nil {
		qrSVG = code.SVG(4, 4)
	} else {
		s.log.Warn("rendering the TOTP QR code", "err", qerr)
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// template.URL and template.HTML for the reasons handleTOTPStart gives.
	s.renderPage(w, r, "enrol", map[string]any{
		"Secret": grouped(encoded), "URI": template.URL(uri), "QR": template.HTML(qrSVG),
		"SignIn": true, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleEnrolMFAConfirm checks the first code, makes it the person's
// authenticator and shows their recovery codes, once.
func (s *Server) handleEnrolMFAConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pending, ok := s.enrolPending(w, r)
	if !ok || s.hasFactorAlready(w, r, pending) {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	outcome, codes, _, err := s.confirmTOTP(ctx, tx, pending.Subject, pending.OrgID, r.PostForm.Get("code"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if outcome != totpConfirmed {
		_ = tx.Rollback(ctx)
		csrf, _ := s.csrfToken(w, r)
		data := map[string]any{"SignIn": true, "CSRF": csrf, "CSRFField": csrfFormField,
			"Error": s.tr(r).T("error.totp.mismatch")}
		if outcome != totpMismatch {
			data["Begin"], data["Error"] = true, s.tr(r).T("error.totp.expired")
		}
		s.renderPage(w, r, "enrol", data)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.announceTOTP(ctx, pending.Subject, false)

	if err := s.setPendingCookieFor(w, pending.Subject, pending.OrgID, pending.AMR,
		pending.Authz, pending.Stage); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Shown ONCE, as on the account page, with the way on.
	s.renderPage(w, r, "recovery", map[string]any{
		"Codes": codes, "SignIn": true, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleEnrolMFAContinue goes on with the sign-in once a factor is enrolled.
func (s *Server) handleEnrolMFAContinue(w http.ResponseWriter, r *http.Request) {
	pending, ok := s.enrolPending(w, r)
	if !ok {
		return
	}
	s.continueEnrolledSignIn(w, r, pending)
}

// continueEnrolledSignIn re-enters the walk. It starts from the first stage,
// so the enrol_mfa stage finds the factor and passes, and nothing after it is
// skipped.
func (s *Server) continueEnrolledSignIn(w http.ResponseWriter, r *http.Request, pending *pendingClaims) {
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, pending.AMR, pending.Authz)
}
