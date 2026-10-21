package httpapi

import (
	"errors"
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/store"
)

// The `verify_email` stage: a sign-in held until the account's address is
// proved (migration 0177).
//
// Self-sign-up under a rule with require_verified_email records that the
// address must be proved; the rule said so from the start and nothing
// consulted it, so a rule naming @example.com let anybody create an account
// as anybody there and sign straight in. Now the first sign-in sends a code to
// the address and the session waits for it. The right code sets
// email_verified_at, which is what makes the ID token and /userinfo say
// `email_verified: true`, and the walk carries on from the start.
//
// A wrong code is charged to the second-factor budget, since only somebody
// holding the password reaches this page, and to the verification's own
// ceiling across codes. Past the ceiling no code is accepted, and resetting the
// password from the email proves the address instead (AddressProvedByRecovery).

// beginVerifyEmail holds the sign-in, sends a code and shows the page.
func (s *Server) beginVerifyEmail(w http.ResponseWriter, r *http.Request,
	userID, orgID string, amr []string, authzQuery string) {

	if err := s.setPendingCookieFor(w, userID, orgID, amr, authzQuery,
		string(flow.StageVerifyEmail)); err != nil {
		s.log.Error("issuing the pending token for an address confirmation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.sendVerificationCode(w, r, userID, "")
}

// sendVerificationCode sends a code, unless one went moments ago, and shows
// the page, with message when one was sent.
func (s *Server) sendVerificationCode(w http.ResponseWriter, r *http.Request, userID string, message string) {
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	code, address, err := store.IssueEmailVerification(ctx, tx, userID)
	switch {
	case errors.Is(err, store.ErrEmailOTPTooSoon):
		// One went moments ago and is still good; another would only be a way
		// to fill somebody's inbox. Said only to somebody who asked for another.
		_ = tx.Rollback(ctx)
		if message != "" {
			message = s.tr(r).Text("verifyemail.toosoon")
		}
		s.renderVerifyEmail(w, r, userID, message)
		return
	case errors.Is(err, store.ErrEmailVerificationClosed):
		_ = tx.Rollback(ctx)
		s.renderVerifyEmail(w, r, userID, "")
		return
	case err != nil:
		s.log.Error("issuing an address confirmation code", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// To the address being proved and nowhere else: a code sent to another
	// channel would prove that channel, not this.
	tr := s.notifierFor(ctx, userID)
	if err := s.mailer.Send(ctx, mail.Message{
		To:      address,
		Subject: tr.Text("mail.verifyemail.subject"),
		Body:    tr.Text("mail.verifyemail.body", map[string]any{"Code": code}),
	}); err != nil {
		s.log.Error("sending an address confirmation code", "err", err, "user_id", userID)
		message = s.tr(r).Text("error.verifyemail.unsent")
	}
	s.renderVerifyEmail(w, r, userID, message)
}

// renderVerifyEmail shows the code form, or, past the ceiling, the way that is
// left.
func (s *Server) renderVerifyEmail(w http.ResponseWriter, r *http.Request, userID, message string) {
	ctx := r.Context()
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	closed, err := store.EmailVerificationClosed(ctx, s.db, userID)
	if err != nil {
		s.log.Error("reading an address confirmation", "err", err)
	}
	var address string
	if err := s.db.QueryRow(ctx, `SELECT COALESCE(email, '') FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&address); err != nil {
		s.log.Error("reading the address to confirm", "err", err)
	}
	s.renderPage(w, r, "verifyemail", map[string]any{
		"Address": address, "Closed": closed || address == "", "Error": message,
		"CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// verifyEmailPending reads the sign-in a verify_email stage held, or sends the
// person back to the start.
func (s *Server) verifyEmailPending(w http.ResponseWriter, r *http.Request) (*pendingClaims, bool) {
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; sign in again")
		return nil, false
	}
	pending, err := s.readPending(r)
	if err != nil || pending.Stage != string(flow.StageVerifyEmail) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	return pending, true
}

// handleVerifyEmailPost checks a code and, when it is right, goes on with the
// sign-in.
func (s *Server) handleVerifyEmailPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pending, ok := s.verifyEmailPending(w, r)
	if !ok {
		return
	}
	ip := clientIP(r)
	if !s.allowSecondFactorAttempt(ctx, w, pending.Subject, ip) {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	right, guessed, err := store.ConfirmEmailVerification(ctx, tx, pending.Subject, r.PostForm.Get("code"))
	if err != nil {
		s.log.Error("checking an address confirmation code", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !right {
		// Committed, so the count of wrong codes stands.
		if err := tx.Commit(ctx); err != nil {
			s.log.Error("recording a wrong confirmation code", "err", err)
		}
		if guessed {
			s.recordSecondFactorFailure(ctx, pending.Subject, ip)
		}
		s.renderVerifyEmail(w, r, pending.Subject, s.tr(r).Text("error.verifyemail.mismatch"))
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "user.email_verified", OrgID: pending.OrgID, SubjectID: pending.Subject,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"by": "code"},
	}); err != nil {
		s.log.Error("auditing an address confirmation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// From the first stage again, in this transaction, which has deleted the
	// verification: verify_email now passes and nothing after it is skipped.
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, pending.AMR, pending.Authz)
}

// handleVerifyEmailResend sends another code.
func (s *Server) handleVerifyEmailResend(w http.ResponseWriter, r *http.Request) {
	pending, ok := s.verifyEmailPending(w, r)
	if !ok {
		return
	}
	// The clock restarts: reading mail on another device takes longer than a
	// pending sign-in otherwise lasts.
	if err := s.setPendingCookieFor(w, pending.Subject, pending.OrgID, pending.AMR,
		pending.Authz, pending.Stage); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.sendVerificationCode(w, r, pending.Subject, s.tr(r).Text("verifyemail.resent"))
}
