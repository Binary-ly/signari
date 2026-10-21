package httpapi

import (
	"errors"
	"fmt"
	"net/http"

	"signari.dev/engine/internal/sms"
	"signari.dev/engine/internal/store"
)

// A number kept only as a hash (migration 0173) is texted when the person
// types it on the code page: its keyed hash is compared with the kept one,
// and on a match the code goes to the number they typed.
//
// The page says the same whether the number matched or not. Whoever holds
// this pending sign-in has the password; telling them which number is on the
// account would be the number a SIM swap needs. Each try draws on the code
// page's own budget, as a code does, so the number cannot be walked.

// handleMFASMSSend is POST /login/mfa/sms.
func (s *Server) handleMFASMSSend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		s.renderLoginStatus(w, r, r.PostForm.Get("authz"),
			"Your sign-in session expired. Please try again.", http.StatusForbidden)
		return
	}
	pending, err := s.readPending(r)
	if err != nil {
		s.clearPending(w)
		s.renderLoginStatus(w, r, r.PostForm.Get("authz"),
			"Your sign-in session expired. Please sign in again.", http.StatusUnauthorized)
		return
	}
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	if !s.allowSecondFactorAttempt(ctx, w, pending.Subject, ip) {
		return
	}
	notice := string(s.tr(r).T("mfa.sms.sent"))
	number, err := sms.NormaliseNumber(r.PostForm.Get("number"))
	if err != nil || !s.smsAvailable() {
		s.renderMFAWith(w, r, pending.Subject, pending.Authz, "", notice)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	hash, err := s.smsNumberHash(ctx, tx, pending.Subject, number)
	if err != nil {
		_ = tx.Rollback(ctx)
		s.log.Error("hashing a typed SMS number", "err", err)
		s.renderMFA(w, r, pending.Subject, pending.Authz, "Something went wrong. Please try again.")
		return
	}
	code, to, err := store.IssueSMSOTPTo(ctx, tx, pending.Subject, number, hash, s.smsVerifier != nil)
	switch {
	case errors.Is(err, store.ErrSMSNumberMismatch), errors.Is(err, store.ErrNoSMSOTP),
		errors.Is(err, store.ErrSMSOTPTooSoon):
		// The same page whichever: see the note above.
		_ = tx.Rollback(ctx)
		s.renderMFAWith(w, r, pending.Subject, pending.Authz, "", notice)
		return
	case err != nil:
		_ = tx.Rollback(ctx)
		s.log.Error("issuing an SMS code to a typed number", "err", err)
		s.renderMFA(w, r, pending.Subject, pending.Authz, "Something went wrong. Please try again.")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.sendSMS(ctx, pending.Subject, smsCode, sms.Message{
		To: to,
		Body: fmt.Sprintf("%s: your sign-in code is %s. It expires in %d minutes. "+
			"If you did not request it, someone has your password.",
			s.cfg.Issuer, code, int(store.SMSOTPLifetime.Minutes())),
	}); err != nil {
		s.log.Error("sending the SMS code", "err", err, "to", sms.RedactNumber(to))
	}
	s.renderMFAWith(w, r, pending.Subject, pending.Authz, "", notice)
}
