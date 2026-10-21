package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/store"
)

// /account/email: a person moving their account to another address (5.06).
//
// There was no way to do it but asking an administrator. The address is the
// account's recovery channel and, verified, an identity relying parties key
// accounts on, so it moves only when a code sent to the new address comes
// back: until then the account keeps its address, its recovery and its
// verified mark. The change asks for a recent sign-in like every other change
// to how the account is reached, its codes are charged to the second-factor
// budget, and once it is done the old address is told, and so is every
// channel the account has -- the old one being the mailbox somebody who
// redirected the account cannot also read.

// handleEmailChange shows the page.
func (s *Server) handleEmailChange(w http.ResponseWriter, r *http.Request) {
	_, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/email"), http.StatusSeeOther)
		return
	}
	s.renderEmailChange(w, r, userID, "", "")
}

func (s *Server) renderEmailChange(w http.ResponseWriter, r *http.Request, userID, message, errMsg string) {
	ctx := r.Context()
	var current string
	if err := s.db.QueryRow(ctx, `SELECT COALESCE(email, '') FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&current); err != nil {
		s.log.Error("reading the account's address", "err", err)
	}
	pending, err := store.PendingEmailChange(ctx, s.db, userID)
	if err != nil {
		s.log.Error("reading a change of address", "err", err)
	}
	data := map[string]any{"Address": current, "Message": message, "Error": errMsg}
	if pending != nil {
		data["NewAddress"], data["Closed"] = pending.NewAddress, pending.Closed
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	data["CSRF"], data["CSRFField"] = csrf, csrfFormField
	s.renderPage(w, r, "emailchange", data)
}

// handleEmailChangePost starts, confirms or cancels a change.
func (s *Server) handleEmailChangePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/email"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; reload and try again")
		return
	}
	if s.credentialChangeRefused(w, r, sid, "/account/email", false) {
		return
	}
	tr := s.tr(r)
	step := r.PostForm.Get("step")
	ip := clientIP(r)
	// The budget is read before the transaction opens: reading it takes a
	// connection of its own, and holding one while waiting for another is how
	// a pool deadlocks under load.
	if step == "verify" && !s.allowSecondFactorAttempt(ctx, w, userID, ip) {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	switch step {
	case "cancel":
		if err := store.CancelEmailChange(ctx, tx, userID); err != nil || tx.Commit(ctx) != nil {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		s.renderEmailChange(w, r, userID, tr.Text("emailchange.cancelled"), "")

	case "verify":
		old, moved, guessed, err := store.ConfirmEmailChange(ctx, tx, userID, strings.TrimSpace(r.PostForm.Get("code")))
		switch {
		case errors.Is(err, store.ErrAddressInUse):
			_ = tx.Rollback(ctx)
			s.renderEmailChange(w, r, userID, "", err.Error())
			return
		case errors.Is(err, store.ErrNoEmailChange):
			_ = tx.Rollback(ctx)
			s.renderEmailChange(w, r, userID, "", "")
			return
		case err != nil:
			s.log.Error("confirming a change of address", "err", err)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		case moved == "":
			// A wrong or dead code, committed so the count stands.
			if err := tx.Commit(ctx); err != nil {
				s.log.Error("recording a wrong code", "err", err)
			}
			if guessed {
				s.recordSecondFactorFailure(ctx, userID, ip)
			}
			s.renderEmailChange(w, r, userID, "", tr.Text("error.verifyemail.mismatch"))
			return
		}
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "user.email_changed", OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx), Detail: map[string]any{"by": "owner"},
		}); err != nil {
			s.log.Error("auditing a change of address", "err", err)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		// After the commit, to every channel the account now has and to the
		// address it left. Neither address is named in the message.
		nt := s.notifierFor(ctx, userID)
		subject, body := nt.Text("mail.email.changed.self.subject"), nt.Text("mail.email.changed.self.body")
		if err := s.notifyAccount(ctx, userID, subject, body, nt.Text("sms.email.changed.self")); err != nil {
			s.log.Error("telling the holder of a change of address", "err", err)
		}
		if old != "" {
			if err := s.mailer.Send(ctx, mail.Message{To: old, Subject: subject, Body: body}); err != nil {
				s.log.Error("telling the old address of a change of address", "err", err)
			}
		}
		s.renderEmailChange(w, r, userID, tr.Text("emailchange.done"), "")

	default: // "start"
		address := strings.ToLower(strings.TrimSpace(r.PostForm.Get("address")))
		if address == "" || !strings.Contains(address, "@") || strings.ContainsAny(address, " \r\n") {
			_ = tx.Rollback(ctx)
			s.renderEmailChange(w, r, userID, "", tr.Text("error.emailchange.address"))
			return
		}
		code, err := store.StartEmailChange(ctx, tx, userID, orgID, address)
		switch {
		case errors.Is(err, store.ErrEmailOTPTooSoon):
			_ = tx.Rollback(ctx)
			s.renderEmailChange(w, r, userID, tr.Text("verifyemail.toosoon"), "")
			return
		case errors.Is(err, store.ErrSameAddress), errors.Is(err, store.ErrAddressInUse):
			_ = tx.Rollback(ctx)
			s.renderEmailChange(w, r, userID, "", err.Error())
			return
		case err != nil:
			s.log.Error("starting a change of address", "err", err)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		// To the new address alone: the code proves that mailbox and no other.
		nt := s.notifierFor(ctx, userID)
		if err := s.mailer.Send(ctx, mail.Message{To: address, Subject: nt.Text("mail.verifyemail.subject"),
			Body: nt.Text("mail.verifyemail.body", map[string]any{"Code": code})}); err != nil {
			s.log.Error("sending the code for a change of address", "err", err)
			s.renderEmailChange(w, r, userID, "", tr.Text("error.verifyemail.unsent"))
			return
		}
		s.renderEmailChange(w, r, userID, "", "")
	}
}
