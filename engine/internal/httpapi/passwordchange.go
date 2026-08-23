package httpapi

import (
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Requiring a password change before a session exists.
//
// # Why this is a step in the sign-in funnel rather than a page in the account
//
// The person is authenticated but has no session yet. A "please change your
// password" link in an account area is a suggestion; this is a gate. It sits
// beside the prompt step in completeSignIn for the same reason that one does --
// there are eight ways to sign in, and a gate implemented at each of them is a
// gate missing from one of them.
//
// # Why the reason is always shown
//
// An unexplained demand to change a password is indistinguishable from
// phishing, and a user trained to comply with unexplained demands is the
// vulnerability the demand was meant to fix. Every path that sets the flag sets
// a reason with it.
//
// # Why it can be reached with a password that was fine when it was chosen
//
// Breach corpora only grow. Every comparable implementation checks a password
// once, at the moment it is set, and never again -- so the control quietly
// expires on the day after it ran. Sign-in is the only moment the plaintext
// exists to check, and this is what the check can do about it.

// beginPasswordChange interrupts the sign-in and asks for a new password.
func (s *Server) beginPasswordChange(w http.ResponseWriter, r *http.Request,
	userID, orgID string, amr []string, authzQuery, reason string) {

	if err := s.setPendingCookie(w, userID, orgID, amr, authzQuery); err != nil {
		s.log.Error("issuing the pending token for a password change", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "changepw", map[string]any{
		"Reason": s.renderChangeReason(r, reason), "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// renderChangeReason turns a stored reason into text for this request.
//
// `must_change_reason` holds one of two things, and they are handled
// differently on purpose:
//
//   - One of OUR keys, written when the flag was set. Translated here, at
//     render time, which is the only moment the reader's language is known. A
//     sentence stored in that column would be frozen in whatever language the
//     server happened to be speaking when a breach check ran months earlier.
//   - Anything an operator wrote, through the Admin API. Shown verbatim,
//     because those are their words and this is not the place to guess at them.
//
// The two are told apart by asking the catalogue, so an operator's sentence can
// never collide with a key unless they write one exactly.
func (s *Server) renderChangeReason(r *http.Request, stored string) any {
	if stored == "" {
		return ""
	}
	if p := s.tr(r); p.Has(stored) {
		return p.T(stored)
	}
	return stored
}

// handlePasswordChangePost sets the new password and resumes the sign-in.
func (s *Server) handlePasswordChangePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden",
			"that form has expired; sign in again")
		return
	}
	pending, err := s.readPending(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	_, reason, _ := store.PasswordChangeRequired(ctx, s.db, pending.Subject)
	again := func(msg string) {
		csrf, _ := s.csrfToken(w, r)
		s.renderPage(w, r, "changepw", map[string]any{
			"Reason": s.renderChangeReason(r, reason), "Error": msg,
			"CSRF": csrf, "CSRFField": csrfFormField,
		})
	}

	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("confirm") {
		again("Those two passwords are not the same.")
		return
	}

	previous, perr := store.RecentPasswordHashes(ctx, s.db, pending.Subject,
		s.pwPolicy.HistoryDepth)
	if perr != nil {
		s.log.Error("reading password history", "err", perr)
	}
	identity, _ := store.EmailForUser(ctx, s.db, pending.Subject)

	// Reuse is checked here whatever the configured depth, because the reason
	// this gate exists may be that the CURRENT password is unusable. Offering
	// the same one back would satisfy the form and change nothing.
	current, cerr := store.CurrentPasswordHash(ctx, s.db, pending.Subject)
	if cerr == nil && current != "" {
		if _, verr := s.hasher.Verify(ctx, current, password); verr == nil {
			again("That is your current password. Choose a different one.")
			return
		}
	}

	if _, err := s.pwPolicy.Check(ctx, password, identity, previous, s.hasher); err != nil {
		again(err.Error())
		return
	}

	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		s.log.Error("hashing a changed password", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Retired before it is replaced, or the new one is filed as a previous one
	// and refused at the next change.
	if s.pwPolicy.HistoryDepth > 0 {
		if rerr := store.RetirePassword(ctx, tx, pending.Subject, pending.OrgID); rerr != nil {
			s.log.Error("recording the retired password", "err", rerr)
		}
	}
	if err := store.SetPassword(ctx, tx, pending.Subject, hash); err != nil {
		s.log.Error("setting a changed password", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Every other session for this user ends. The reason for the change may be
	// that somebody else knows the old password, and leaving their session alive
	// makes the change ceremonial.
	if _, terr := store.TerminateSessions(ctx, tx, "", pending.Subject,
		store.ReasonPasswordChange); terr != nil {
		s.log.Error("terminating sessions after a password change", "err", terr)
	}

	s.auditDetached(ctx, audit.Event{
		Type: "password.changed", OrgID: pending.OrgID, SubjectID: pending.Subject,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"required": true, "reason": reason},
	})

	// Back into the funnel. The flag is now clear, so this step does not repeat.
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, pending.AMR, pending.Authz)
}
