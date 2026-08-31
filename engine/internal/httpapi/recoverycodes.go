package httpapi

import (
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Self-service recovery-code regeneration.
//
// Recovery codes are the backup that gets somebody in when their second factor
// is lost -- a broken phone, a misplaced security key. They are shown once at
// enrolment and never again (only hashes are stored), so a user who has spent
// some, or fears the printout leaked, has no way to get a fresh set without an
// administrator. This is that way.
//
// Two guardrails:
//   - It regenerates only for an account that HAS a second factor. Codes that
//     back up nothing are just a second password to lose, and offering them to a
//     password-only account teaches the wrong idea of what they are for.
//   - Regenerating REPLACES the old set (store.GenerateRecoveryCodes deletes the
//     previous codes first), which is the point: a leaked printout must stop
//     working, and a regenerate that left the old codes live would not be one.

const recoveryCodeCount = 10

// handleRecoveryCodes shows how many codes remain and the button to replace them.
func (s *Server) handleRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/recovery"), http.StatusSeeOther)
		return
	}

	hasFactor, err := store.HasSecondFactor(ctx, s.db, userID)
	if err != nil {
		s.log.Error("checking for a second factor", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	remaining := 0
	if hasFactor {
		tx, err := s.db.Begin(ctx)
		if err != nil {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		remaining, _ = store.RemainingRecoveryCodes(ctx, tx, userID)
		_ = tx.Rollback(ctx)
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("issuing a CSRF token", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	htmlPageHeaders(w)
	s.renderPage(w, r, "recoverycodes", map[string]any{
		"HasFactor": hasFactor,
		"Remaining": remaining,
		"CSRF":      csrf,
		"CSRFField": csrfFormField,
	})
}

// handleRecoveryCodesRegenerate replaces the codes and shows the new set once.
func (s *Server) handleRecoveryCodesRegenerate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		http.Error(w, "that request could not be verified", http.StatusBadRequest)
		return
	}
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/recovery"), http.StatusSeeOther)
		return
	}

	// Only for an account that has a factor these codes back up.
	hasFactor, err := store.HasSecondFactor(ctx, s.db, userID)
	if err != nil {
		s.log.Error("checking for a second factor", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if !hasFactor {
		http.Redirect(w, r, "/account/recovery", http.StatusSeeOther)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	codes, err := store.GenerateRecoveryCodes(ctx, tx, userID, orgID, recoveryCodeCount)
	if err != nil {
		s.log.Error("regenerating recovery codes", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// Notify: regenerating recovery codes invalidates the old set, and somebody
	// who did not do it should learn that the codes they hold have just stopped
	// working -- on an independent channel, per the notification design.
	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.recovery_codes_regenerated", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
	}); aerr != nil {
		s.log.Error("recording recovery-code regeneration", "err", aerr)
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// Best-effort, after the commit: the codes are already replaced, so a notice
	// that fails must not undo that.
	tr := s.notifierFor(ctx, userID)
	_ = s.notifyAccount(ctx, userID,
		tr.Text("mail.recoverycodes.replaced.subject"),
		tr.Text("mail.recoverycodes.replaced.body"),
		tr.Text("sms.recoverycodes.replaced"))

	// Shown once, on the same page enrolment uses.
	htmlPageHeaders(w)
	s.renderPage(w, r, "recovery", map[string]any{"Codes": codes})
}
