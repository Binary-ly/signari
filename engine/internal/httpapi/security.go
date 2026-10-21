package httpapi

import (
	"context"
	"errors"
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/sms"
	"signari.dev/engine/internal/store"
)

// /account/security: every way the person signs in, on one page, with what
// adds, replaces or removes each.
//
// The pages that enrol an authenticator app, email codes and text-message codes
// existed and nothing linked to them, and an app or an address, once added,
// could not be taken away by its owner: only an administrator could. Somebody
// replacing a phone was left with an authenticator they no longer had, still
// asked for at every sign-in. Passkeys are listed and added on the account page,
// where their script runs, and recovery codes on their own; this page counts
// them and links there.

// securityState is what the page shows.
type securityState struct {
	TOTP, TOTPDisabled bool
	Email              string
	EmailDisabled      bool
	// SMS is the proved number, redacted, or "hashed" when only its hash is
	// kept; empty with none.
	SMS                string
	SMSAvailable       bool
	Passkeys, Recovery int
	RecoveryDisabled   bool
	Duo                bool
	HasSecondFactor    bool
}

func (s *Server) securityState(ctx context.Context, userID string) (securityState, error) {
	st := securityState{SMSAvailable: s.smsAvailable()}
	var email *string
	if err := s.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.totp_credentials WHERE user_id = $1::uuid AND confirmed_at IS NOT NULL),
		       EXISTS (SELECT 1 FROM core.totp_credentials WHERE user_id = $1::uuid AND disabled_at IS NOT NULL),
		       (SELECT address FROM core.email_otp_credentials WHERE user_id = $1::uuid AND verified_at IS NOT NULL),
		       EXISTS (SELECT 1 FROM core.email_otp_credentials WHERE user_id = $1::uuid AND disabled_at IS NOT NULL),
		       (SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid),
		       (SELECT count(*) FROM core.recovery_codes WHERE user_id = $1::uuid AND used_at IS NULL),
		       EXISTS (SELECT 1 FROM core.recovery_code_failures WHERE user_id = $1::uuid AND disabled_at IS NOT NULL),
		       EXISTS (SELECT 1 FROM core.duo_enrollments WHERE user_id = $1::uuid)`, userID).
		Scan(&st.TOTP, &st.TOTPDisabled, &email, &st.EmailDisabled, &st.Passkeys, &st.Recovery,
			&st.RecoveryDisabled, &st.Duo); err != nil {
		return st, err
	}
	if email != nil {
		st.Email = *email
	}
	cred, err := store.LoadSMSOTP(ctx, s.db, userID)
	switch {
	case err == nil && cred.Verified && cred.Hashed:
		st.SMS = "hashed"
	case err == nil && cred.Verified:
		st.SMS = sms.RedactNumber(cred.Number)
	case err != nil && !errors.Is(err, store.ErrNoSMSOTP):
		return st, err
	}
	if st.HasSecondFactor, err = store.HasSecondFactor(ctx, s.db, userID); err != nil {
		return st, err
	}
	return st, nil
}

// handleSecurity shows the page.
func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	_, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/security"), http.StatusSeeOther)
		return
	}
	s.renderSecurity(w, r, userID, "")
}

func (s *Server) renderSecurity(w http.ResponseWriter, r *http.Request, userID, message string) {
	st, err := s.securityState(r.Context(), userID)
	if err != nil {
		s.log.Error("reading the sign-in methods", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	// Flat, under the names the page validator's probes fill (pages/validate.go),
	// so an operator's override of this page is held to its forms' CSRF fields.
	s.renderPage(w, r, "security", map[string]any{
		"TOTP": st.TOTP, "TOTPDisabled": st.TOTPDisabled,
		"Email": st.Email, "EmailDisabled": st.EmailDisabled,
		"Number": st.SMS, "Hashed": st.SMS == "hashed", "Configured": st.SMSAvailable,
		"Passkeys": st.Passkeys, "Recovery": st.Recovery, "RecoveryDisabled": st.RecoveryDisabled,
		"HasSecondFactor": st.HasSecondFactor, "Duo": st.Duo,
		"Message": message, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleSecurityRemove removes one of the person's own methods: behind a
// recent sign-in, audited, and told on every channel the account still has.
func (s *Server) handleSecurityRemove(w http.ResponseWriter, r *http.Request) {
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/security"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; reload and try again")
		return
	}
	if s.credentialChangeRefused(w, r, sid, "/account/security", false) {
		return
	}
	kind := r.PostForm.Get("factor")
	cleared, err := s.removeOwnFactor(r.Context(), userID, orgID, kind)
	switch {
	case errors.Is(err, store.ErrUnknownFactor):
		writeError(w, http.StatusBadRequest, "invalid_request", "that is not a method removed here")
		return
	case errors.Is(err, store.ErrFactorNotFound):
		s.renderSecurity(w, r, userID, "")
		return
	case err != nil:
		s.log.Error("removing a sign-in method", "kind", kind, "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	msg := s.tr(r).Text("security.removed")
	if cleared {
		msg = s.tr(r).Text("security.removed.recovery")
	}
	s.renderSecurity(w, r, userID, msg)
}

// removeOwnFactor removes and records it, then tells the holder. Shared with
// the text-message page's own remove button.
func (s *Server) removeOwnFactor(ctx context.Context, userID, orgID, kind string) (recoveryCleared bool, err error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if recoveryCleared, err = store.RemoveOwnFactor(ctx, tx, userID, kind); err != nil {
		return false, err
	}
	// Literal types, one per kind, so the event registry's guard can read them.
	var ev audit.Event
	switch kind {
	case "totp":
		ev = audit.Event{Type: "mfa.totp_removed"}
	case "email_otp":
		ev = audit.Event{Type: "mfa.email_otp_removed"}
	default:
		ev = audit.Event{Type: "mfa.sms_removed"}
	}
	ev.OrgID, ev.SubjectID, ev.CorrelationID = orgID, userID, correlationID(ctx)
	ev.Detail = map[string]any{"by": "owner", "recovery_codes_cleared": recoveryCleared}
	if err := audit.Write(ctx, tx, ev); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	// After the commit, as every notice is: a notice of a removal that rolled
	// back teaches people to ignore these. Whoever removed it may be holding a
	// stolen session, so it goes to every channel the account still has.
	tr := s.notifierFor(ctx, userID)
	data := map[string]any{"Factor": tr.Text("factor.kind." + kind)}
	if nerr := s.notifyAccount(ctx, userID, tr.Text("mail.factor.removed.self.subject"),
		tr.Text("mail.factor.removed.self.body", data), tr.Text("sms.factor.removed.self", data)); nerr != nil {
		s.log.Error("telling the holder a sign-in method was removed", "err", nerr, "user_id", userID)
	}
	return recoveryCleared, nil
}
