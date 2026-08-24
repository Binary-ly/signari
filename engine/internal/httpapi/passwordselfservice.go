package httpapi

import (
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Voluntary password change from the self-service account console.
//
// Distinct from /login/password-change, which is a GATE in the sign-in funnel
// for a user the server is forcing to change (a breach hit, an administrator's
// request). This is a signed-in user choosing to change their password.
//
// The one thing this does that the forced flow does not is REQUIRE THE CURRENT
// PASSWORD. The forced flow runs immediately after the credential was proven, so
// the person is known; here the session may be one an attacker captured, and
// changing a password without proving the old one is how a stolen cookie becomes
// permanent account ownership. ASVS V6.2 and the "re-authenticate before
// changing a factor" rule are what this satisfies. Everything after the current-
// password check -- reuse, policy, history, hashing, session termination -- is
// the same path the forced change uses, deliberately, so the two cannot drift.

// handleAccountPassword renders the voluntary change form.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := s.currentSession(r); !ok {
		http.Redirect(w, r, parkLogin("/account/password"), http.StatusSeeOther)
		return
	}
	s.renderAccountPassword(w, r, "", r.URL.Query().Get("m"))
}

func (s *Server) renderAccountPassword(w http.ResponseWriter, r *http.Request, errMsg, note string) {
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("issuing a CSRF token", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	htmlPageHeaders(w)
	s.renderPage(w, r, "accountpw", map[string]any{
		"CSRF": csrf, "CSRFField": csrfFormField, "Error": errMsg, "Message": note,
	})
}

// handleAccountPasswordPost applies a voluntary change.
func (s *Server) handleAccountPasswordPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		http.Error(w, "that request could not be verified", http.StatusBadRequest)
		return
	}
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/password"), http.StatusSeeOther)
		return
	}

	current := r.PostForm.Get("current")
	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("confirm") {
		s.renderAccountPassword(w, r, "Those two passwords are not the same.", "")
		return
	}

	// Prove the CURRENT password before changing it. One generic refusal whether
	// the account has no password or the one given is wrong -- the distinction is
	// not the caller's to learn.
	stored, cerr := store.CurrentPasswordHash(ctx, s.db, userID)
	if cerr != nil || stored == "" {
		s.renderAccountPassword(w, r, "Your current password could not be checked. "+
			"If you signed in without a password, set one through account recovery instead.", "")
		return
	}
	if _, verr := s.hasher.Verify(ctx, stored, current); verr != nil {
		s.renderAccountPassword(w, r, "That is not your current password.", "")
		return
	}
	if _, verr := s.hasher.Verify(ctx, stored, password); verr == nil {
		s.renderAccountPassword(w, r, "That is your current password. Choose a different one.", "")
		return
	}

	identity, _ := store.EmailForUser(ctx, s.db, userID)
	previous, perr := store.RecentPasswordHashes(ctx, s.db, userID, s.pwPolicy.HistoryDepth)
	if perr != nil {
		s.log.Error("reading password history", "err", perr)
	}
	if _, err := s.pwPolicy.Check(ctx, password, identity, previous, s.hasher); err != nil {
		s.renderAccountPassword(w, r, err.Error(), "")
		return
	}

	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		s.log.Error("hashing a changed password", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if s.pwPolicy.HistoryDepth > 0 {
		if rerr := store.RetirePassword(ctx, tx, userID, orgID); rerr != nil {
			s.log.Error("recording the retired password", "err", rerr)
		}
	}
	if err := store.SetPassword(ctx, tx, userID, hash); err != nil {
		s.log.Error("setting a changed password", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// Every session ends, this one included. A password change is the moment to
	// assume the old credential is compromised; keeping any session alive on the
	// old proof is the outcome the change exists to prevent. The user signs in
	// again with the new password. ASVS V7.4.3 (terminate other sessions after a
	// credential change) is satisfied by terminating all of them.
	if _, terr := store.TerminateSessions(ctx, tx, "", userID, store.ReasonPasswordChange); terr != nil {
		s.log.Error("terminating sessions after a voluntary password change", "err", terr)
	}

	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "password.changed", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"required": false, "self_service": true},
	}); aerr != nil {
		s.log.Error("recording a voluntary password change", "err", aerr)
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// The session cookie this browser holds is now revoked, so send them to sign
	// in with the new password rather than to an account page that would bounce.
	http.Redirect(w, r, parkLogin("/account"), http.StatusSeeOther)
}
