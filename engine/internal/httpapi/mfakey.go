package httpapi

import (
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/passkeys"
)

// A security key or passkey as the second factor, after a password.
//
// The key is asked for on the code page, by the person the password step
// proved, and only by them: the ceremony is begun from the pending cookie, names
// that person's credentials alone, and is finished on the same page's form. A
// passkey was only ever a way to sign in on its own, so a person whose one
// factor beyond the password was a key was let in on the password alone, and a
// relying party asking for multi-factor was told the account had none.

// ceremonyMFA is the purpose a second-factor ceremony is issued with, so that
// neither a sign-in nor a registration challenge can be finished here, nor this
// one there.
const ceremonyMFA = "mfa"

// handleMFAKeyBegin starts an assertion for the person holding the pending
// cookie, against the credentials they registered.
func (s *Server) handleMFAKeyBegin(w http.ResponseWriter, r *http.Request) {
	// V3.5.2, as for the other ceremonies: a form cannot send this content
	// type without a preflight.
	if err := requireJSONContentType(r); err != nil {
		writeJSONContentTypeError(w, err)
		return
	}
	ctx := r.Context()
	pending, err := s.readPending(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_request",
			"no sign-in is in progress; sign in again")
		return
	}
	u, err := s.passkeyUser(ctx, pending.Subject)
	if err != nil {
		// Deactivated since the password step, or gone.
		s.log.Info("no account for a second-factor key", "err", err)
		writeError(w, http.StatusUnauthorized, "invalid_request",
			"no sign-in is in progress; sign in again")
		return
	}
	if len(u.Creds) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"this account has no security key")
		return
	}
	rp, err := s.relyingParty(ctx, pending.OrgID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys_unavailable", "unavailable")
		return
	}
	assertion, sd, err := rp.BeginSecondFactor(u)
	if err != nil {
		s.log.Error("beginning a second-factor assertion", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := s.issueCeremony(w, ceremonyMFA, pending.Subject, pending.OrgID, sd); err != nil {
		s.log.Error("issuing ceremony", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// finishMFAKey is handleMFAPost's branch for an assertion: the CSRF token, the
// pending cookie and the guessing budget have been checked.
func (s *Server) finishMFAKey(w http.ResponseWriter, r *http.Request, pending *pendingClaims,
	ip string, assertion []byte) {

	ctx := r.Context()
	const rejected = "That security key was not accepted. Please try again."
	refuse := func(reason, detail string) {
		s.log.Info("second-factor key refused", "reason", reason, "detail", detail,
			"correlation_id", correlationID(ctx))
		// Charged as a wrong code is. A signature cannot be guessed, but the
		// budget is what bounds how often this can be tried, and one budget for
		// the step is the one an operator can reason about.
		s.recordSecondFactorFailure(ctx, pending.Subject, ip)
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: pending.OrgID, SubjectID: pending.Subject,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "second_factor_key_" + reason},
		})
		s.renderMFA(w, r, pending.Subject, pending.Authz, rejected)
	}

	cl, sd, err := s.readCeremony(r, ceremonyMFA)
	// Cleared here rather than deferred: a cookie set after the page is
	// written is never sent.
	s.clearCeremony(w)
	if err != nil {
		refuse("no_ceremony", err.Error())
		return
	}
	// The ceremony must be this sign-in's. The library binds the assertion to
	// the user the ceremony named, so this is what stops a challenge begun
	// under one pending sign-in being finished under another's.
	if cl.Subject != pending.Subject || cl.OrgID != pending.OrgID {
		refuse("other_subject", "")
		return
	}
	u, err := s.passkeyUser(ctx, pending.Subject)
	if err != nil {
		refuse("no_account", err.Error())
		return
	}
	rp, err := s.relyingParty(ctx, pending.OrgID)
	if err != nil {
		s.log.Error("loading the relying party for a second-factor key", "err", err)
		s.renderMFA(w, r, pending.Subject, pending.Authz, "Something went wrong. Please try again.")
		return
	}
	cred, err := rp.FinishSecondFactor(u, *sd, assertion)
	if err != nil {
		refuse("rejected", passkeys.Reason(err))
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	refused, err := s.recordAssertion(ctx, tx, cred, pending.Subject, pending.OrgID)
	if err != nil {
		_ = tx.Rollback(ctx)
		s.renderMFA(w, r, pending.Subject, pending.Authz, "Something went wrong. Please try again.")
		return
	}
	if refused {
		// recordAssertion committed the regression's record; this releases the
		// connection if that commit failed.
		_ = tx.Rollback(ctx)
		s.renderMFA(w, r, pending.Subject, pending.Authz,
			"This security key's signature counter did not advance, which can mean "+
				"it has been copied. Use another factor, and remove the key.")
		return
	}

	// What the key proved: presence, on a device-bound or a synced credential.
	// Not whether it verified the user: the library reports the credential's
	// record there, not this assertion, and the step does not ask for it. The
	// combination is two factors whatever the key did, so AMRMFA is appended,
	// as for a code (handleMFAPost).
	key := []string{oauth.AMRUserPresence, oauth.AMRHardwareKey}
	if cred.Flags.BackupEligible {
		key[1] = "swk"
	}
	full := append(append(append([]string{}, pending.AMR...), key...), oauth.AMRMFA)
	s.rememberThisDevice(ctx, w, r, tx, pending.Subject, pending.OrgID)
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, full, pending.Authz)
}
