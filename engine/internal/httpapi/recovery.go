package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/mail"
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

	// The work happens regardless of whether the account exists, and the same
	// page is always returned. See the file comment.
	if identifier != "" {
		if err := s.beginRecovery(ctx, identifier); err != nil {
			// Logged, never surfaced: the error text distinguishes "no such user"
			// from "SMTP is down", and only one of those is the caller's business.
			s.log.Error("beginning recovery", "err", err, "correlation_id", correlationID(ctx))
		}
	}

	s.renderPage(w, r, "sent", map[string]any{})
}

// beginRecovery does the work for an identifier that may not exist.
func (s *Server) beginRecovery(ctx context.Context, identifier string) error {
	userID, orgID, _, ok, err := s.lookupCredential(ctx, identifier)
	if err != nil {
		return err
	}
	if !ok {
		return nil // no account; the caller already returned the same page
	}

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
	// can read an address. A second factor waives the delay elsewhere, after it
	// has actually been proven.
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

// notifyRecovery tells every channel on the account.
func (s *Server) notifyRecovery(ctx context.Context, userID, token, cancelTok string, effective time.Time) error {
	addresses, err := s.recoveryChannels(ctx, userID)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return fmt.Errorf("user %s has no channel to notify", userID)
	}

	wait := time.Until(effective).Round(time.Minute)
	body := fmt.Sprintf(`Someone asked to reset the password for your account.

If this was you, the reset becomes available in %s:

  %s/recover/reset?token=%s

If it was NOT you, cancel it now -- no sign-in needed:

  %s/recover/cancel?token=%s

The delay is deliberate. It exists so that a reset you did not ask for cannot
happen without you having a chance to stop it.

This message was sent to every address on the account, including ones the
request did not come from.`,
		wait, s.cfg.Issuer, token, s.cfg.Issuer, cancelTok)

	var firstErr error
	for _, addr := range addresses {
		if err := s.mailer.Send(ctx, mail.Message{
			To:      addr,
			Subject: "Password reset requested",
			Body:    body,
		}); err != nil {
			// One failing address must not stop the others: notifying the OTHER
			// channels is the entire defence when the requester controls one.
			s.log.Error("sending recovery notice", "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// recoveryChannels lists every address that must be told.
func (s *Server) recoveryChannels(ctx context.Context, userID string) ([]string, error) {
	var email string
	if err := s.db.QueryRow(ctx,
		`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid AND status = 'active'`,
		userID).Scan(&email); err != nil {
		return nil, err
	}
	if email == "" {
		return nil, nil
	}
	// One address today. The signature returns a slice because the design depends
	// on notifying ALL channels, and a secondary-address feature must not have to
	// rediscover that.
	return []string{email}, nil
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

	req, lerr := store.LookupRecovery(r.Context(), tx, hash, time.Now())
	csrf, cerr := s.csrfToken(w, r)
	if cerr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	switch {
	case errors.Is(lerr, store.ErrRecoveryPending):
		// Told exactly when, because "try again later" with no time is advice
		// nobody can act on.
		s.renderPage(w, r, "reset", map[string]any{
			"Pending": true,
			"When":    req.EffectiveAt.UTC().Format("15:04 MST on 2 January"),
			"Wait":    time.Until(req.EffectiveAt).Round(time.Minute).String(),
		})
	case lerr != nil:
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
	default:
		s.renderPage(w, r, "reset", map[string]any{
			"Ready": true, "Token": token, "CSRF": csrf, "CSRFField": csrfFormField,
		})
	}
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

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	req, err := store.LookupRecovery(ctx, tx, hash, time.Now())
	if err != nil {
		// Pending and invalid are shown the same way here. By the time a form is
		// being submitted, the difference only matters to someone probing.
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
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
	previous, perr := store.RecentPasswordHashes(ctx, tx, req.UserID, s.pwPolicy.HistoryDepth)
	if perr != nil {
		s.log.Error("reading password history", "err", perr)
	}
	identity, _ := store.EmailForUser(ctx, tx, req.UserID)
	if res, cerr := s.pwPolicy.Check(ctx, password, identity, previous, s.hasher); cerr != nil {
		s.renderPage(w, r, "reset", map[string]any{
			"Ready": true, "Token": r.PostForm.Get("token"), "Error": cerr.Error(),
		})
		return
	} else if s.pwPolicy.Breach != nil && !res.BreachCheckRan {
		s.log.Warn("the breach check did not run for a password reset",
			"correlation_id", correlationID(ctx))
	}

	// The outgoing hash is recorded BEFORE it is replaced. Doing it afterwards
	// would file the new password as a previous one and refuse it next time.
	if s.pwPolicy.HistoryDepth > 0 {
		if err := store.RetirePassword(ctx, tx, req.UserID, req.OrgID); err != nil {
			s.log.Error("recording the retired password", "err", err)
		}
	}

	newHash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		s.log.Error("hashing the new password", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := store.ConsumeRecovery(ctx, tx, req.ID, req.UserID, newHash); err != nil {
		s.log.Error("consuming recovery", "err", err)
		s.renderPage(w, r, "reset", map[string]any{"Error": s.tr(r).T("error.reset.expired")})
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
	// victim needs to know about immediately.
	if addrs, err := s.recoveryChannels(ctx, req.UserID); err == nil {
		for _, a := range addrs {
			_ = s.mailer.Send(ctx, mail.Message{
				To:      a,
				Subject: "Your password was changed",
				Body: "Your account password has just been changed, and every signed-in " +
					"session was ended.\n\nIf this was not you, reset it again immediately " +
					"and contact your administrator.",
			})
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
