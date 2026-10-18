package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/sms"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// The second-factor step of sign-in.
//
// The shape that matters: a password that verifies does NOT create a session
// when the account has a confirmed second factor. It creates a short-lived
// PENDING authentication that can do nothing except present a code. Anything
// else -- issuing a session and "upgrading" it after the code, or setting a flag
// on a live session -- means a stolen password alone already produced something
// usable, which is precisely what the second factor exists to prevent.

// pendingTTL bounds how long a half-finished sign-in stays open. Long enough to
// read a code off a phone, short enough that an abandoned attempt on a shared
// machine is worthless within minutes.
const pendingTTL = 3 * time.Minute

// PendingCookieName carries the half-authenticated state. Same __Host- prefix
// and attributes as the session cookie: it is a credential, just a narrower one.
const PendingCookieName = "__Host-signari_pending"

// typPending keeps this token out of every other verification path. A pending
// token must never be accepted where an access or ID token is expected, and a
// distinct `typ` is what makes that structural rather than a convention.
const typPending = "pending+jwt"

// pendingClaims is a signed, stateless record of "the password step passed".
//
// Signed rather than stored: it is single-purpose, expires in minutes, and a
// table would need its own sweeping. It carries no session id and confers no
// access -- the only thing it can be exchanged for is a code prompt.
type pendingClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	OrgID    string   `json:"org"`
	AMR      []string `json:"amr"`
	Authz    string   `json:"authz,omitempty"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
}

// beginMFAChallenge issues the pending token and renders the code prompt.
//
// It reports failedOpen when Duo is unreachable, the deployment fails open and
// the person has nothing else to present. Nothing has been written to the
// response then: the caller records it (recordDuoFailOpen) and carries on to the
// session in its own transaction, without a second factor and without saying it
// had one.
func (s *Server) beginMFAChallenge(w http.ResponseWriter, r *http.Request,
	userID, orgID, authzQuery string, amr []string) (failedOpen bool) {
	return s.challengeMFA(w, r, s.probeDuo(r.Context(), s.db, userID, orgID),
		userID, orgID, authzQuery, amr)
}

// challengeMFA is beginMFAChallenge with Duo already probed, for a caller that
// probed while holding a transaction and has since released it.
func (s *Server) challengeMFA(w http.ResponseWriter, r *http.Request, p duoProbe,
	userID, orgID, authzQuery string, amr []string) (failedOpen bool) {

	// Duo takes the browser away entirely, so it is offered BEFORE the code
	// form is rendered -- a page asking for a code the person will never receive
	// is worse than no page. And before the pending cookie: Duo's callback is
	// tied to its own stored challenge, and a fail-open sign-in has no code
	// step for the cookie to admit anybody to.
	//
	// When Duo is configured but unreachable and the deployment fails closed,
	// startDuo renders the refusal itself; when it is not configured, or the
	// user is not enrolled, the ordinary code prompt follows.
	switch s.actOnDuo(w, r, p, userID, orgID, authzQuery, amr) {
	case duoTookOver:
		return false
	case duoFailedOpen:
		return true
	}

	key, err := s.cfg.Keys.Active(keys.ES256)
	if err != nil {
		// Fall back to whatever can sign; the algorithm is irrelevant here since
		// only this server ever verifies these.
		for _, alg := range s.cfg.Keys.Algorithms() {
			if k, e := s.cfg.Keys.Active(alg); e == nil {
				key, err = k, nil
				break
			}
		}
	}
	if err != nil {
		s.log.Error("no signing key for the pending token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}

	now := time.Now()
	tok, err := tokens.NewSigner(key).SignJSON(pendingClaims{
		Issuer: s.cfg.Issuer, Subject: userID, OrgID: orgID, AMR: amr,
		Authz: authzQuery, IssuedAt: now.Unix(), Expiry: now.Add(pendingTTL).Unix(),
	}, typPending)
	if err != nil {
		s.log.Error("signing the pending token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}

	http.SetCookie(w, &http.Cookie{
		Name: PendingCookieName, Value: tok, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(pendingTTL.Seconds()),
	})

	// If email is the enrolled factor, the code has to be sent now -- the person
	// is looking at a form asking for a code that does not exist yet.
	//
	// Failure here is logged and NOT surfaced: which factors somebody has
	// enrolled is not something an unauthenticated form should disclose, and the
	// challenge page is identical either way.
	s.sendEmailOTPIfEnrolled(r.Context(), userID)
	s.sendSMSOTPIfEnrolled(r.Context(), userID)

	s.renderMFA(w, r, authzQuery, "")
	return false
}

// sendEmailOTPIfEnrolled issues and mails a code, when that factor is enrolled.
//
// Best effort by design. A user with both an authenticator app and email
// enrolled can still use the app if mail is slow or broken, and blocking the
// sign-in because SMTP is down would turn a mail outage into an authentication
// outage.
func (s *Server) sendEmailOTPIfEnrolled(ctx context.Context, userID string) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.log.Error("beginning a transaction for the email code", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	code, address, err := store.IssueEmailOTP(ctx, tx, userID)
	switch {
	case errors.Is(err, store.ErrNoEmailOTP):
		return // not enrolled; nothing to do
	case errors.Is(err, store.ErrEmailOTPTooSoon):
		// A code was sent moments ago and is still live. Saying nothing is right:
		// the person has one in their inbox.
		return
	case err != nil:
		s.log.Error("issuing an email code", "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("storing an email code", "err", err)
		return
	}

	// The ACCOUNT HOLDER's language, not the requester's.
	//
	// It is tempting to use the request here on the grounds that whoever is
	// signing in is about to read this. But the code is delivered to the
	// ADDRESS ON THE ACCOUNT, so by construction the reader is the account
	// holder -- and if the person at the form is not them, this message is the
	// one telling them somebody has their password. That reader needs their own
	// language, not the browser language of whoever triggered it.
	//
	// The address-confirmation mail in enrol.go is the genuinely interactive
	// case and uses the request instead: there, the person at the form is
	// demonstrably the person who will read it.
	tr := s.notifierFor(ctx, userID)
	if err := s.mailer.Send(ctx, mail.Message{
		To:      address,
		Subject: tr.Text("mail.signincode.subject"),
		Body: tr.Text("mail.signincode.body", map[string]any{
			"Code":    code,
			"Minutes": int(store.EmailOTPLifetime.Minutes()),
		}),
	}); err != nil {
		// The code is already stored, so a resend can succeed later. Logged
		// rather than surfaced: telling the form that mail failed would confirm
		// the account exists and has email enrolled.
		s.log.Error("sending an email code", "err", err, "user_id", userID)
	}
}

// readPending verifies the pending cookie.
func (s *Server) readPending(r *http.Request) (*pendingClaims, error) {
	c, err := r.Cookie(PendingCookieName)
	if err != nil || c.Value == "" {
		return nil, errors.New("no pending authentication")
	}
	raw, err := tokens.VerifyTyped(s.cfg.Keys, s.cfg.Issuer, c.Value, typPending)
	if err != nil {
		return nil, err
	}
	var p pendingClaims
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("malformed pending token: %w", err)
	}
	if time.Now().After(time.Unix(p.Expiry, 0)) {
		return nil, errors.New("pending authentication expired")
	}
	if p.Subject == "" || p.OrgID == "" {
		return nil, errors.New("pending token names no subject")
	}
	return &p, nil
}

func (s *Server) clearPending(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: PendingCookieName, Value: "", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// handleMFAPost verifies a TOTP code or a recovery code and completes sign-in.
func (s *Server) handleMFAPost(w http.ResponseWriter, r *http.Request) {
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
		// Expired or absent: the user must start again. Deliberately vague --
		// the distinction between "expired" and "forged" helps only an attacker.
		s.clearPending(w)
		s.renderLoginStatus(w, r, r.PostForm.Get("authz"),
			"Your sign-in session expired. Please sign in again.", http.StatusUnauthorized)
		return
	}

	code := r.PostForm.Get("code")
	const generic = "That code is not valid."

	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	if !s.allowSecondFactorAttempt(ctx, w, pending.Subject, ip) {
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	res, err := s.verifySecondFactor(ctx, tx, pending.Subject, code)
	if err != nil {
		// Released before rendering, which takes a connection of its own.
		_ = tx.Rollback(ctx)
		s.log.Error("verifying second factor", "err", err)
		s.renderMFA(w, r, pending.Authz, "Something went wrong. Please try again.")
		return
	}
	if !res.OK {
		// Committed: the failure counter and any lockout must persist even
		// though the sign-in did not. Rolling back here would make the lockout
		// unreachable, since every failed attempt would undo its own record.
		if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing failed second factor", "err", err)
		}
		s.recordSecondFactorFailure(ctx, pending.Subject, ip)
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: pending.OrgID, SubjectID: pending.Subject,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "bad_second_factor"},
		})
		s.factorsDisabled(ctx, pending.OrgID, pending.Subject, res.Disabled)
		s.renderMFA(w, r, pending.Authz, generic)
		return
	}
	amr := res.AMR

	// Both factors are now proven. amr records what ACTUALLY happened, and acr is
	// derived from it rather than asserted.
	//
	// AMRMFA is appended because two DISTINCT factors were used, which is exactly
	// what acr.go:93 says the value asserts -- and because deriving it from the
	// concatenation alone is wrong whenever both factors land in the same
	// category. A passkey without user verification reports ["user","hwk"], all
	// possession; adding a TOTP code gives ["user","hwk","otp"], still possession
	// only, so ACRFromAMR would answer single-factor after a second factor had
	// genuinely been presented. The sequencer would then demand the same code
	// again, and again. `duo.go:210` already appends it for this reason.
	full := append(append(append([]string{}, pending.AMR...), amr...), oauth.AMRMFA)
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, full, pending.Authz)
}

// The second-factor guessing budget.
//
// Two limits, both charged only by a wrong code and read before one is checked,
// in the same way as the password step (allowSignInAttempt):
//
//   - Per account, keyed by the user the password step proved. Unlike the sign-in
//     form's per-account key this one cannot be chosen by a stranger: only
//     somebody holding the password reaches the code step, so it can be tight.
//     It is what bounds recovery-code guessing for an account whose second
//     factor is not an authenticator app, which had no limit at all.
//   - Per address, the sign-in form's own `signin:fail:ip:` bucket. A guess is a
//     guess whichever box it was typed into; two doors onto one budget, for the
//     reason ldapauth.go gives.
//
// The per-factor counters in store (the TOTP pause, and the consecutive ceiling
// that disables a factor) sit under these and are what NIST SP 800-63B §3.2.2
// asks for. These bound the rate; those bound the total.
const (
	secondFactorPerAccountLimit  = 10
	secondFactorPerAccountWindow = 15 * time.Minute
)

func secondFactorAccountKey(userID string) string { return "mfa:fail:user:" + userID }

// allowSecondFactorAttempt answers 429 and returns false when either budget is
// spent. ip is empty where the client's address is not the person's -- an
// outpost relaying for a desktop -- and then only the account is checked.
func (s *Server) allowSecondFactorAttempt(ctx context.Context, w http.ResponseWriter, userID, ip string) bool {
	check := func(key string, limit int, window time.Duration) bool {
		n, err := store.CountRate(ctx, s.db, key, window)
		if err != nil {
			// Fail closed, as the password step does: verifying the code needs
			// the database one query later anyway.
			s.log.Error("checking the second-factor rate limit", "err", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "please try again")
			return false
		}
		if n >= limit {
			s.tooManyAttempts(w, window)
			return false
		}
		return true
	}
	if ip != "" && !check("signin:fail:ip:"+ip, signInPerIPLimit, signInPerIPWindow) {
		return false
	}
	return check(secondFactorAccountKey(userID), secondFactorPerAccountLimit,
		secondFactorPerAccountWindow)
}

// recordSecondFactorFailure charges a wrong code to both budgets.
func (s *Server) recordSecondFactorFailure(ctx context.Context, userID, ip string) {
	if ip != "" {
		if _, err := store.AllowRate(ctx, s.db, "signin:fail:ip:"+ip,
			signInPerIPLimit, signInPerIPWindow); err != nil {
			s.log.Error("recording a second-factor failure", "err", err)
		}
	}
	if _, err := store.AllowRate(ctx, s.db, secondFactorAccountKey(userID),
		secondFactorPerAccountLimit, secondFactorPerAccountWindow); err != nil {
		s.log.Error("recording a second-factor failure", "err", err)
	}
}

// factorsDisabled records and announces each factor a failed code switched off.
//
// Called after the failure is committed. The account holder is told on every
// channel they have, in their own language: whoever disabled the factor holds
// their password, so the notice is the thing that tells them to change it.
func (s *Server) factorsDisabled(ctx context.Context, orgID, userID string, disabled []string) {
	for _, factor := range disabled {
		s.auditDetached(ctx, audit.Event{
			Type: "mfa.factor_disabled", OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail: map[string]any{
				"factor": factor, "reason": "consecutive_failures",
				"limit": s.failureLimit(),
			},
		})
		s.log.Warn("second factor disabled after consecutive failures",
			"user_id", userID, "factor", factor, "limit", s.failureLimit())

		tr := s.notifierFor(ctx, userID)
		var err error
		switch factor {
		case factorTOTP:
			err = s.notifyAccount(ctx, userID, tr.Text("mail.totp.disabled.subject"),
				tr.Text("mail.totp.disabled.body"), tr.Text("sms.totp.disabled"))
		case factorRecoveryCodes:
			err = s.notifyAccount(ctx, userID, tr.Text("mail.recoverycodes.disabled.subject"),
				tr.Text("mail.recoverycodes.disabled.body"), tr.Text("sms.recoverycodes.disabled"))
		}
		if err != nil {
			s.log.Error("telling the account holder a factor was disabled",
				"user_id", userID, "factor", factor, "err", err)
		}
	}
}

// The factors a failed code can disable, as named in the audit record.
const (
	factorTOTP          = "totp"
	factorRecoveryCodes = "recovery_codes"
)

// secondFactorResult is what one presented code did.
type secondFactorResult struct {
	AMR []string
	OK  bool
	// Disabled names each factor this failure switched off, for the caller to
	// record and announce once the failure is committed.
	Disabled []string
}

// verifySecondFactor accepts a TOTP, email, SMS or recovery code.
//
// Recovery codes are tried only after TOTP fails, so a recovery code is never
// consumed by a user who simply mistyped their authenticator code.
//
// A wrong code is charged to each factor it could have been a guess at -- the
// authenticator when it has the authenticator's shape, the recovery codes when
// it has theirs -- because §3.2.2 counts failures per authenticator, and a
// mistyped six-digit code charged to the recovery codes would let ordinary
// typing errors disable the codes kept for the day the phone is gone. Email and
// SMS codes count their own attempts per code (store.VerifyEmailOTP).
func (s *Server) verifySecondFactor(ctx context.Context, tx pgx.Tx, userID, code string) (secondFactorResult, error) {
	var res secondFactorResult
	cred, err := store.LoadTOTP(ctx, tx, userID, s.cfg.Root)
	switch {
	case errors.Is(err, store.ErrTOTPLocked), errors.Is(err, store.ErrTOTPDisabled):
		// Not tried and not charged. The other factors still are, each with its
		// own limit -- which is what lets somebody whose authenticator an
		// attacker paused or disabled sign in with a recovery code.
	case errors.Is(err, store.ErrNoTOTP):
		// No authenticator; the other factors are what is available.
	case err != nil:
		return res, err
	default:
		counter, verr := mfa.Verify(cred.Secret, code, time.Now(), cred.Digits,
			cred.Period, mfa.DefaultSkew, cred.LastCounter)
		if verr == nil {
			if err := store.RecordTOTPSuccess(ctx, tx, userID, counter); err != nil {
				return res, err
			}
			return secondFactorResult{AMR: []string{"otp"}, OK: true}, nil
		}
	}

	// Email code next. Checked before recovery codes because it is the factor a
	// user who chose it will actually be holding -- and because a recovery code
	// is the last resort, not the second guess.
	if ok, eerr := store.VerifyEmailOTP(ctx, tx, userID, strings.TrimSpace(code)); eerr != nil {
		return res, eerr
	} else if ok {
		return secondFactorResult{AMR: []string{"otp"}, OK: true}, nil
	}

	// SMS. The amr value is "sms", NOT "otp".
	//
	// RFC 8176 has both, and the difference is the point: a policy asking for a
	// phishing-resistant or possession-strong factor must be able to tell that
	// this one was satisfied by a text message, which SIM swap defeats without
	// any technical exploit. Reporting it as "otp" would make it indistinguishable
	// from an authenticator app in every record and every policy decision --
	// documenting the weakness and then erasing it in the one field that
	// machines read.
	if ok, serr := store.VerifySMSOTP(ctx, tx, userID, strings.TrimSpace(code)); serr != nil {
		return res, serr
	} else if ok {
		return secondFactorResult{AMR: []string{oauth.AMRSMS}, OK: true}, nil
	}

	used, err := store.ConsumeRecoveryCode(ctx, tx, userID, code)
	if err != nil {
		return res, err
	}
	if used {
		// `rba` is not right and `otp` would overstate it: a recovery code is a
		// possession factor the user wrote down. RFC 8176 has no better value,
		// so `otp` is used and the audit record carries the distinction.
		return secondFactorResult{AMR: []string{"otp"}, OK: true}, nil
	}

	// cred is nil when the authenticator was absent, paused or disabled: only
	// one that was actually tried is charged.
	if cred != nil && mfa.Plausible(code, cred.Digits) {
		f, err := store.RecordTOTPFailure(ctx, tx, userID, s.failureLimit())
		if err != nil {
			return res, err
		}
		if f.Disabled {
			res.Disabled = append(res.Disabled, factorTOTP)
		}
	}
	if store.CouldBeRecoveryCode(code) {
		f, err := store.RecordRecoveryCodeFailure(ctx, tx, userID, s.failureLimit())
		if err != nil {
			return res, err
		}
		if f.Disabled {
			res.Disabled = append(res.Disabled, factorRecoveryCodes)
		}
	}
	return res, nil
}

func (s *Server) renderMFA(w http.ResponseWriter, r *http.Request, authzQuery, msg string) {
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("minting csrf token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "sign-in unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	setCSP(w, `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")

	ref := ""
	status := http.StatusOK
	if msg != "" {
		status = http.StatusUnauthorized
		ref = shortCode(correlationID(r.Context()))
	}
	w.WriteHeader(status)
	s.renderPage(w, r, "mfa", map[string]any{
		"Authz": authzQuery, "Error": msg, "CSRF": csrf,
		"CSRFField": csrfFormField, "Reference": ref,
	})
}

// sendSMSOTPIfEnrolled texts a code, when that factor is enrolled and verified.
//
// Best effort, exactly like the email equivalent: a user with an authenticator
// app as well can still use it when the gateway is down, and blocking the
// sign-in on a third party's availability would turn their outage into ours.
//
// Only a VERIFIED number is texted. An unverified one is somebody's typo, and
// sending codes to it would be this engine spamming a stranger every time an
// account it does not own is signed into.
func (s *Server) sendSMSOTPIfEnrolled(ctx context.Context, userID string) {
	if s.texter == nil {
		return
	}
	verified, err := store.HasVerifiedSMS(ctx, s.db, userID)
	if err != nil {
		s.log.Error("checking the SMS factor", "err", err)
		return
	}
	if !verified {
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.log.Error("beginning a transaction for the SMS code", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	code, number, err := store.IssueSMSOTP(ctx, tx, userID)
	switch {
	case errors.Is(err, store.ErrNoSMSOTP):
		return
	case errors.Is(err, store.ErrSMSOTPTooSoon):
		// A code was sent moments ago and is still live. The person has it.
		return
	case err != nil:
		s.log.Error("issuing an SMS code", "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("storing an SMS code", "err", err)
		return
	}

	if err := s.sendSMS(ctx, userID, smsCode, sms.Message{
		To: number,
		// No link, and the issuer named. A code with a link in it trains people
		// to tap links in texts, which is the delivery mechanism for the attack
		// this factor is supposed to make harder.
		Body: fmt.Sprintf("%s: your sign-in code is %s. It expires in %d minutes. "+
			"If you did not request it, someone has your password.",
			s.cfg.Issuer, code, int(store.SMSOTPLifetime.Minutes())),
	}); err != nil {
		// Logged with the number redacted. A log line carrying a phone number is
		// a log line carrying the thing SIM swap targets.
		s.log.Error("sending the SMS code", "err", err, "to", sms.RedactNumber(number))
	}
}
