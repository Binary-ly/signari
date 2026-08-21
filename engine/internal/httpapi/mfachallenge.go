package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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
func (s *Server) beginMFAChallenge(w http.ResponseWriter, r *http.Request,
	userID, orgID, authzQuery string, amr []string) {

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
		return
	}

	now := time.Now()
	tok, err := tokens.NewSigner(key).SignJSON(pendingClaims{
		Issuer: s.cfg.Issuer, Subject: userID, OrgID: orgID, AMR: amr,
		Authz: authzQuery, IssuedAt: now.Unix(), Expiry: now.Add(pendingTTL).Unix(),
	}, typPending)
	if err != nil {
		s.log.Error("signing the pending token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: PendingCookieName, Value: tok, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(pendingTTL.Seconds()),
	})
	// Duo takes the browser away entirely, so it is offered BEFORE the code
	// form is rendered -- a page asking for a code the person will never receive
	// is worse than no page.
	//
	// startDuo reports whether it took over the response. When Duo is
	// configured but unreachable and the deployment fails closed, it renders the
	// refusal itself; when it is not configured, or the user is not enrolled, it
	// returns false and the ordinary code prompt follows.
	if s.startDuo(w, r, userID, orgID, authzQuery, amr) {
		return
	}

	// If email is the enrolled factor, the code has to be sent now -- the person
	// is looking at a form asking for a code that does not exist yet.
	//
	// Failure here is logged and NOT surfaced: which factors somebody has
	// enrolled is not something an unauthenticated form should disclose, and the
	// challenge page is identical either way.
	s.sendEmailOTPIfEnrolled(r.Context(), userID)
	s.sendSMSOTPIfEnrolled(r.Context(), userID)

	s.renderMFA(w, r, authzQuery, "")
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

	if err := s.mailer.Send(ctx, mail.Message{
		To:      address,
		Subject: "Your sign-in code",
		Body: fmt.Sprintf(
			"Your sign-in code is %s\n\n"+
				"It expires in %d minutes and can be used once.\n\n"+
				"If you did not just try to sign in, somebody has your password. "+
				"Change it, and tell whoever runs your systems.\n",
			code, int(store.EmailOTPLifetime.Minutes())),
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

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	amr, ok, err := s.verifySecondFactor(ctx, tx, pending.Subject, code)
	if err != nil {
		s.log.Error("verifying second factor", "err", err)
		s.renderMFA(w, r, pending.Authz, "Something went wrong. Please try again.")
		return
	}
	if !ok {
		// Committed: the failure counter and any lockout must persist even
		// though the sign-in did not. Rolling back here would make the lockout
		// unreachable, since every failed attempt would undo its own record.
		if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing failed second factor", "err", err)
		}
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: pending.OrgID, SubjectID: pending.Subject,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "bad_second_factor"},
		})
		s.renderMFA(w, r, pending.Authz, generic)
		return
	}

	// Both factors are now proven. amr records what ACTUALLY happened, and acr is
	// derived from it rather than asserted.
	full := append(append([]string{}, pending.AMR...), amr...)
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, full, pending.Authz)
}

// verifySecondFactor accepts either a TOTP code or a recovery code.
//
// Recovery codes are tried only after TOTP fails, so a recovery code is never
// consumed by a user who simply mistyped their authenticator code.
func (s *Server) verifySecondFactor(ctx context.Context, tx pgx.Tx, userID, code string) ([]string, bool, error) {
	cred, err := store.LoadTOTP(ctx, tx, userID, s.cfg.Root)
	switch {
	case errors.Is(err, store.ErrTOTPLocked):
		return nil, false, nil
	case errors.Is(err, store.ErrNoTOTP):
		// No authenticator; a recovery code is the only second factor available.
	case err != nil:
		return nil, false, err
	default:
		counter, verr := mfa.Verify(cred.Secret, code, time.Now(), cred.Digits,
			cred.Period, mfa.DefaultSkew, cred.LastCounter)
		if verr == nil {
			if err := store.RecordTOTPSuccess(ctx, tx, userID, counter); err != nil {
				return nil, false, err
			}
			return []string{"otp"}, true, nil
		}
	}

	// Email code next. Checked before recovery codes because it is the factor a
	// user who chose it will actually be holding -- and because a recovery code
	// is the last resort, not the second guess.
	if ok, eerr := store.VerifyEmailOTP(ctx, tx, userID, strings.TrimSpace(code)); eerr != nil {
		return nil, false, eerr
	} else if ok {
		return []string{"otp"}, true, nil
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
		return nil, false, serr
	} else if ok {
		return []string{oauth.AMRSMS}, true, nil
	}

	used, err := store.ConsumeRecoveryCode(ctx, tx, userID, code)
	if err != nil {
		return nil, false, err
	}
	if used {
		// `rba` is not right and `otp` would overstate it: a recovery code is a
		// possession factor the user wrote down. RFC 8176 has no better value,
		// so `otp` is used and the audit record carries the distinction.
		return []string{"otp"}, true, nil
	}

	if cred != nil {
		if _, err := store.RecordTOTPFailure(ctx, tx, userID); err != nil {
			return nil, false, err
		}
	}
	return nil, false, nil
}

var mfaPage = template.Must(template.New("mfa").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Two-factor authentication</title>
<style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}
label{display:block;margin:.75rem 0 .25rem}input{width:100%;padding:.5rem;font-size:1.25rem;letter-spacing:.2em}
button{margin-top:1rem;padding:.6rem 1rem;font-size:1rem;width:100%}
.err{color:#b00020;margin:.5rem 0}.hint{color:#666;font-size:.85rem}
.ref{color:#666;font-size:.85rem;margin:.25rem 0}</style></head>
<body>
<h1>Two-factor authentication</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Reference}}<p class="ref">Reference: <code>{{.Reference}}</code></p>{{end}}
<form method="POST" action="/login/mfa">
<input type="hidden" name="authz" value="{{.Authz}}">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
<label for="c">Code from your authenticator app</label>
<input id="c" name="code" inputmode="numeric" autocomplete="one-time-code"
       autofocus required pattern="[0-9A-Za-z\- ]+">
<p class="hint">Lost your device? Enter one of your recovery codes instead.</p>
<button type="submit">Continue</button>
</form>
</body></html>`))

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
	_ = mfaPage.Execute(w, map[string]string{
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

	if err := s.texter.Send(ctx, sms.Message{
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
