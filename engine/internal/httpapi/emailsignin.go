package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// An emailed code as the first factor (5.16).
//
// Identifier-first: the sign-in form's "Email me a code" sends what was typed
// to /login/email, which answers with the same page whether or not an account
// has that name -- the code is queued in the outbox and minted when it is
// sent, so no mail goes out while the page waits -- and the code typed at
// /login/email/verify is the sign-in, recorded as amr `otp` and single-factor.
// It is offered only where the organisation's sign-in flow takes it
// (`email_otp` with `proved_by_email`), because a code to a mailbox is weaker
// than a password against anybody who reads that mailbox.
//
// What the page holds between the two is its own cookie, never the pending
// sign-in token. A pending token says the first factor is proven, and the
// second-factor page accepts any; one issued here, naming the account before
// any code came back, would have let a second factor alone sign in.
//
// And it is sealed under the root key, not signed. A signed token is readable
// by whoever holds it, and this one is handed to anybody who types a name: the
// account's id, the same on every request, against a fresh random one for a
// name nobody has, told them which names were accounts however alike the pages
// read. Sealed, with random ids of the same length for nobody, two requests
// differ the same way whatever was typed.

const (
	emailCodeContext    = "signari email sign-in page"
	EmailCodeCookieName = "__Host-signari_emailcode"
	emailCodeStep       = 15 * time.Minute
)

type emailCodeClaims struct {
	Subject string `json:"sub"`
	OrgID   string `json:"org"`
	Authz   string `json:"authz,omitempty"`
	Expiry  int64  `json:"exp"`
}

// emailSignInOffered reports whether the organisation's sign-in flow takes an
// emailed code alone. orgID is empty for a page that names no organisation in
// a deployment with several, and then it is offered where some organisation's
// flow takes it: which account a name is decides which flow applies, as for a
// password. Never without the root key, which the page's cookie is sealed by.
func (s *Server) emailSignInOffered(ctx context.Context, orgID string) bool {
	if s.db == nil || s.cfg.Root == nil {
		return false
	}
	if orgID != "" {
		fl := s.flowFor(ctx, s.db, orgID, flow.Authentication)
		return fl != nil && fl.AdmitsProof(flow.StageEmailOTP)
	}
	// Loads the organisations' documents, once per process. One with none is
	// served the built-in flow, which takes no emailed code.
	_ = s.flowFor(ctx, s.db, "", flow.Authentication)
	s.flows.mu.RLock()
	defer s.flows.mu.RUnlock()
	for _, doc := range s.flows.byOrg {
		if fl, ok := doc.For(flow.Authentication); ok && fl.AdmitsProof(flow.StageEmailOTP) {
			return true
		}
	}
	return false
}

func (s *Server) setEmailCodeCookie(w http.ResponseWriter, subject, orgID, authz string) error {
	raw, err := json.Marshal(emailCodeClaims{
		Subject: subject, OrgID: orgID, Authz: authz, Expiry: time.Now().Add(emailCodeStep).Unix(),
	})
	if err != nil {
		return err
	}
	sealed, err := s.cfg.Root.Seal(raw, emailCodeContext)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: EmailCodeCookieName, Value: base64.RawURLEncoding.EncodeToString(sealed),
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(emailCodeStep.Seconds())})
	return nil
}

func (s *Server) readEmailCode(r *http.Request) (*emailCodeClaims, error) {
	c, err := r.Cookie(EmailCodeCookieName)
	if err != nil || c.Value == "" || s.cfg.Root == nil {
		return nil, errors.New("no emailed sign-in in progress")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, fmt.Errorf("malformed emailed sign-in: %w", err)
	}
	raw, err := s.cfg.Root.Open(sealed, emailCodeContext)
	if err != nil {
		return nil, err
	}
	var p emailCodeClaims
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("malformed emailed sign-in: %w", err)
	}
	if time.Now().After(time.Unix(p.Expiry, 0)) || p.Subject == "" || p.OrgID == "" {
		return nil, errors.New("the emailed sign-in expired")
	}
	return &p, nil
}

func (s *Server) renderEmailCode(w http.ResponseWriter, r *http.Request, msg string) {
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "emailcode", map[string]any{"Error": msg, "CSRF": csrf, "CSRFField": csrfFormField})
}

// handleEmailSignInStart asks for a code. The page is the same whatever is
// found; what differs is a row and a queued notice.
func (s *Server) handleEmailSignInStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		s.renderLoginStatus(w, r, r.PostForm.Get("authz"),
			"Your sign-in session expired. Please try again.", http.StatusForbidden)
		return
	}
	authz := r.PostForm.Get("authz")
	orgID := s.loginOrg(ctx, authz)
	if !s.emailSignInOffered(ctx, orgID) {
		s.renderLogin(w, r, authz, s.tr(r).Text("emailcode.unavailable"))
		return
	}
	identifier := strings.TrimSpace(r.PostForm.Get("username"))
	// Nobody, unless the name is somebody's: ids of the same shape either way.
	subject, subjectOrg := uuid.NewString(), uuid.NewString()
	if identifier != "" && s.allowRecovery(ctx, "emailsignin:ip:"+budgetIP(clientIP(r)), 20, time.Hour) {
		if userID, userOrg, ok := s.emailSignInAccount(ctx, identifier, orgID); ok {
			subject, subjectOrg = userID, userOrg
			// One a minute and five an hour per account, as recovery is paced:
			// over the pace the code already sent stays the one that works.
			if s.allowRecovery(ctx, "emailsignin:user:min:"+userID, 1, time.Minute) &&
				s.allowRecovery(ctx, "emailsignin:user:hour:"+userID, 5, time.Hour) {
				if err := s.startEmailSignIn(ctx, userID, userOrg); err != nil {
					s.log.Error("starting an emailed sign-in", "err", err, "correlation_id", correlationID(ctx))
				}
			}
		}
	}
	if err := s.setEmailCodeCookie(w, subject, subjectOrg, authz); err != nil {
		s.log.Error("issuing the emailed sign-in's token", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderEmailCode(w, r, "")
}

// emailSignInAccount is the one account a name holds whose organisation's flow
// takes an emailed code: in orgID, or in every organisation when it is empty.
// A name held in several is nobody's here, as on the password form
// (lookupCredential): the page cannot say which is meant.
func (s *Server) emailSignInAccount(ctx context.Context, identifier, orgID string) (userID, userOrg string, ok bool) {
	rows, err := s.db.Query(ctx, `
		SELECT id::text, org_id::text FROM core.users
		 WHERE ($1 = '' OR org_id::text = $1) AND status = 'active' AND email IS NOT NULL
		   AND (lower(email) = lower($2) OR lower(username) = lower($2))
		 ORDER BY org_id LIMIT 2`, orgID, identifier)
	if err != nil {
		s.log.Error("looking up an emailed sign-in's account", "err", err)
		return "", "", false
	}
	var found [][2]string
	for rows.Next() {
		var id, org string
		if err := rows.Scan(&id, &org); err != nil {
			rows.Close()
			s.log.Error("looking up an emailed sign-in's account", "err", err)
			return "", "", false
		}
		found = append(found, [2]string{id, org})
	}
	rows.Close()
	if rows.Err() != nil || len(found) != 1 || !s.emailSignInOffered(ctx, found[0][1]) {
		return "", "", false
	}
	return found[0][0], found[0][1], true
}

func (s *Server) startEmailSignIn(ctx context.Context, userID, orgID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartEmailSignIn(ctx, tx, userID, orgID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// deliverSignInCode sends the code a NoticeSignInCode names, minting it now.
func (s *Server) deliverSignInCode(ctx context.Context, n store.AccountNotice) error {
	var email string
	if err := s.db.QueryRow(ctx, `SELECT COALESCE(email, '') FROM core.users
		WHERE id = $1::uuid AND status = 'active'`, n.UserID).Scan(&email); err != nil || email == "" {
		// Gone, deactivated or without an address since it was asked for:
		// nothing to send, and trying again changes nothing.
		return nil
	}
	code, expires, err := store.MintEmailSignInCode(ctx, s.db, n.LinkID)
	if errors.Is(err, store.ErrEmailSignInInvalid) {
		return nil // replaced or expired before it went out
	}
	if err != nil {
		return err
	}
	tr := s.notifierFor(ctx, n.UserID)
	return s.mailer.Send(ctx, mail.Message{To: email, Subject: tr.Text("mail.emailsignin.subject"),
		Body: tr.Text("mail.emailsignin.body", map[string]any{
			"Code": code, "Until": expires.UTC().Format("15:04 MST"),
		})})
}

// handleEmailSignInVerify takes the code, and with it signs in.
func (s *Server) handleEmailSignInVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		s.renderLoginStatus(w, r, "", "Your sign-in session expired. Please try again.", http.StatusForbidden)
		return
	}
	pending, err := s.readEmailCode(r)
	if err != nil {
		s.renderLoginStatus(w, r, "", s.tr(r).Text("emailcode.expired"), http.StatusUnauthorized)
		return
	}
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	// The second-factor budget, keyed by the account the code is for: whoever
	// holds the page is the one guessing.
	if !s.allowSecondFactorAttempt(ctx, w, pending.Subject, ip) {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ok, err := store.VerifyEmailSignIn(ctx, tx, pending.Subject, strings.TrimSpace(r.PostForm.Get("code")))
	if err != nil {
		s.log.Error("checking an emailed sign-in code", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		// Committed: the count against the code outlives the refusal.
		if err := tx.Commit(ctx); err != nil {
			s.log.Error("committing a wrong emailed sign-in code", "err", err)
		}
		s.recordSecondFactorFailure(ctx, pending.Subject, ip)
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: pending.OrgID, SubjectID: pending.Subject,
			CorrelationID: correlationID(ctx), Detail: map[string]any{"reason": "bad_email_code"},
		})
		s.renderEmailCode(w, r, s.tr(r).Text("emailcode.wrong"))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: EmailCodeCookieName, Value: "", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	// One factor, possession of the mailbox: amr `otp`, which the sign-in flow
	// reads as proved_by_email and oauth.ACRFromAMR as single-factor.
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, []string{oauth.AMROTP}, pending.Authz)
}
