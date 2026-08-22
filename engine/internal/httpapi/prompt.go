package httpapi

import (
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Prompts shown between authentication and the session.
//
// # Where the state lives
//
// The same signed pending token MFA uses: the person is authenticated, and the
// token carries who they are, what factors they used and where they were going,
// for as long as it takes to answer. Nothing is stored server-side for a login
// in flight, and nothing about them is in a URL.
//
// A session is NOT established first. Answering a prompt afterwards would mean
// the prompt is advisory — a signed-in person can simply navigate elsewhere —
// and a terms notice that can be walked past is not a terms notice.

// beginPrompt renders a prompt and holds the login.
func (s *Server) beginPrompt(w http.ResponseWriter, r *http.Request,
	userID, orgID string, amr []string, authzQuery string, p prompts.Prompt) {

	if err := s.setPendingCookie(w, userID, orgID, amr, authzQuery); err != nil {
		s.log.Error("issuing the pending token for a prompt", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "prompt", map[string]any{
		"Slug": p.Slug, "Title": p.Title, "Body": p.Body, "Fields": p.Fields,
		"CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// setPendingCookie mints the short-lived token that carries a login in flight.
func (s *Server) setPendingCookie(w http.ResponseWriter, userID, orgID string,
	amr []string, authzQuery string) error {

	key, err := s.cfg.Keys.Active(keys.ES256)
	if err != nil {
		for _, alg := range s.cfg.Keys.Algorithms() {
			if k, e := s.cfg.Keys.Active(alg); e == nil {
				key, err = k, nil
				break
			}
		}
	}
	if err != nil {
		return err
	}
	now := time.Now()
	tok, err := tokens.NewSigner(key).SignJSON(pendingClaims{
		Issuer: s.cfg.Issuer, Subject: userID, OrgID: orgID, AMR: amr,
		Authz: authzQuery, IssuedAt: now.Unix(), Expiry: now.Add(pendingTTL).Unix(),
	}, typPending)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: PendingCookieName, Value: tok, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(pendingTTL.Seconds()),
	})
	return nil
}

// handlePromptPost records an answer and continues the sign-in.
func (s *Server) handlePromptPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden",
			"that form has expired; sign in again")
		return
	}
	pending, err := s.readPending(r)
	if err != nil {
		// The token expired or was never there. Back to the start rather than a
		// message about tokens, which means nothing to whoever is reading it.
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	p, err := store.LoadPrompt(ctx, s.db, pending.OrgID, r.PostFormValue("prompt"))
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	submitted := prompts.Answers{}
	for _, f := range p.Fields {
		if f.Name != "" {
			submitted[f.Name] = r.PostFormValue(f.Name)
		}
	}
	answers, verr := p.ValidateAnswers(submitted)
	if verr != nil {
		csrf, _ := s.csrfToken(w, r)
		s.renderPage(w, r, "prompt", map[string]any{
			"Slug": p.Slug, "Title": p.Title, "Body": p.Body, "Fields": p.Fields,
			"Error": verr.Error(), "CSRF": csrf, "CSRFField": csrfFormField,
		})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := store.RecordAnswer(ctx, tx, p.ID, pending.Subject, pending.OrgID,
		answers); err != nil {
		s.log.Error("recording a prompt answer", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Recorded in the audit trail as well as the response table. "When did they
	// accept the terms" is asked later by somebody who does not have access to
	// the application database and does have the audit export.
	s.auditDetached(ctx, audit.Event{
		Type: "prompt.answered", OrgID: pending.OrgID, SubjectID: pending.Subject,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"prompt": p.Slug},
	})

	// Back into the funnel. Any remaining prompt is picked up by the same check,
	// so several in sequence need no special handling.
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, pending.AMR, pending.Authz)
}
