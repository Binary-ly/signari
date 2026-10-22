package httpapi

import (
	"errors"
	"net/http"
	"strconv"
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
		"Slug": p.Slug, "Title": p.Title, "Body": p.Body, "Fields": p.Fields, "Version": p.Version,
		"CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// setPendingCookie mints the short-lived token that carries a login in flight.
func (s *Server) setPendingCookie(w http.ResponseWriter, userID, orgID string,
	amr []string, authzQuery string) error {
	return s.setPendingCookieFor(w, userID, orgID, amr, authzQuery, "")
}

// setPendingCookieFor is setPendingCookie for a sign-in only one stage's pages
// may continue (pendingClaims.Stage).
func (s *Server) setPendingCookieFor(w http.ResponseWriter, userID, orgID string,
	amr []string, authzQuery, stage string) error {

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
		Stage: stage,
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
	rerender := func(msg string) {
		csrf, _ := s.csrfToken(w, r)
		s.renderPage(w, r, "prompt", map[string]any{
			"Slug": p.Slug, "Title": p.Title, "Body": p.Body, "Fields": p.Fields, "Version": p.Version,
			"Error": msg, "CSRF": csrf, "CSRFField": csrfFormField,
		})
	}
	// The version the person was shown (5.13). Edited since, the answer would be
	// to text they did not read, so the current text is shown instead.
	shown, _ := strconv.Atoi(r.PostFormValue("version"))
	if shown != p.Version {
		rerender(s.tr(r).Text("error.prompt.changed"))
		return
	}
	answers, verr := p.ValidateAnswers(submitted)
	if verr != nil {
		rerender(verr.Error())
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := store.RecordAnswer(ctx, tx, p.ID, p.Version, pending.Subject, pending.OrgID,
		answers); errors.Is(err, store.ErrPromptChanged) {
		_ = tx.Rollback(ctx)
		if fresh, lerr := store.LoadPrompt(ctx, s.db, pending.OrgID, p.Slug); lerr == nil {
			p = fresh
		}
		rerender(s.tr(r).Text("error.prompt.changed"))
		return
	} else if err != nil {
		s.log.Error("recording a prompt answer", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Answers that are attributes (5.14), in the answer's transaction, so the
	// two commit together and a claim mapper can release them from the next
	// token on. A field left blank leaves its attribute as it was. The operator
	// mapped the field, so this does not ask user_writable, which governs the
	// person's own profile page.
	var written []string
	for _, f := range p.Fields {
		if f.Attribute == "" || answers[f.Name] == "" {
			continue
		}
		if err := store.SetUserAttribute(ctx, tx, pending.Subject, pending.OrgID, f.Attribute,
			answers[f.Name], s.root); errors.Is(err, store.ErrInvalidAttributeValue) {
			_ = tx.Rollback(ctx)
			rerender(f.Label + ": " + err.Error())
			return
		} else if err != nil {
			s.log.Error("writing a prompt answer to its attribute", "err", err, "attribute", f.Attribute)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		written = append(written, f.Attribute)
	}
	if len(written) > 0 {
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "user.attributes_updated", OrgID: pending.OrgID, SubjectID: pending.Subject,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"by": "prompt", "prompt": p.Slug, "attributes": written},
		}); err != nil {
			s.log.Error("auditing the attributes a prompt wrote", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// Recorded in the audit trail as well as the response table. "When did they
	// accept the terms" is asked later by somebody who does not have access to
	// the application database and does have the audit export.
	// In the answer's own transaction, so the record and the answer commit
	// together. A detached write took a second connection while this one was
	// held.
	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "prompt.answered", OrgID: pending.OrgID, SubjectID: pending.Subject,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"prompt": p.Slug, "version": p.Version},
	}); aerr != nil {
		s.log.Error("auditing a prompt answer", "err", aerr)
	}

	// Back into the funnel. Any remaining prompt is picked up by the same check,
	// so several in sequence need no special handling.
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, pending.AMR, pending.Authz)
}
