package httpapi

import (
	"errors"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// Starting and stopping support access from the browser.
//
// # Why it starts here and not in the admin API
//
// Impersonation produces a browser SESSION -- a cookie the administrator then
// browses with. An API that returns one would have to hand a session cookie to
// something that is not a browser, and whatever did the handing would become a
// way to mint sessions for arbitrary users with a bearer token. So the API
// records the authorisation and this issues the session, to the browser that
// asked, once.
//
// # Why stopping is not just deleting a cookie
//
// The session must be revoked server-side and the episode closed, or "stopped"
// means "this browser stopped showing it". The administrator's own session is
// not restored automatically: they sign in again as themselves, which is one
// extra step and removes any question about whose session is whose.

// handleImpersonateStart begins support access.
//
// POST /admin/impersonate  {user, reason}
//
// Requires an existing administrative session -- the actor is taken from THAT
// session, never from the request body. A parameter naming the actor is a
// parameter an attacker sets.
func (s *Server) handleImpersonateStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired")
		return
	}
	adminSID, actorID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}

	// The permission to do this at all. Checked before anything is written, so a
	// refusal leaves no trace of an attempt to act as somebody.
	may, err := store.MayImpersonate(ctx, s.db, orgID, actorID)
	if err != nil || !may {
		s.auditDetached(ctx, audit.Event{
			Type: "impersonation.refused", OrgID: orgID, SubjectID: actorID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "not_an_administrator"},
		})
		writeError(w, http.StatusForbidden, "forbidden",
			"you do not have permission to act as another user")
		return
	}

	target := r.PostForm.Get("user")
	reason := r.PostForm.Get("reason")

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	im, err := store.BeginImpersonation(ctx, tx, orgID, actorID, target,
		reason, correlationID(ctx), store.MaxImpersonation)
	if err != nil {
		if errors.Is(err, store.ErrImpersonationRefused) {
			// The refusals are safe to report: the caller is an authenticated
			// administrator of this organisation, and every one of them is about
			// their own request rather than about whether a user exists.
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		s.log.Error("beginning impersonation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sid, err := newSID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cookieToken, err := newSID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The session's acr and amr describe how the ADMINISTRATOR authenticated,
	// because that is what actually happened. Copying the subject's would claim
	// a factor nobody performed in this session, and a step-up requirement would
	// then be satisfied by an authentication that never took place.
	var amr []string
	if err := tx.QueryRow(ctx, `SELECT amr FROM core.sessions WHERE sid = $1`,
		adminSID).Scan(&amr); err != nil {
		s.log.Error("reading the administrator's factors", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	acr := oauth.ACRFromAMR(amr)

	// Bounded by the episode, not by the ordinary session lifetime. An eight-hour
	// cookie for thirty minutes of support access outlives its own authorisation.
	ttl := time.Until(im.ExpiresAt)
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3, $4, $5, $6, now(), now() + $7::interval)`,
		sid, store.HashToken(cookieToken), orgID, target, acr, amr,
		ttl.String()); err != nil {
		s.log.Error("creating an impersonated session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := store.AttachImpersonation(ctx, tx, im.ID, sid, actorID); err != nil {
		s.log.Error("attaching impersonation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Recorded against BOTH people. An investigation starts from whichever name
	// it has, and a trail findable only from the administrator's side is one the
	// user cannot use to find out what happened to their own account.
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "impersonation.started", OrgID: orgID, SubjectID: target,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"actor": actorID, "reason": reason,
			"expires_at": im.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}); err != nil {
		s.log.Error("auditing impersonation start", "err", err)
	}

	if err := tx.Commit(ctx); err != nil {
		s.log.Error("committing impersonation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.setSessionCookie(w, cookieToken)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleImpersonateStop ends it.
//
// Deliberately reachable by the impersonated session itself: the way out must
// be available from where you are, not only from the console you left.
func (s *Server) handleImpersonateStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired")
		return
	}
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := store.EndImpersonation(ctx, tx, sid, "stopped"); err != nil {
		s.log.Error("ending impersonation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "impersonation.ended", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"how": "stopped"},
	}); err != nil {
		s.log.Error("auditing impersonation end", "err", err)
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("committing the end of impersonation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The administrator signs in again as themselves. Restoring their previous
	// session automatically would mean keeping it alive throughout, and a
	// dormant administrative session is exactly what an attacker who reaches
	// this browser would want to find.
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}
