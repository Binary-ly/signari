package httpapi

import (
	"errors"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/store"
)

// logoutTokenBodyLimit is more than any logout token needs; the endpoint is open.
const logoutTokenBodyLimit = 16 << 10

// handleFederatedBackchannelLogout ends the sessions of somebody whose provider says
// they signed out there (8.19). The token is the only authentication. Every session
// the person has here ends: a session records no provider, so nothing could tell one
// from another, and a person signed out upstream keeping a session here is the failure
// this exists to stop. A token naming only a session is refused, since nothing here
// records the provider's session ids.
//
// A retry and an unknown subject are both answered as done: the provider asked for
// this person to have no session here, and they have none.
func (s *Server) handleFederatedBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")
	w.Header().Set("Cache-Control", "no-store")
	refuse := func(reason string) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": reason})
	}
	r.Body = http.MaxBytesReader(w, r.Body, logoutTokenBodyLimit)
	if err := r.ParseForm(); err != nil {
		refuse("the request could not be read")
		return
	}
	raw := r.PostForm.Get("logout_token")
	if raw == "" {
		refuse("no logout_token")
		return
	}
	provider, err := s.loadIdentityProvider(ctx, slug)
	if err != nil {
		// The same answer as a bad token, so the endpoint does not list providers.
		refuse("the logout token could not be verified")
		return
	}
	claims, err := provider.VerifyLogoutToken(ctx, s.outboundClient(federationTimeout), &s.assertionKeys, raw, time.Now())
	if err != nil {
		s.log.InfoContext(ctx, "a logout token was refused", "slug", slug, "err", err, "correlation_id", correlationID(ctx))
		refuse("the logout token could not be verified")
		return
	}
	if claims.Subject == "" {
		refuse("a logout token must name a subject here")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = store.ClaimAssertionJTI(ctx, tx, provider.ID, claims.ID, claims.IssuedAt.Add(2*federation.MaxLogoutTokenAge).Unix())
	if errors.Is(err, store.ErrAssertionReplayed) {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "recording a logout token", "slug", slug, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	userID, err := store.FindFederatedIdentity(ctx, tx, provider.ID, claims.Subject)
	if err != nil {
		s.log.ErrorContext(ctx, "finding who a logout token names", "slug", slug, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	ended := 0
	if userID != "" {
		term, err := store.TerminateSessions(ctx, tx, "", userID, store.ReasonSharedSignal)
		if err != nil {
			s.log.ErrorContext(ctx, "ending sessions on a logout token", "slug", slug, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		if term != nil {
			ended = term.Sessions
		}
		if err := audit.Write(ctx, tx, audit.Event{Type: "federation.backchannel_logout", OrgID: provider.OrgID,
			SubjectID: userID, Detail: map[string]any{"provider": slug, "sessions_ended": ended}}); err != nil {
			s.log.ErrorContext(ctx, "recording a back-channel logout", "slug", slug, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.WriteHeader(http.StatusOK)
}
