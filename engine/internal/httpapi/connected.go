package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// The applications a user has granted access to, and the button that takes it
// away.
//
// This existed as two store functions and no way to reach either. The comment
// on one of them said, correctly, that without it "a user can grant access and
// never see it again, which is consent as a formality rather than a control" --
// and it was written above a function nothing called. A consent screen with no
// matching revoke screen is a record of a decision the user cannot revisit.

type connectedApp struct {
	ClientID     string
	Name         string
	Scopes       []string
	Granted      string
	ActiveTokens int
	// OfflineUntil is the date its offline access ends, empty for none.
	OfflineUntil string
}

// handleConnectedApps lists what the user has granted.
func (s *Server) handleConnectedApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/connected"), http.StatusSeeOther)
		return
	}

	apps, err := store.ConnectedApps(ctx, s.db, userID)
	if err != nil {
		s.log.Error("listing connected applications", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	view := make([]connectedApp, 0, len(apps))
	for _, a := range apps {
		app := connectedApp{
			ClientID: a.ClientID, Name: a.DisplayName, Scopes: a.Scopes,
			Granted: a.GrantedAt.Format("2 January 2006"), ActiveTokens: a.ActiveTokens,
		}
		if a.OfflineUntil != nil {
			app.OfflineUntil = a.OfflineUntil.Format("2 January 2006")
		}
		view = append(view, app)
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("issuing a CSRF token", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	htmlPageHeaders(w)
	s.renderPage(w, r, "connected", map[string]any{
		"Apps":    view,
		"CSRF":    csrf,
		"Message": r.URL.Query().Get("m"),
	})
}

// handleConnectedRevoke withdraws consent and revokes the tokens.
func (s *Server) handleConnectedRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		// A cross-site POST that removes an application's access is a nuisance
		// rather than a takeover, and it is still somebody else deciding what
		// happens to this account.
		http.Error(w, "that request could not be verified", http.StatusBadRequest)
		return
	}
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/connected"), http.StatusSeeOther)
		return
	}
	if s.credentialChangeRefused(w, r, sid, "/account/connected", false) {
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if clientID == "" {
		http.Redirect(w, r, "/account/connected", http.StatusSeeOther)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Scoped to THIS user. The client id arrives from a form field, so the only
	// thing stopping it naming somebody else's grant is that the query is keyed
	// on the session's user as well.
	revoked, err := store.DisconnectApp(ctx, tx, userID, clientID, "user disconnected the application")
	if err != nil {
		s.log.Error("disconnecting an application", "err", err, "client_id", clientID)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "consent.withdrawn", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"client_id": clientID, "families_revoked": revoked,
		},
	}); aerr != nil {
		s.log.Error("recording the withdrawal", "err", aerr)
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// Honest about the window. An access token already issued is self-contained
	// and stays valid until it expires; saying "removed" full stop would be the
	// more comfortable message and the false one. The window is this client's
	// lifetime, which is set per client. A lifetime lowered within the last hour
	// leaves earlier tokens to the one they were minted with; that is said to
	// the operator who lowers it, not to somebody revoking an application.
	window := tokens.DefaultAccessTokenTTL
	if c, cerr := clients.Lookup(ctx, s.db, clientID); cerr == nil {
		window = c.AccessTokenTTL()
	}
	msg := "Access removed. The application can no longer obtain new tokens, and " +
		"any it already holds stop working within " +
		window.Round(time.Minute).String() + "."
	http.Redirect(w, r, "/account/connected?m="+url.QueryEscape(msg), http.StatusSeeOther)
}
