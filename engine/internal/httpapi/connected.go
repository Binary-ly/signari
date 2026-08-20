package httpapi

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
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
}

var connectedTmpl = template.Must(template.New("connected").Parse(`<!doctype html>
<meta charset="utf-8"><title>Connected applications</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem}
 .app{border:1px solid #ddd;border-radius:.5rem;padding:1rem;margin:.75rem 0}
 .scopes{color:#555;font-size:.9rem;margin:.35rem 0}
 .meta{color:#777;font-size:.85rem}
 button{padding:.4rem .8rem}
 .none{color:#666}
 .note{background:#f6f6f6;border-radius:.5rem;padding:.75rem;font-size:.9rem;color:#444}
</style>
<h1>Connected applications</h1>
{{if .Message}}<p class="note">{{.Message}}</p>{{end}}
{{if not .Apps}}
  <p class="none">No application has been granted access to your account.</p>
{{else}}
  {{range .Apps}}
  <div class="app">
    <strong>{{.Name}}</strong>
    <div class="scopes">Can see: {{range $i, $s := .Scopes}}{{if $i}}, {{end}}{{$s}}{{end}}</div>
    <div class="meta">
      Granted {{.Granted}}.
      {{if gt .ActiveTokens 0}}{{.ActiveTokens}} active session(s).{{else}}No active session.{{end}}
    </div>
    <form method="post" action="/account/connected/revoke" style="margin-top:.6rem">
      <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
      <input type="hidden" name="client_id" value="{{.ClientID}}">
      <button type="submit">Remove access</button>
    </form>
  </div>
  {{end}}
{{end}}
<p class="meta"><a href="/account">Back to your account</a></p>
`))

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
		view = append(view, connectedApp{
			ClientID: a.ClientID, Name: a.DisplayName, Scopes: a.Scopes,
			Granted: a.GrantedAt.Format("2 January 2006"), ActiveTokens: a.ActiveTokens,
		})
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("issuing a CSRF token", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = connectedTmpl.Execute(w, map[string]any{
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
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/connected"), http.StatusSeeOther)
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
	revoked, err := store.DisconnectApp(ctx, tx, userID, clientID)
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
	// more comfortable message and the false one.
	msg := "Access removed. The application can no longer obtain new tokens, and " +
		"any it already holds stop working within " +
		tokens.DefaultAccessTokenTTL.Round(time.Minute).String() + "."
	http.Redirect(w, r, "/account/connected?m="+url.QueryEscape(msg), http.StatusSeeOther)
}
