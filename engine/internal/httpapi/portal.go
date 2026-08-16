package httpapi

import (
	"html/template"
	"net/http"

	"signari.dev/engine/internal/store"
)

// The application portal.
//
// # Why the blocked ones are shown
//
// Every other product in this field silently omits an application a user
// cannot reach. That turns "why can't I get into Payroll?" into a support
// ticket, and the answer -- "you are not in the finance group" -- is one an
// operator has to look up by hand. It is the most common identity support
// burden there is, and it exists only because the product declines to say what
// it already knows.
//
// So a blocked application is listed with the reason it is blocked. The reason
// comes from the access policy, which already produces a human-readable message
// for exactly this purpose.
//
// # What that discloses, and the way out
//
// Listing a blocked application tells the user that application exists. For
// most estates that is not a secret -- people know their employer runs a
// payroll system -- and the support saving is worth it. Where it is a secret,
// `portal_hidden` keeps a client off the portal entirely, and the CLI says so
// when registering one.
//
// The trade is stated rather than assumed, because it IS a trade.

// handlePortal lists the applications a user can reach, and why not the others.
func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/apps"), http.StatusFound)
		return
	}

	candidates, err := store.ListPortalCandidates(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing portal applications", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// The session's factors, read once. The policy is evaluated per application
	// because a policy can name a client, so "may Alice reach this" is a
	// different question for each one.
	mfa, amr := sessionFactors(ctx, s.db, sid)

	type tile struct {
		Name, LaunchURL, LogoURI string
		Blocked                  bool
		Reason                   string
		Unlaunchable             bool
	}
	var open, blocked []tile

	for _, a := range candidates {
		name := a.DisplayName
		if name == "" {
			name = a.ClientID
		}
		if d := s.checkAccessPolicy(ctx, r, orgID, a.ClientID, userID, "openid", mfa, amr); d != nil {
			blocked = append(blocked, tile{Name: name, Blocked: true, Reason: d.Message})
			continue
		}
		open = append(open, tile{
			Name: name, LaunchURL: a.LaunchURL, LogoURI: a.LogoURI,
			// Reported rather than hidden: an application with no launch URL is
			// a configuration mistake, and omitting it is how it stays one.
			Unlaunchable: a.LaunchURL == "",
		})
	}

	s.renderPage(w, portalPage, map[string]any{
		"Open": open, "Blocked": blocked,
		"Empty": len(open) == 0 && len(blocked) == 0,
	})
}

var portalPage = template.Must(template.New("portal").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your applications</title><style>` + pageCSS + `
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:.75rem;margin:1rem 0}
.tile{display:block;padding:.9rem;border:1px solid #d4d4d8;border-radius:8px;text-decoration:none;color:inherit}
.tile:hover{border-color:#71717a}
.tile.blocked{opacity:.65;border-style:dashed}
.tile .why{display:block;margin-top:.35rem;font-size:.8rem;color:#52525b}
.tile img{max-height:2rem;margin-bottom:.4rem}
</style></head>
<body>
<h1>Your applications</h1>

{{if .Empty}}
<p>No applications have been set up yet.</p>
<p class="hint">An administrator registers one with <code>signari client create</code>.</p>
{{end}}

{{if .Open}}
<div class="tiles">
{{range .Open}}
  {{if .Unlaunchable}}
  <div class="tile blocked">{{if .LogoURI}}<img src="{{.LogoURI}}" alt="">{{end}}{{.Name}}
  <span class="why">You can use this, but no launch address is configured.
  Ask an administrator to set <code>-launch-url</code>.</span></div>
  {{else}}
  <a class="tile" href="{{.LaunchURL}}">{{if .LogoURI}}<img src="{{.LogoURI}}" alt="">{{end}}{{.Name}}</a>
  {{end}}
{{end}}
</div>
{{end}}

{{if .Blocked}}
<h2>Not available to you</h2>
<p class="hint">Listed with the reason, so you know what to ask for rather than
having to open a ticket to find out.</p>
<div class="tiles">
{{range .Blocked}}
<div class="tile blocked">{{.Name}}<span class="why">{{.Reason}}</span></div>
{{end}}
</div>
{{end}}

<p class="hint"><a href="/account">Your account and sign-in methods</a></p>
</body></html>`))
