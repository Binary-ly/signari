package httpapi

import (
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
		http.Redirect(w, r, parkLogin("/apps"), http.StatusSeeOther)
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

	s.renderPage(w, r, "portal", map[string]any{
		"Open": open, "Blocked": blocked,
		"Empty": len(open) == 0 && len(blocked) == 0,
	})
}
