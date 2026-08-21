package httpapi

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
)

// OpenID Connect Front-Channel Logout 1.0.
//
// # Why this exists alongside back-channel logout
//
// Back-channel logout is server-to-server: reliable, retryable, invisible to the
// browser, and already the primary mechanism here. What it cannot reach is state
// the BROWSER holds -- a relying party keeping its session in a cookie the
// server never inspects, in local storage, or in a service worker is still
// signed in from the user's point of view after a perfect back-channel logout.
//
// So both run, and the result of each is reported rather than assumed.
//
// # What this page can and cannot promise
//
// It loads each relying party's logout URL in a frame. Whether the relying party
// then clears anything is entirely up to it, and we get no answer back -- a
// frame gives no completion signal that can be trusted across origins.
//
// Third-party cookie restrictions make it weaker still: a frame from another
// origin may be denied its own cookies, in which case the relying party cannot
// identify the session to end. That is a real and growing limitation, and the
// honest response is to say so rather than to report success because the frames
// were rendered.

// frontChannelTarget is one relying party to notify.
type frontChannelTarget struct {
	ClientID string
	URL      string
}

// frontChannelTargets lists the participating relying parties with a registered
// front-channel URI.
func (s *Server) frontChannelTargets(ctx context.Context, sid, issuer string) []frontChannelTarget {
	if sid == "" {
		return nil
	}
	rows, err := s.db.Query(ctx, `
		SELECT c.client_id, c.frontchannel_logout_uri, c.frontchannel_logout_session_required
		FROM core.session_clients sc
		JOIN core.clients c ON c.client_id = sc.client_id
		WHERE sc.sid = $1 AND c.frontchannel_logout_uri IS NOT NULL AND c.enabled
		ORDER BY c.client_id`, sid)
	if err != nil {
		s.log.Error("listing front-channel logout targets", "err", err)
		return nil
	}
	defer rows.Close()

	var out []frontChannelTarget
	for rows.Next() {
		var clientID, raw string
		var sessionRequired bool
		if err := rows.Scan(&clientID, &raw, &sessionRequired); err != nil {
			return out
		}

		// Built from the REGISTERED URI. Nothing from the request contributes,
		// because this URL is loaded by the browser and anything caller-supplied
		// here would be a way to make somebody's browser fetch a URL of the
		// attacker's choosing during their logout.
		u, err := url.Parse(raw)
		if err != nil {
			s.log.Error("a registered front-channel logout URI does not parse",
				"client_id", clientID, "err", err)
			continue
		}
		if sessionRequired {
			q := u.Query()
			q.Set("iss", issuer)
			// The sid identifies WHICH session ended. Without it a relying party
			// holding several sessions for one person ends all of them or none --
			// and "all of them" signs the user out of other devices they never
			// touched.
			q.Set("sid", sid)
			u.RawQuery = q.Encode()
		}
		out = append(out, frontChannelTarget{ClientID: clientID, URL: u.String()})
	}
	return out
}

// renderFrontChannelLogout shows the page that loads each relying party's
// logout URL.
//
// The frames load in PARALLEL, unlike the SAML logout chain which must be
// sequential. SAML needs each provider to redirect the browser onward, so the
// hops are serial by construction; here each frame is independent, so the whole
// thing takes as long as the slowest one rather than the sum.
func (s *Server) renderFrontChannelLogout(w http.ResponseWriter, r *http.Request,
	targets []frontChannelTarget, continueTo string) {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// This page must not itself be framed: a logout page inside somebody else's
	// frame is a way to sign a user out without their knowledge.
	w.Header().Set("X-Frame-Options", "DENY")
	// frame-src is deliberately broad because the frames ARE the point, and the
	// URLs are registered rather than caller-supplied. Everything else is denied:
	// no script, no styles from elsewhere, and no form submission.
	setCSP(w, "default-src 'none'; frame-src https:; style-src 'unsafe-inline'; "+
		"frame-ancestors 'none'")

	if continueTo == "" {
		continueTo = "/"
	}
	_ = frontChannelPage.Execute(w, map[string]any{
		"Targets":    targets,
		"ContinueTo": continueTo,
		// Seconds before the page moves on regardless. A relying party that never
		// loads must not leave the user staring at a blank page -- and no
		// completion signal is available to wait for anyway.
		"WaitSeconds": 2,
	})
}

// frontChannelPage renders without JavaScript for the redirect.
//
// A meta refresh, not a script: the CSP on this page forbids script entirely,
// and adding 'unsafe-inline' to allow one would weaken the page that renders
// third-party URLs. The frames still load; only the continuation is declarative.
var frontChannelPage = template.Must(template.New("fclogout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="{{.WaitSeconds}};url={{.ContinueTo}}">
<title>Signing out&hellip;</title>
<style>body{font-family:system-ui,sans-serif;max-width:24rem;margin:4rem auto;padding:0 1rem}
iframe{display:none}p{color:#444}</style></head>
<body>
<h1>Signing you out</h1>
<p>Signing you out of {{len .Targets}} application(s). This page will continue
automatically.</p>
{{range .Targets}}<iframe src="{{.URL}}" title="logout"></iframe>{{end}}
<p><a href="{{.ContinueTo}}">Continue now</a></p>
</body></html>`))
