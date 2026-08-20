package httpapi

import (
	"context"
	"html/template"
	"net/http"
)

// externalProvider is one sign-in button on the login page.
type externalProvider struct {
	Slug string
	Name string
}

// externalProviders lists the enabled external providers.
//
// Failure is deliberately silent: if this query fails the sign-in page still
// renders with a password form, which is a degraded page rather than no page at
// all. An identity provider whose login screen 500s because a secondary feature
// is unavailable has turned a small fault into an outage.
func (s *Server) externalProviders(ctx context.Context) []externalProvider {
	if s.db == nil {
		// No database configured at all. The sign-in form still has to render --
		// that is the whole point of failing quietly here -- and a nil pool
		// panics rather than returning an error, so it is checked rather than
		// caught.
		return nil
	}
	rows, err := s.db.Query(ctx, `
		SELECT slug, display_name FROM core.identity_providers
		WHERE enabled ORDER BY display_name`)
	if err != nil {
		s.log.Error("listing external providers for the sign-in page", "err", err)
		return nil
	}
	defer rows.Close()

	var out []externalProvider
	for rows.Next() {
		var p externalProvider
		if err := rows.Scan(&p.Slug, &p.Name); err != nil {
			return out
		}
		out = append(out, p)
	}
	return out
}

// linkedProvider is one row on the account page.
type linkedProvider struct {
	Slug     string
	Name     string
	Linked   bool
	Email    string
	Verified bool
}

// handleAccount shows the signed-in user's linked sign-in methods.
//
// This page exists because /account/link/{slug} was reachable only by typing the
// URL. An endpoint nothing links to is a feature nobody uses, and the linking
// flow is the ONLY safe way to attach an external account -- so leaving it
// unreachable pushes operators toward asking for the unsafe one.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account"), http.StatusSeeOther)
		return
	}

	rows, err := s.db.Query(ctx, `
		SELECT p.slug, p.display_name,
		       f.id IS NOT NULL,
		       COALESCE(f.email,''), COALESCE(f.email_verified,false)
		FROM core.identity_providers p
		LEFT JOIN core.federated_identities f
		       ON f.provider_id = p.id AND f.user_id = $1::uuid
		WHERE p.org_id = $2::uuid AND p.enabled
		ORDER BY p.display_name`, userID, orgID)
	if err != nil {
		s.log.Error("listing linked providers", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var providers []linkedProvider
	for rows.Next() {
		var p linkedProvider
		if err := rows.Scan(&p.Slug, &p.Name, &p.Linked, &p.Email, &p.Verified); err != nil {
			break
		}
		providers = append(providers, p)
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		`default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")
	_ = accountPage.Execute(w, map[string]any{
		"Providers": providers, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleAccountUnlink removes an external sign-in method.
//
// POST, with CSRF. A GET that removes a credential is removable by an <img> tag
// on any page the user visits -- and removing somebody's only sign-in method
// locks them out.
func (s *Server) handleAccountUnlink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		// A cross-site POST that removes a credential is the shape this guards.
		s.federationError(w, r, "That request could not be verified. Please try again.")
		return
	}
	_, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account"), http.StatusSeeOther)
		return
	}
	slug := r.PathValue("slug")

	// Refuse to remove the LAST way in.
	//
	// A user who signed up through a provider has no password, so unlinking it
	// leaves an account nobody can reach -- recoverable only by an administrator,
	// and only if the account has a verified address. The check is one query and
	// it prevents a self-inflicted lockout that looks like data loss.
	var remaining int
	if err := s.db.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM core.federated_identities f
		        JOIN core.identity_providers p ON p.id = f.provider_id
		        WHERE f.user_id = $1::uuid AND p.slug <> $2)
		     + (SELECT count(*) FROM core.password_credentials
		        WHERE user_id = $1::uuid AND is_current)
		     + (SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid)`,
		userID, slug).Scan(&remaining); err != nil {
		s.log.Error("counting remaining sign-in methods", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if remaining == 0 {
		s.federationError(w, r, "That is the only way to sign in to this account. Set a "+
			"password or add a passkey first, then remove it.")
		return
	}

	if _, err := s.db.Exec(ctx, `
		DELETE FROM core.federated_identities f
		USING core.identity_providers p
		WHERE f.provider_id = p.id AND f.user_id = $1::uuid AND p.slug = $2`,
		userID, slug); err != nil {
		s.log.Error("unlinking provider", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

var accountPage = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your account</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}
h1{font-size:1.4rem}table{width:100%;border-collapse:collapse;margin-top:1rem}
td,th{text-align:left;padding:.5rem .25rem;border-bottom:1px solid #e4e4e7}
.muted{color:#666;font-size:.85rem}button{padding:.35rem .7rem}
a.btn{padding:.35rem .7rem;border:1px solid #d4d4d8;border-radius:.25rem;
text-decoration:none;color:inherit}</style></head>
<body>
<h1>Sign-in methods</h1>
{{if .Providers}}
<table>
<tr><th>Provider</th><th>Account</th><th></th></tr>
{{range .Providers}}
<tr>
<td>{{.Name}}</td>
<td>{{if .Linked}}{{if .Email}}{{.Email}}{{if not .Verified}} <span class="muted">(unverified)</span>{{end}}{{else}}linked{{end}}{{else}}<span class="muted">not linked</span>{{end}}</td>
<td>{{if .Linked}}
<form method="POST" action="/account/unlink/{{.Slug}}" style="margin:0">
<input type="hidden" name="{{$.CSRFField}}" value="{{$.CSRF}}">
<button type="submit">Remove</button></form>
{{else}}<a class="btn" href="/account/link/{{.Slug}}">Add</a>{{end}}</td>
</tr>
{{end}}
</table>
<p class="muted">Adding a provider here is the only way to link one to this
account. We never link on a matching email address alone.</p>
{{else}}
<p class="muted">No external sign-in providers are configured.</p>
{{end}}
</body></html>`))
