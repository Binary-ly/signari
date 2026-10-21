package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// externalProvider is one sign-in button on the login page.
type externalProvider struct {
	Slug string
	Name string
	// Href is where the button goes: the start route for the provider's kind,
	// carrying the parked request so the person comes back to it.
	Href string
}

// loginOrg is the organisation a sign-in page belongs to, when that can be
// known: the organisation of the client whose authorization request is parked,
// or the deployment's only organisation. Empty when neither applies -- a bare
// /login on a deployment with several.
func (s *Server) loginOrg(ctx context.Context, authzQuery string) string {
	if s.db == nil {
		return ""
	}
	clientID := ""
	if q, err := url.ParseQuery(authzQuery); err == nil {
		clientID = q.Get("client_id")
		if clientID == "" {
			// A parked return, which for an authorization request is the
			// /authorize URL with the client in it.
			if dest, ok := parkedReturn(authzQuery); ok {
				if u, err := url.Parse(dest); err == nil {
					clientID = u.Query().Get("client_id")
				}
			}
		}
	}
	if clientID != "" {
		if c, err := s.lookupClient(ctx, clientID); err == nil && c != nil {
			return c.OrgID
		}
	}
	var n int
	var only string
	if err := s.db.QueryRow(ctx,
		`SELECT count(*), COALESCE(min(id::text), '') FROM core.organizations`).Scan(&n, &only); err != nil {
		s.log.Error("counting organisations for the sign-in page", "err", err)
		return ""
	}
	if n == 1 {
		return only
	}
	return ""
}

// federationReturn is where a provider's sign-in should land afterwards: the
// parked return, or the parked authorization request itself. Without it the
// buttons dropped the request on the floor, and somebody who chose "continue
// with Google" from an application ended up on their account page instead.
func federationReturn(authzQuery string) string {
	if dest, ok := parkedReturn(authzQuery); ok {
		return dest
	}
	if q, err := url.ParseQuery(authzQuery); err == nil && q.Get("client_id") != "" {
		return "/authorize?" + authzQuery
	}
	return ""
}

// externalProviders lists the enabled providers of one organisation that a
// person can sign in through, each with the route its kind starts at.
//
// Scoped to the organisation, which it was not: every tenant's providers were
// offered on every tenant's sign-in page, naming one customer's identity
// providers to another's users. Kind-aware, which it was not either: a SAML
// source starts at /saml/source/<slug>/start, and its button pointed at the
// OAuth route, where it did nothing useful. Assertion issuers are not sign-in
// providers at all and are never listed.
//
// Failure is deliberately silent: if this query fails the sign-in page still
// renders with a password form, which is a degraded page rather than no page at
// all. An identity provider whose login screen 500s because a secondary feature
// is unavailable has turned a small fault into an outage.
func (s *Server) externalProviders(ctx context.Context, orgID, authzQuery string) []externalProvider {
	if s.db == nil || orgID == "" {
		// No database configured at all, or no way to know whose page this is.
		// The sign-in form still has to render -- that is the whole point of
		// failing quietly here -- and offering every tenant's buttons when the
		// organisation is unknown is the leak this function was written to stop.
		return nil
	}
	rows, err := s.db.Query(ctx, `
		SELECT slug, display_name, kind FROM core.identity_providers
		WHERE enabled AND org_id = $1::uuid AND kind <> 'assertion'
		ORDER BY display_name`, orgID)
	if err != nil {
		s.log.Error("listing external providers for the sign-in page", "err", err)
		return nil
	}
	defer rows.Close()

	query := ""
	if ret := federationReturn(authzQuery); ret != "" {
		query = "?" + url.Values{"return": {ret}}.Encode()
	}
	var out []externalProvider
	for rows.Next() {
		var p externalProvider
		var kind string
		if err := rows.Scan(&p.Slug, &p.Name, &kind); err != nil {
			return out
		}
		if kind == "saml" {
			p.Href = "/saml/source/" + url.PathEscape(p.Slug) + "/start" + query
		} else {
			p.Href = "/login/with/" + url.PathEscape(p.Slug) + query
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
		  -- An assertion issuer publishes keys for the jwt-bearer grant and has
		  -- no sign-in route; offering to link one is a button that fails.
		  AND p.kind <> 'assertion'
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

	// The person's passkeys, to list and remove, beside the control that adds
	// one. Registration and removal existed as endpoints, and passkey.js could
	// drive both, and no page offered either: nobody could add a passkey.
	passkeys, err := s.accountPasskeys(ctx, userID)
	if err != nil {
		s.log.Error("listing passkeys", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// PasskeyScript widens renderPage's policy to script-src and connect-src
	// 'self' for /passkey.js and the ceremony's requests. Nothing inline.
	s.renderPage(w, r, "account", map[string]any{
		"Providers": providers, "Passkeys": passkeys, "CSRF": csrf, "CSRFField": csrfFormField,
		"PasskeyScript": true,
	})
}

// accountPasskey is one row of the account page's passkey list.
type accountPasskey struct {
	ID, Name, Added string
}

func (s *Server) accountPasskeys(ctx context.Context, userID string) ([]accountPasskey, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id::text, COALESCE(NULLIF(friendly_name,''), 'Passkey'), created_at
		  FROM core.webauthn_credentials WHERE user_id = $1::uuid ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []accountPasskey
	for rows.Next() {
		var p accountPasskey
		var added time.Time
		if err := rows.Scan(&p.ID, &p.Name, &added); err != nil {
			return nil, err
		}
		p.Added = added.UTC().Format("2 Jan 2006")
		out = append(out, p)
	}
	return out, rows.Err()
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
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account"), http.StatusSeeOther)
		return
	}
	if s.credentialChangeRefused(w, r, sid, "/account", false) {
		return
	}
	slug := r.PathValue("slug")

	// Refuse to remove the LAST way in.
	//
	// A user who signed up through a provider has no password, so unlinking it
	// leaves an account nobody can reach -- recoverable only by an administrator,
	// and only if the account has a verified address. Counted as passkey removal
	// counts (store.SignInMethodsBesides), in the transaction that removes it.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	remaining, err := store.SignInMethodsBesides(ctx, tx, userID, "", slug)
	if err != nil {
		s.log.Error("counting remaining sign-in methods", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if remaining == 0 {
		_ = tx.Rollback(ctx)
		s.federationError(w, r, "That is the only way to sign in to this account. Set a "+
			"password or add a passkey first, then remove it.")
		return
	}

	var provider string
	err = tx.QueryRow(ctx, `
		DELETE FROM core.federated_identities f
		USING core.identity_providers p
		WHERE f.provider_id = p.id AND f.user_id = $1::uuid AND p.slug = $2
		RETURNING p.display_name`, userID, slug).Scan(&provider)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not linked: nothing to remove, record or tell.
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.log.Error("unlinking provider", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	// A way into the account went, so it is audited and the holder told, as
	// linking one is: an unlink they did not make is somebody else in their
	// session.
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "federation.account_unlinked", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx), Detail: map[string]any{"provider": slug},
	}); err != nil {
		s.log.Error("auditing an unlink", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if err := store.EnqueueAccountNotice(ctx, tx, store.AccountNotice{UserID: userID,
		Notice: store.NoticeProviderUnlinked, Provider: provider}); err != nil {
		s.log.Error("queueing the unlink notice", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("unlinking provider", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
