package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"signari.dev/engine/internal/store"
)

// Home-realm discovery (8.20): sending somebody to their own identity provider without
// showing them a password box first. It chooses a route and nothing else. The provider
// still authenticates them, and every link rule still applies when they come back.

// providerStart is where a person signs in through a provider, carrying the parked
// request back, as the provider's button on the sign-in page does.
func providerStart(slug, kind, authzQuery string) string {
	query := ""
	if ret := federationReturn(authzQuery); ret != "" {
		query = "?" + url.Values{"return": {ret}}.Encode()
	}
	if kind == "saml" {
		return "/saml/source/" + url.PathEscape(slug) + "/start" + query
	}
	return "/login/with/" + url.PathEscape(slug) + query
}

// emailDomain is the domain of an address, "" for what is not one.
func emailDomain(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 {
		return ""
	}
	return address[at+1:]
}

// homeRealm finds where an authorization request should sign in: the provider idp_hint
// names, or the one that signs in login_hint's domain. A hint naming nothing here is
// ignored, as a hint may be, and the sign-in page is shown. Only ever a provider of the
// client's own organisation.
func (s *Server) homeRealm(ctx context.Context, orgID string, query url.Values) (slug, kind string, err error) {
	if hint := query.Get("idp_hint"); hint != "" {
		if slug, kind, err = store.SignInProvider(ctx, s.db, orgID, hint); slug != "" || err != nil {
			return slug, kind, err
		}
	}
	if domain := emailDomain(query.Get("login_hint")); domain != "" {
		return store.ProviderForDomain(ctx, s.db, orgID, domain)
	}
	return "", "", nil
}

// singleSignOnOffered reports whether the page should offer sign-in by address. An
// error shows the page without it: the other ways in still work.
func (s *Server) singleSignOnOffered(ctx context.Context, orgID string) bool {
	if orgID == "" || s.db == nil {
		return false
	}
	offered, err := store.RoutesByDomain(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading whether single sign-on is offered", "err", err)
		return false
	}
	return offered
}

// routeByAddress sends somebody who asked for single sign-on to the provider of their
// address, reporting whether it answered. A password box left empty is what asked, so
// somebody with a local password in the same domain signs in with it as ever.
func (s *Server) routeByAddress(w http.ResponseWriter, r *http.Request, orgID, identifier, authzQuery string) bool {
	if orgID == "" {
		return false
	}
	domain := emailDomain(identifier)
	if domain == "" {
		return false
	}
	slug, kind, err := store.ProviderForDomain(r.Context(), s.db, orgID, domain)
	if err != nil {
		s.log.Error("routing an address to its provider", "err", err)
		return false
	}
	if slug == "" {
		return false
	}
	http.Redirect(w, r, providerStart(slug, kind, authzQuery), http.StatusSeeOther)
	return true
}
