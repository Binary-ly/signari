package httpapi

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The sign-in page offered every tenant's identity providers to every tenant's
// users, pointed SAML sources at the OAuth start route, and dropped the parked
// authorization request from every button.

type providerPage struct {
	f                           *signInFixture
	oidc, saml, issuer, foreign string
}

func newProviderPage(t *testing.T) *providerPage {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	n := time.Now().UnixNano()
	p := &providerPage{f: f,
		oidc: fmt.Sprintf("own-oidc-%d", n), saml: fmt.Sprintf("own-saml-%d", n),
		issuer: fmt.Sprintf("own-iss-%d", n), foreign: fmt.Sprintf("foreign-%d", n)}

	var otherOrg string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'pp-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
	      VALUES ($1::uuid, $2, 'Own OIDC', 'oidc', 'c', '{openid}')`, f.orgID, p.oidc)
	exec(`INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
	      VALUES ($1::uuid, $2, 'Foreign OIDC', 'oidc', 'c', '{openid}')`, otherOrg, p.foreign)
	exec(`INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes,
	                                         issuer, jwks_url, allow_signup, allow_linking)
	      VALUES ($1::uuid, $2, 'Issuer', 'assertion', '', '{}', 'https://iss.test',
	              'https://iss.test/jwks', false, false)`, f.orgID, p.issuer)
	exec(`WITH ip AS (
	          INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
	          VALUES ($1::uuid, $2, 'Own SAML', 'saml', '', '{}') RETURNING id
	      )
	      INSERT INTO core.saml_sources (provider_id, org_id, entity_id, sso_url, cert_pem)
	      SELECT id, $1::uuid, 'https://upstream.test/idp', 'https://upstream.test/sso',
	             '-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----' FROM ip`, f.orgID, p.saml)
	return p
}

func (p *providerPage) render(authz string) string {
	target := "/login"
	if authz != "" {
		target += "?authz=" + url.QueryEscape(authz)
	}
	rec := httptest.NewRecorder()
	p.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return html.UnescapeString(rec.Body.String())
}

func TestTheSignInPageOffersOnlyItsOwnOrganisationsProviders(t *testing.T) {
	p := newProviderPage(t)
	authz := url.Values{"client_id": {p.f.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}}.Encode()
	page := p.render(authz)

	if strings.Contains(page, p.foreign) {
		t.Error("the sign-in page for one organisation's application offered another organisation's provider")
	}
	if strings.Contains(page, p.issuer) {
		t.Error("an assertion issuer, which has no sign-in route, was offered as a sign-in button")
	}
	ret := url.Values{"return": {"/authorize?" + authz}}.Encode()
	if want := "/login/with/" + p.oidc + "?" + ret; !strings.Contains(page, want) {
		t.Errorf("the OIDC button does not carry the authorization request back:\nwant %s", want)
	}
	samlHref := "/saml/source/" + p.saml + "/start?" + ret
	if !strings.Contains(page, samlHref) {
		t.Fatalf("the SAML button does not go to the SAML start route:\nwant %s", samlHref)
	}

	// And the SAML button reaches the upstream.
	rec := httptest.NewRecorder()
	p.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, samlHref, nil))
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther ||
		!strings.HasPrefix(loc, "https://upstream.test/sso?") || !strings.Contains(loc, "SAMLRequest=") {
		t.Fatalf("the SAML button answered %d -> %q, want a redirect to the upstream with a SAMLRequest",
			rec.Code, loc)
	}
}

// With no application and several organisations, whose page this is cannot be
// known, and no tenant's providers are named to whoever opens it.
func TestABareSignInPageOnAManyTenantDeploymentNamesNoProviders(t *testing.T) {
	p := newProviderPage(t)
	page := p.render("")
	for _, slug := range []string{p.oidc, p.saml, p.foreign} {
		if strings.Contains(page, slug) {
			t.Errorf("a sign-in page with no organisation offered %s", slug)
		}
	}
}
