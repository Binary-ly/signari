package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// An operator whose upstream provider is compromised takes it out of service,
// and every way in through it closes from the next request: the sign-in button,
// the sign-in route, the SAML start, and the jwt-bearer grant. The enabled
// column and its readers existed from the start, and nothing could set it, so
// none of this was reachable without SQL.

func configVersion(t *testing.T, f *signInFixture) int64 {
	t.Helper()
	var v int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT version FROM core.config_version WHERE id = true`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestADisabledProviderClosesEveryWayInThroughIt(t *testing.T) {
	p := newProviderPage(t)
	ctx := context.Background()
	authz := url.Values{"client_id": {p.f.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}}.Encode()
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		p.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	before := configVersion(t, p.f)
	for _, slug := range []string{p.oidc, p.saml} {
		if _, err := store.SetIdentityProviderEnabled(ctx, p.f.pool, slug, false); err != nil {
			t.Fatal(err)
		}
	}
	if after := configVersion(t, p.f); after != before+2 {
		t.Errorf("the configuration version moved %d -> %d over two changes", before, after)
	}

	page := p.render(authz)
	for _, slug := range []string{p.oidc, p.saml} {
		if strings.Contains(page, slug) {
			t.Errorf("the sign-in page still offers disabled provider %s", slug)
		}
	}
	if rec := get("/login/with/" + p.oidc); rec.Code == http.StatusFound || rec.Code == http.StatusSeeOther {
		t.Errorf("the disabled provider's sign-in route still redirected upstream: %d %s",
			rec.Code, rec.Header().Get("Location"))
	}
	if rec := get("/saml/source/" + p.saml + "/start"); strings.HasPrefix(rec.Header().Get("Location"), "https://upstream.test/") {
		t.Errorf("the disabled SAML source still sent people upstream: %d", rec.Code)
	}

	for _, slug := range []string{p.oidc, p.saml} {
		if _, err := store.SetIdentityProviderEnabled(ctx, p.f.pool, slug, true); err != nil {
			t.Fatal(err)
		}
	}
	page = p.render(authz)
	for _, slug := range []string{p.oidc, p.saml} {
		if !strings.Contains(page, slug) {
			t.Errorf("re-enabled provider %s is not offered again", slug)
		}
	}
	if rec := get("/saml/source/" + p.saml + "/start"); !strings.HasPrefix(rec.Header().Get("Location"), "https://upstream.test/") {
		t.Errorf("the re-enabled SAML source does not reach the upstream: %d", rec.Code)
	}

	var audited int
	if err := p.f.pool.QueryRow(ctx, `
		SELECT count(*) FROM core.audit_events
		 WHERE event_type = 'admin.identity_provider_updated' AND detail->>'provider' = $1`,
		p.oidc).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 2 {
		t.Errorf("%d audit records for disabling and enabling %s, want 2", audited, p.oidc)
	}

	if _, err := store.SetIdentityProviderEnabled(ctx, p.f.pool, "no-such-provider", false); err != store.ErrProviderUnknown {
		t.Errorf("an unknown slug gave %v, want ErrProviderUnknown", err)
	}
}

// The jwt-bearer grant reads the same switch.
func TestADisabledIssuerMintsNothing(t *testing.T) {
	f := newAssertionFixture(t)
	if _, err := store.SetIdentityProviderEnabled(context.Background(), f.pool, f.providerSlug, false); err != nil {
		t.Fatal(err)
	}
	if status, body := f.grant(t, f.assert(t, nil), nil); status != http.StatusBadRequest {
		t.Fatalf("a disabled issuer's assertion gave %d %v", status, body)
	}
	if _, err := store.SetIdentityProviderEnabled(context.Background(), f.pool, f.providerSlug, true); err != nil {
		t.Fatal(err)
	}
	if status, body := f.grant(t, f.assert(t, nil), nil); status != http.StatusOK {
		t.Fatalf("the re-enabled issuer's assertion gave %d %v", status, body)
	}
}
