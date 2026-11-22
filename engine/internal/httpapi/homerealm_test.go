package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// homeRealmFixture is a client's organisation with a provider that signs in
// corp.example, a SAML one, and another tenant's provider.
type homeRealmFixture struct {
	*tokenFixture
	corp, saml, foreign string
}

func newHomeRealmFixture(t *testing.T) *homeRealmFixture {
	t.Helper()
	f := newTokenFixture(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	h := &homeRealmFixture{tokenFixture: f, corp: fmt.Sprintf("corp-%d", stamp), saml: fmt.Sprintf("saml-%d", stamp),
		foreign: fmt.Sprintf("foreign-%d", stamp)}
	var other string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'hr-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, other)
	})
	for _, p := range []struct {
		org, slug, kind string
		domains         []string
	}{{f.orgID, h.corp, "oidc", []string{"corp.example"}}, {f.orgID, h.saml, "saml", []string{"saml.example"}},
		{other, h.foreign, "oidc", []string{"foreign.example"}}} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id,
			scopes, login_domains) VALUES ($1::uuid, $2, 'Corp', $3, 'c', '{}', $4)`, p.org, p.slug, p.kind, p.domains); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *homeRealmFixture) authorize(t *testing.T, extra url.Values, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"client_id": {h.clientID}, "redirect_uri": {"https://rp.test/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"s"}, "code_challenge_method": {"S256"},
		"code_challenge": {oauth.Challenge("verifier-home-realm-0123456789abcdefghijklmnop")}}
	for k, v := range extra {
		q[k] = v
	}
	r := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func TestAHintGoesToTheProvider(t *testing.T) {
	h := newHomeRealmFixture(t)
	routed := func(rec *httptest.ResponseRecorder) string {
		if rec.Code != http.StatusSeeOther {
			return ""
		}
		return rec.Header().Get("Location")
	}
	for name, tc := range map[string]struct {
		extra url.Values
		want  string // A prefix, or empty for the sign-in page.
	}{
		"idp_hint":                 {url.Values{"idp_hint": {h.corp}}, "/login/with/" + h.corp + "?return="},
		"a SAML provider":          {url.Values{"idp_hint": {h.saml}}, "/saml/source/" + h.saml + "/start?return="},
		"login_hint":               {url.Values{"login_hint": {"ada@corp.example"}}, "/login/with/" + h.corp},
		"login_hint in any case":   {url.Values{"login_hint": {"ADA@CORP.EXAMPLE"}}, "/login/with/" + h.corp},
		"a domain nobody signs in": {url.Values{"login_hint": {"ada@elsewhere.example"}}, ""},
		"not an address":           {url.Values{"login_hint": {"ada"}}, ""},
		"an unknown provider":      {url.Values{"idp_hint": {"nobody"}}, ""},
		"another tenant's":         {url.Values{"idp_hint": {h.foreign}}, ""},
		"another tenant's domain":  {url.Values{"login_hint": {"ada@foreign.example"}}, ""},
		"no hint at all":           {url.Values{}, ""},
	} {
		got := routed(h.authorize(t, tc.extra, ""))
		if (tc.want == "" && got != "") || !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s went to %q, want %q", name, got, tc.want)
		}
	}
	// prompt=none must not interact, and a redirect to a provider is interaction.
	rec := h.authorize(t, url.Values{"idp_hint": {h.corp}, "prompt": {"none"}}, "")
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "login_required") {
		t.Errorf("prompt=none went to %q", loc)
	}
	// The way back carries the request.
	loc := routed(h.authorize(t, url.Values{"idp_hint": {h.corp}}, ""))
	parsed, err := url.Parse(loc)
	if err != nil || !strings.Contains(parsed.Query().Get("return"), h.clientID) {
		t.Errorf("the way back is lost: %q", loc)
	}
}

// Somebody with a session short of a factor needs it here, not at the provider.
func TestAHintDoesNotTakeASessionAwayFromStepUp(t *testing.T) {
	h := newHomeRealmFixture(t)
	cookie := fmt.Sprintf("home-realm-%d", time.Now().UnixNano())
	if _, err := h.pool.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, '1', ARRAY['pwd'], now() - interval '2 hours', now() + interval '1 hour')`,
		"sid-"+cookie, store.HashToken(cookie), h.orgID, h.userID); err != nil {
		t.Fatal(err)
	}
	rec := h.authorize(t, url.Values{"idp_hint": {h.corp}, "max_age": {"1"}}, cookie)
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "/login/with/") {
		t.Errorf("a step-up went to %q", loc)
	}
}

// The button routes by address, and a password in the same domain is untouched.
func TestSingleSignOnRoutesWithoutTouchingPasswords(t *testing.T) {
	h := newHomeRealmFixture(t)
	authz := url.Values{"client_id": {h.clientID}}.Encode()
	post := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		form.Set("authz", authz)
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.srv.handleLoginPost(rec, r)
		return rec
	}
	rec := post(url.Values{"sso": {"1"}, "username": {"ada@corp.example"}})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login/with/"+h.corp) {
		t.Fatalf("single sign-on answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = post(url.Values{"sso": {"1"}, "username": {"ada@elsewhere.example"}})
	if rec.Code == http.StatusSeeOther || !strings.Contains(rec.Body.String(), "Single sign-on is not set up") {
		t.Errorf("an address nobody signs in answered %d", rec.Code)
	}
	rec = post(url.Values{"username": {"ada@corp.example"}, "password": {"a-password"}})
	if rec.Code == http.StatusSeeOther && strings.Contains(rec.Header().Get("Location"), "/login/with/") {
		t.Errorf("a password in the domain went to the provider: %q", rec.Header().Get("Location"))
	}

	page := httptest.NewRecorder()
	h.srv.Routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/login?authz="+url.QueryEscape(authz), nil))
	if !strings.Contains(page.Body.String(), `name="sso"`) {
		t.Errorf("the sign-in page offers no button: %.200s", page.Body.String())
	}
}

// A domain goes to one provider, and only one that signs anybody in.
func TestALoginDomainIsChecked(t *testing.T) {
	h := newHomeRealmFixture(t)
	ctx := context.Background()
	set := func(slug string, domains ...string) error {
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.ChangeIdentityProvider(ctx, tx, h.orgID, slug, store.IdentityProviderChange{LoginDomains: &domains}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	for name, domain := range map[string]string{"an address": "ada@corp.example", "a bare word": "corp", "a scheme": "https://corp.example"} {
		if err := set(h.saml, domain); !errors.Is(err, store.ErrIdPInvalid) {
			t.Errorf("%s answered %v", name, err)
		}
	}
	if err := set(h.saml, "corp.example"); !errors.Is(err, store.ErrIdPInvalid) {
		t.Errorf("a domain another provider signs in answered %v", err)
	}
	if err := set(h.saml, "Second.Example", " third.example "); err != nil {
		t.Fatal(err)
	}
	slug, _, err := store.ProviderForDomain(ctx, h.pool, h.orgID, "SECOND.example")
	if err != nil || slug != h.saml {
		t.Errorf("a domain folded reads %q, %v", slug, err)
	}
	if err := set(h.saml); err != nil {
		t.Fatal(err)
	}
	if slug, _, _ := store.ProviderForDomain(ctx, h.pool, h.orgID, "second.example"); slug != "" {
		t.Errorf("cleared domains still route to %q", slug)
	}
}
