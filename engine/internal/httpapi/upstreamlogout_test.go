package httpapi

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
)

type upstreamLogoutFixture struct {
	*signInFixture
	slug, session string
}

const upstreamEndSession = "https://idp.corp.example/logout?tenant=7"

// newUpstreamLogoutFixture is a person signed in, a provider with an end-session
// address, and the session marked as having come through a provider.
func newUpstreamLogoutFixture(t *testing.T) *upstreamLogoutFixture {
	t.Helper()
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	ctx := context.Background()
	slug := fmt.Sprintf("up-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, end_session_url)
		VALUES ($1::uuid, $2, 'Corp', 'oidc', 'our-client-there', $3)`, f.orgID, slug, upstreamEndSession); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = $1`, slug)
	})
	u := &upstreamLogoutFixture{signInFixture: f, slug: slug, session: f.signInAndReturnCookie(t)}
	u.setAMR(t, "fed")
	return u
}

func (f *upstreamLogoutFixture) setAMR(t *testing.T, amr string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.sessions SET amr = ARRAY[$2] WHERE user_id = $1::uuid`,
		f.userID, amr); err != nil {
		t.Fatal(err)
	}
}

// signOut confirms a sign-out in a browser holding the session, and the provider's
// cookie when one is given.
func (f *upstreamLogoutFixture) signOut(t *testing.T, upstream, query string) *httptest.ResponseRecorder {
	t.Helper()
	h := f.srv.Routes()
	get := httptest.NewRequest(http.MethodGet, oidc.PathEndSession+query, nil)
	get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: f.session})
	page := httptest.NewRecorder()
	h.ServeHTTP(page, get)
	action := regexp.MustCompile(`<form method="post" action="([^"]*)"`).FindStringSubmatch(page.Body.String())
	field := regexp.MustCompile(`name="` + csrfFormField + `" value="([^"]*)"`).FindStringSubmatch(page.Body.String())
	if action == nil || field == nil {
		t.Fatalf("no confirmation form: %d", page.Code)
	}
	post := httptest.NewRequest(http.MethodPost, html.UnescapeString(action[1]),
		strings.NewReader(url.Values{csrfFormField: {field[1]}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: f.session})
	if upstream != "" {
		post.AddCookie(&http.Cookie{Name: upstreamCookieName, Value: upstream})
	}
	for _, c := range page.Result().Cookies() {
		post.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	return rec
}

// A person who came through a provider that asks to be told goes on to it, and
// comes back to where the application asked; the session here has ended either way.
func TestASignOutGoesOnToTheProviderAndComesBack(t *testing.T) {
	f := newUpstreamLogoutFixture(t)
	ctx := context.Background()
	const final = "https://rp.example.test/signed-out"
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.client_post_logout_redirect_uris (client_id, redirect_uri)
		VALUES ($1, $2)`, f.clientID, final); err != nil {
		t.Fatal(err)
	}
	query := "?" + url.Values{"client_id": {f.clientID}, "post_logout_redirect_uri": {final}}.Encode()

	rec := f.signOut(t, f.slug, query)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the sign-out answered %d: %s", rec.Code, rec.Body.String())
	}
	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if to.Host != "idp.corp.example" || to.Path != "/logout" {
		t.Fatalf("the browser went to %s", to)
	}
	q := to.Query()
	if q.Get("tenant") != "7" || q.Get("client_id") != "our-client-there" ||
		q.Get("post_logout_redirect_uri") != f.srv.cfg.Issuer+pathLogoutComplete || q.Get("state") == "" {
		t.Errorf("the provider was sent %v", q)
	}
	var live bool
	if err := f.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.sessions
		WHERE user_id = $1::uuid AND revoked_at IS NULL)`, f.userID).Scan(&live); err != nil || live {
		t.Errorf("a session survived, %v", err)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		cleared = cleared || (c.Name == upstreamCookieName && c.MaxAge < 0)
	}
	if !cleared {
		t.Error("the provider's cookie outlived the sign-out")
	}

	back := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(back, httptest.NewRequest(http.MethodGet,
		pathLogoutComplete+"?"+url.Values{"state": {q.Get("state")}}.Encode(), nil))
	if back.Code != http.StatusSeeOther || back.Header().Get("Location") != final {
		t.Errorf("coming back answered %d to %q", back.Code, back.Header().Get("Location"))
	}
}

// The state crosses the provider and the browser, so what comes back is only ever
// an address this server validated. Anything else is reported as a sign-out.
func TestTheWayBackIsNoOpenRedirect(t *testing.T) {
	f := newUpstreamLogoutFixture(t)
	sealed := f.srv.sealLogoutReturn("https://rp.example.test/signed-out")
	mark := sealed[strings.Index(sealed, ".")+1:]
	forged := f.srv.sealLogoutReturn("https://evil.example.test/")
	for name, state := range map[string]string{
		"nothing":                "",
		"not a seal":             "https://evil.example.test/",
		"another address's mark": forged[:strings.Index(forged, ".")] + "." + mark,
		"a mark of nothing":      "." + mark,
		"an undecodable address": "!!!." + mark,
	} {
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			pathLogoutComplete+"?"+url.Values{"state": {state}}.Encode(), nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
			t.Errorf("%s answered %d to %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// With no application to return to, it still goes to the provider, and comes back
// to a plain report.
func TestASignOutWithNowhereToGoStillGoesToTheProvider(t *testing.T) {
	f := newUpstreamLogoutFixture(t)
	rec := f.signOut(t, f.slug, "")
	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther || to.Host != "idp.corp.example" {
		t.Fatalf("the sign-out answered %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if to.Query().Get("state") != "" {
		t.Errorf("a state with nothing to carry: %v", to.Query())
	}
}

// The cookie picks among what the operator set for this session's organisation and
// no further, and only a session that came through a provider leaves at all.
func TestOnlyAFederatedSessionLeavesAndOnlyForItsOwnProvider(t *testing.T) {
	t.Run("a session that did not come through a provider", func(t *testing.T) {
		f := newUpstreamLogoutFixture(t)
		f.setAMR(t, "pwd")
		if rec := f.signOut(t, f.slug, ""); rec.Header().Get("Location") != "" {
			t.Errorf("a password session was sent to %q", rec.Header().Get("Location"))
		}
	})
	t.Run("a browser with no cookie", func(t *testing.T) {
		f := newUpstreamLogoutFixture(t)
		if rec := f.signOut(t, "", ""); rec.Header().Get("Location") != "" {
			t.Errorf("it was sent to %q", rec.Header().Get("Location"))
		}
	})
	t.Run("a cookie naming a provider that does not exist", func(t *testing.T) {
		f := newUpstreamLogoutFixture(t)
		if rec := f.signOut(t, "no-such-provider", ""); rec.Header().Get("Location") != "" {
			t.Errorf("it was sent to %q", rec.Header().Get("Location"))
		}
	})
	t.Run("a provider taken out of service", func(t *testing.T) {
		f := newUpstreamLogoutFixture(t)
		if _, err := f.pool.Exec(context.Background(), `UPDATE core.identity_providers SET enabled = false WHERE slug = $1`, f.slug); err != nil {
			t.Fatal(err)
		}
		if rec := f.signOut(t, f.slug, ""); rec.Header().Get("Location") != "" {
			t.Errorf("it was sent to %q", rec.Header().Get("Location"))
		}
	})
	t.Run("a provider of another organisation", func(t *testing.T) {
		f := newUpstreamLogoutFixture(t)
		ctx := context.Background()
		var other string
		if err := f.pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT instance_id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'Other' FROM core.organizations
			WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&other); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE core.identity_providers SET org_id = $1::uuid WHERE slug = $2`, other, f.slug); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			c := context.Background()
			_, _ = f.pool.Exec(c, `DELETE FROM core.identity_providers WHERE slug = $1`, f.slug)
			_, _ = f.pool.Exec(c, `DELETE FROM core.organizations WHERE id = $1::uuid`, other)
		})
		if rec := f.signOut(t, f.slug, ""); rec.Header().Get("Location") != "" {
			t.Errorf("it was sent to %q", rec.Header().Get("Location"))
		}
	})
}

// The cookie is set only for a provider that asks to be told.
func TestACallbackRemembersOnlyAProviderToBeTold(t *testing.T) {
	f := newTokenFixture(t)
	rec := httptest.NewRecorder()
	f.srv.rememberUpstream(rec, &federation.Config{Slug: "quiet"})
	if len(rec.Result().Cookies()) != 0 {
		t.Error("a provider with no address left a cookie")
	}
	rec = httptest.NewRecorder()
	f.srv.rememberUpstream(rec, &federation.Config{Slug: "corp", EndSessionURL: upstreamEndSession})
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "corp" || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Errorf("the cookie is %+v", cookies)
	}
}
