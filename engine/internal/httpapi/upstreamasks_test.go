package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// What a sign-in passes on to a provider (8.36): nothing until it is opted in, then only
// what was named. An acr means something only here, so the provider is asked in its own
// values, and a second factor it says it did is judged when it comes back, as ever
// (TestAnUpstreamsTrustedMFASatisfiesTheMFAStage).
func TestAProviderIsToldOnlyWhatItWasOptedInFor(t *testing.T) {
	h := newHomeRealmFixture(t)
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, `UPDATE core.identity_providers SET authorize_url = 'https://corp.test/authorize'
		WHERE slug = $1`, h.corp); err != nil {
		t.Fatal(err)
	}
	opt := func(forward, trusted []string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `UPDATE core.identity_providers SET forward_parameters = $2, mfa_acr = $3
			WHERE slug = $1`, h.corp, forward, trusted); err != nil {
			t.Fatal(err)
		}
	}
	start := func(returnTo string) url.Values {
		t.Helper()
		rec := httptest.NewRecorder()
		h.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/login/with/"+h.corp+"?return="+url.QueryEscape(returnTo), nil))
		location, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || location.Host != "corp.test" {
			t.Fatalf("the sign-in went to %q (%d): %.200s", rec.Header().Get("Location"), rec.Code, rec.Body.String())
		}
		return location.Query()
	}
	request := "/authorize?" + url.Values{"client_id": {h.clientID}, "prompt": {"login select_account none"},
		"login_hint": {"ada@corp.example"}, "acr_values": {"2"}}.Encode()
	told := func(q url.Values) []string {
		var named []string
		for _, name := range []string{"prompt", "login_hint", "acr_values"} {
			if q.Has(name) {
				named = append(named, name)
			}
		}
		return named
	}

	if got := told(start(request)); got != nil {
		t.Errorf("a provider nothing was opted in for was told %v", got)
	}

	opt([]string{"prompt", "login_hint", "acr_values"}, []string{"urn:corp:loa:multi", "urn:corp:loa:hard"})
	q := start(request)
	if got := q.Get("prompt"); got != "login select_account" {
		t.Errorf("the provider was told prompt=%q; none is answered here and never goes on", got)
	}
	if got := q.Get("login_hint"); got != "ada@corp.example" {
		t.Errorf("the provider was told login_hint=%q", got)
	}
	if got := q.Get("acr_values"); got != "urn:corp:loa:multi urn:corp:loa:hard" {
		t.Errorf("the provider was told acr_values=%q, want its own values", got)
	}

	// Named but not asked for, and asked for with nothing to say it in.
	plain := "/authorize?" + url.Values{"client_id": {h.clientID}}.Encode()
	if got := told(start(plain)); got != nil {
		t.Errorf("a plain request told the provider %v", got)
	}
	opt([]string{"acr_values"}, []string{})
	if got := start(request).Get("acr_values"); got != "" {
		t.Errorf("with no trusted value the provider was told acr_values=%q", got)
	}

	// Only what was named, whichever of them the request carries.
	opt([]string{"login_hint"}, []string{"urn:corp:loa:multi"})
	if got := told(start(request)); len(got) != 1 || got[0] != "login_hint" {
		t.Errorf("naming login_hint told the provider %v", got)
	}

	// A return address that is not this server's is no request.
	if got := told(start("https://evil.test/authorize?login_hint=ada@corp.example")); got != nil {
		t.Errorf("an address elsewhere told the provider %v", got)
	}
}
