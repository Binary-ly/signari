package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/proxyrules"
)

func (pa *proxyAuthz) setRules(t *testing.T, host string, rules ...proxyrules.Rule) {
	t.Helper()
	held, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pa.f.pool.Exec(context.Background(), `UPDATE core.proxy_hosts SET rules = $2::jsonb WHERE host = $1`,
		host, string(held)); err != nil {
		t.Fatal(err)
	}
}

// ask is the proxy's question about one request, with a person or with nobody.
func (pa *proxyAuthz) ask(token, host, method, uri string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	if token != "" {
		r.AddCookie(&http.Cookie{Name: ProxyCookieName, Value: token})
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", uri)
	if method != "" {
		r.Header.Set("X-Forwarded-Method", method)
	}
	rec := httptest.NewRecorder()
	pa.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

var identityHeaders = []string{"X-Forwarded-User", "X-Forwarded-Sub", "X-Forwarded-Email", "X-Forwarded-Groups", "X-Forwarded-Jwt"}

// One application, with paths that want three different things, and the person and the
// nobody who ask about each.
func TestAPathOfAProtectedHostIsHeldToItsRule(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)
	pa.setRules(t, pa.own,
		proxyrules.Rule{Effect: proxyrules.EffectAuth, Path: "/static/private/**"},
		proxyrules.Rule{Effect: proxyrules.EffectPublic, Path: "/static/**", Methods: []string{"GET", "HEAD"}},
		proxyrules.Rule{Effect: proxyrules.EffectPublic, Path: "/health"},
		proxyrules.Rule{Effect: proxyrules.EffectDeny, Path: "/internal/**"},
	)

	for name, c := range map[string]struct {
		token, method, uri string
		want               int
	}{
		"nobody at a public path":              {"", "GET", "/static/app.js", http.StatusOK},
		"nobody at a public path's query":      {"", "GET", "/static/app.js?v=2", http.StatusOK},
		"nobody at a path open to any method":  {"", "POST", "/health", http.StatusOK},
		"nobody writing to a public path":      {"", "POST", "/static/app.js", http.StatusUnauthorized},
		"nobody at a path taken back":          {"", "GET", "/static/private/key", http.StatusUnauthorized},
		"nobody at a path no rule names":       {"", "GET", "/dashboard", http.StatusUnauthorized},
		"nobody at a refused path":             {"", "GET", "/internal/metrics", http.StatusForbidden},
		"a person at a refused path":           {tok, "GET", "/internal/metrics", http.StatusForbidden},
		"a person at a path taken back":        {tok, "GET", "/static/private/key", http.StatusOK},
		"a person at a path no rule names":     {tok, "GET", "/dashboard", http.StatusOK},
		"a request of no known method, public": {"", "", "/static/app.js", http.StatusUnauthorized},
	} {
		if rec := pa.ask(c.token, pa.own, c.method, c.uri); rec.Code != c.want {
			t.Errorf("%s answered %d (%q), want %d", name, rec.Code, rec.Header().Get("X-Signari-Reason"), c.want)
		}
	}

	// A public path says nobody is there, and says it: the headers are what overwrites
	// whatever the browser sent, and leaving them off leaves that in place.
	rec := pa.ask("", pa.own, "GET", "/health")
	for _, h := range identityHeaders {
		if got, sent := rec.Header()[h]; !sent || got[0] != "" {
			t.Errorf("%s on a public path: %q, sent %v", h, got, sent)
		}
	}
	rec = pa.ask(tok, pa.own, "GET", "/health")
	if rec.Code != http.StatusOK || rec.Header().Get("X-Forwarded-User") != "" {
		t.Errorf("a person on a public path answered %d as %q", rec.Code, rec.Header().Get("X-Forwarded-User"))
	}
}

// Each of these would reach the path the deny is on, or leave the public path it says
// it is on, at an application that reads a path as most do.
func TestAPathThatCouldMeanTwoThingsIsNotLetThrough(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)
	pa.setRules(t, pa.own,
		proxyrules.Rule{Effect: proxyrules.EffectPublic, Path: "/static/**"},
		proxyrules.Rule{Effect: proxyrules.EffectDeny, Path: "/internal/**"},
	)
	for _, uri := range []string{
		"/static/../internal/metrics",
		"/static/%2e%2e/internal/metrics",
		"/static/%2E%2E/internal/metrics",
		"/static/..%2finternal/metrics",
		"/static/%252e%252e/internal/metrics",
		"/static/..\\internal/metrics",
		"/static/;/../internal/metrics",
		"//internal/metrics",
		"/./internal/metrics",
		"/internal%2fmetrics",
	} {
		for who, token := range map[string]string{"nobody": "", "a person": tok} {
			rec := pa.ask(token, pa.own, "GET", uri)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s at %q answered %d", who, uri, rec.Code)
			}
			if rec.Header().Get("X-Forwarded-User") != "" {
				t.Errorf("%s at %q was named", who, uri)
			}
		}
	}

	// A comma is a character of a path: stopping at one reads this as /static/x.
	if rec := pa.ask("", pa.own, "GET", "/static/x,/../../internal/metrics"); rec.Code != http.StatusForbidden {
		t.Errorf("a path with a comma in it answered %d", rec.Code)
	}
	// A comma in a path that means what it says is still a path.
	if rec := pa.ask("", pa.own, "GET", "/static/a,b.js"); rec.Code != http.StatusOK {
		t.Errorf("a plain comma answered %d", rec.Code)
	}

	// With rules, a proxy that does not say which path has asked nothing they can answer.
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Host", pa.own)
	rec := httptest.NewRecorder()
	pa.f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("X-Signari-Reason"), "X-Forwarded-Uri") {
		t.Errorf("no path answered %d %q", rec.Code, rec.Header().Get("X-Signari-Reason"))
	}
	r = httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Host", pa.own)
	r.Header.Add("X-Forwarded-Uri", "/static/x")
	r.Header.Add("X-Forwarded-Uri", "/internal/metrics")
	rec = httptest.NewRecorder()
	pa.f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("two paths answered %d", rec.Code)
	}
}

// A host with no rules is every host as it was: nothing above applies to it, a strange
// path included, which is the application's to judge.
func TestAHostWithNoRulesIsUntouched(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)
	if rec := pa.ask(tok, pa.own, "GET", "/a/../b"); rec.Code != http.StatusOK {
		t.Errorf("a person answered %d", rec.Code)
	}
	if rec := pa.ask("", pa.own, "GET", "/health"); rec.Code != http.StatusUnauthorized {
		t.Errorf("nobody answered %d", rec.Code)
	}
}

// A switched-off application opens nothing, and rules on another organisation's host
// are that organisation's to hold, not a way in for a person of this one.
func TestARuleOpensOnlyWhatItsHostOpens(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)
	open := proxyrules.Rule{Effect: proxyrules.EffectAuth, Path: "/**"}
	pa.setRules(t, pa.disabled, proxyrules.Rule{Effect: proxyrules.EffectPublic, Path: "/**"})
	if rec := pa.ask("", pa.disabled, "GET", "/health"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a public rule on a disabled host answered %d", rec.Code)
	}
	pa.setRules(t, pa.foreign, open)
	if rec := pa.ask(tok, pa.foreign, "GET", "/x"); rec.Code != http.StatusForbidden {
		t.Errorf("an auth rule on another organisation's host answered %d", rec.Code)
	}
}

// A path can have a policy of its own, on top of the host's.
func TestAPathCanBeHeldToAPolicyOfItsOwn(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)
	pa.setRules(t, pa.own, proxyrules.Rule{Effect: proxyrules.EffectAuth, Path: "/console/**", Name: "console"})

	applyPolicy(t, pa.f.srv, pa.f.pool, pa.f.orgID, denyClient("proxy:"+pa.own+"#console"))
	if rec := pa.ask(tok, pa.own, "GET", "/console/users"); rec.Code != http.StatusForbidden {
		t.Errorf("the path answered %d", rec.Code)
	}
	if rec := pa.ask(tok, pa.own, "GET", "/dashboard"); rec.Code != http.StatusOK {
		t.Errorf("the rest of the host answered %d", rec.Code)
	}
}

func TestAnAccessTokenIsHeldToTheRulesToo(t *testing.T) {
	pa := newProxyAuthz(t)
	pa.setRules(t, pa.own, proxyrules.Rule{Effect: proxyrules.EffectDeny, Path: "/internal/**"})
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("Authorization", "Bearer not-looked-at")
	r.Header.Set("X-Forwarded-Host", pa.own)
	r.Header.Set("X-Forwarded-Uri", "/internal/metrics")
	rec := httptest.NewRecorder()
	pa.f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("answered %d", rec.Code)
	}
}
