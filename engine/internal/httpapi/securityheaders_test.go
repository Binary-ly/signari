package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

// OWASP ASVS 5.0.0 V3.4, "Browser Security Mechanism Headers".
//
// V3 was outside the earlier sweeps, which covered V6–V11 and reasoned that the
// rest was "relevant to the product, not specific to it". V3.4 is the chapter
// governing the login page, and five of its headers were absent entirely.
//
// These go through Routes(), NOT through the handlers directly. The middleware
// is only in the chain the router builds, so a test that called the handler
// would assert nothing about what a browser receives -- and every existing login
// page test in this package calls the handler directly.

func headerTestServer(t *testing.T, issuer string) *Server {
	t.Helper()
	return &Server{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		login: newBucket(5, 20),
		cfg:   oidc.Config{Issuer: issuer},
	}
}

func TestTheBaselineBrowserHeadersAreOnEveryResponse(t *testing.T) {
	// The real server, with a database behind it: the sign-in page loads its
	// branding before rendering, so a stub server cannot serve it and a test
	// using one would silently cover only the JSON routes.
	f := newTokenFixture(t)

	// An HTML route and two JSON ones. The JSON ones are the point: headers get
	// added to the pages somebody is looking at and forgotten on the endpoints
	// they are not.
	for _, path := range []string{"/login", "/healthz", "/.well-known/openid-configuration"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)

			// Without this the assertions below hold vacuously: the middleware
			// runs before routing, so a 404 carries the headers too and would
			// prove only that the middleware exists.
			if rec.Code == http.StatusNotFound {
				t.Fatalf("%s is not a route on this server, so this case tests nothing", path)
			}

			// V3.4.4 (L1). This server answers JSON almost everywhere and echoes
			// caller-supplied values into `error_description`; a browser that
			// sniffs one of those as HTML runs script on the issuer's origin,
			// which is the origin holding the session cookie.
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff (V3.4.4, Level 1)", got)
			}
			// V3.4.5 (L2). Authorization requests carry `state` and `login_hint`
			// in the query string and authorization RESPONSES carry `code`.
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want no-referrer (V3.4.5): a resource "+
					"loaded from a page whose URL holds an authorization code would "+
					"otherwise send that code onward in a request header", got)
			}
			// The fixture's issuer is https, so V3.4.1 applies here too. Asserted
			// through the router rather than only against the middleware, because
			// the middleware being correct and the middleware being WIRED are
			// different claims and only this one checks the second.
			if got := rec.Header().Get("Strict-Transport-Security"); got == "" {
				t.Error("no Strict-Transport-Security header (V3.4.1, Level 1)")
			}
		})
	}
}

// V3.4.1: "A maximum age of at least 1 year must be defined, and for L2 and up,
// the policy must apply to all subdomains as well."
//
// The middleware directly, with a trivial handler behind it. The wiring is
// asserted above through the router; what is asserted here is the decision the
// middleware makes about the issuer scheme, which needs two servers and no
// working routes at all.
func TestHSTSIsSentForAnHTTPSIssuerAndNotForAPlaintextOne(t *testing.T) {
	probe := func(issuer string) string {
		s := headerTestServer(t, issuer)
		rec := httptest.NewRecorder()
		s.withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec.Header().Get("Strict-Transport-Security")
	}

	got := probe("https://headers.test")
	if got == "" {
		t.Fatal("no Strict-Transport-Security header for an https issuer (V3.4.1, Level 1)")
	}
	if !strings.Contains(got, "max-age=31536000") {
		t.Errorf("HSTS = %q; V3.4.1 requires a maximum age of at least one year", got)
	}
	if !strings.Contains(got, "includeSubDomains") {
		t.Errorf("HSTS = %q; V3.4.1 requires the policy to cover subdomains at L2", got)
	}

	// AllowInsecureIssuer exists so the OIDF conformance suite can reach the
	// engine over plain http by a service name. A browser ignores HSTS received
	// over plaintext, so sending it there would be a header that does nothing --
	// and a header that does nothing is worse documentation than one that is
	// absent for a stated reason.
	if got := probe("http://conformance-suite:8080"); got != "" {
		t.Errorf("HSTS = %q on a plaintext issuer", got)
	}
}

// V3.4.3 names `object-src 'none'` and `base-uri 'none'` explicitly, and it names
// both because only one of them is reachable through `default-src`.
//
// `object-src` falls back to `default-src`, so our `default-src 'none'` already
// covered it. `base-uri` has NO fallback -- it sits outside the default-src
// chain -- so every policy this server sent left `<base>` unrestricted.
func TestEveryContentSecurityPolicyCarriesTheInvariantDirectives(t *testing.T) {
	// Exercised through setCSP, which is what all ten call sites now use.
	for name, policy := range map[string]string{
		"the sign-in page":     `default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`,
		"a bare policy":        `frame-ancestors 'none'`,
		"a trailing semicolon": `default-src 'none';`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			setCSP(rec, policy)
			got := rec.Header().Get("Content-Security-Policy")

			if !strings.Contains(got, "base-uri 'none'") {
				t.Errorf("policy %q carries no base-uri; `base-uri` does not fall "+
					"back to `default-src`, so <base> is unrestricted and every "+
					"relative URL on the page can be re-pointed", got)
			}
			if !strings.Contains(got, "object-src 'none'") {
				t.Errorf("policy %q carries no object-src (V3.4.3)", got)
			}
			// The original policy must survive intact, or the helper is
			// silently weakening the pages it was added to protect.
			for _, d := range strings.Split(strings.TrimSuffix(strings.TrimSpace(policy), ";"), ";") {
				if d = strings.TrimSpace(d); d != "" && !strings.Contains(got, d) {
					t.Errorf("the helper dropped %q from the policy: %q", d, got)
				}
			}
			if strings.Contains(got, ";;") {
				t.Errorf("the policy has an empty directive: %q", got)
			}
		})
	}
}
