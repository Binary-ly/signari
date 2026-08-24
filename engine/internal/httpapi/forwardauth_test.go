package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"signari.dev/engine/internal/oidc"
)

func newProxyServer() *Server {
	return &Server{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: oidc.Config{Issuer: "https://auth.example.test"},
	}
}

// TestProxyVerifyStripsCallerIdentityHeaders is the test for the vulnerability
// this endpoint exists to avoid.
//
// A forward-auth setup copies the auth server's RESPONSE headers onto the
// upstream request. So a header the caller sent that we echo -- or merely fail
// to overwrite -- arrives at the application as an authenticated identity. The
// caller here is unauthenticated and is claiming to be an administrator.
func TestProxyVerifyStripsCallerIdentityHeaders(t *testing.T) {
	s := newProxyServer()

	for _, h := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Sub"} {
		req := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
		req.Header.Set(h, "admin@evil.test")
		rec := httptest.NewRecorder()

		// Some proxies pre-populate the recorder's headers from the request.
		// Simulating that is the only way to prove we DELETE rather than merely
		// decline to set.
		rec.Header().Set(h, "admin@evil.test")

		s.handleProxyVerify(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: unauthenticated request got %d, want 401", h, rec.Code)
		}
		if got := rec.Header().Get(h); got != "" {
			t.Errorf("%s survived to the response as %q; the application would "+
				"treat that as a signed-in user", h, got)
		}
	}
}

// TestAMalformedProxyCookieIsDeniedNotPassedThrough pins the one answer a
// forward-auth endpoint may give to a cookie that does not verify.
//
// The failure mode this guards against: a malformed cookie is treated as "no
// identity" rather than as "denied", and the request is passed through with none
// of the identity headers set. Whether the application is protected then depends
// on how it treats an absent header -- which is a decision the proxy has silently
// delegated to something that does not know it is making one. The only acceptable
// answers are 401 and nothing else, never a 200 whose emptiness the application
// must notice.
func TestAMalformedProxyCookieIsDeniedNotPassedThrough(t *testing.T) {
	s := newProxyServer()

	for _, hostile := range []string{
		"not-a-jwt",
		"..",                    // three empty JWT segments
		"e30.e30.",              // {} header, {} payload, empty signature
		string(make([]byte, 8)), // NULs
	} {
		req := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
		req.AddCookie(&http.Cookie{Name: ProxyCookieName, Value: hostile})
		rec := httptest.NewRecorder()

		s.handleProxyVerify(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("cookie %q: got %d, want 401 -- a malformed credential must "+
				"deny, not pass through for the application to judge", hostile, rec.Code)
		}
		for _, h := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Sub"} {
			if got := rec.Header().Get(h); got != "" {
				t.Errorf("cookie %q: %s = %q on a denial", hostile, h, got)
			}
		}
	}
}

// TestProxyVerifyDenyPointsAtStart checks the 401 carries somewhere to go, and
// that the return URL is the one the PROXY reported rather than anything the
// caller could smuggle past it.
func TestProxyVerifyDenyPointsAtStart(t *testing.T) {
	s := newProxyServer()
	req := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.test")
	req.Header.Set("X-Forwarded-Uri", "/dashboard?tab=1")
	rec := httptest.NewRecorder()

	s.handleProxyVerify(rec, req)

	want := "https://auth.example.test/proxy/start?rd=" +
		"https%3A%2F%2Fapp.example.test%2Fdashboard%3Ftab%3D1"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if rec.Header().Get("X-Signari-Reason") == "" {
		t.Error("no X-Signari-Reason: nginx auth_request discards the body, so an " +
			"operator debugging a 401 has nowhere to look")
	}
}

// TestFirstHeaderTakesTheFirstValue pins the header-splitting rule.
//
// A proxy chain APPENDS, so "X-Forwarded-Host: real, evil" is one header with
// two values. Taking the last -- the intuitive "most recent" reading -- lets
// the caller choose the host, because the caller's value is appended after the
// trusted one.
func TestFirstHeaderTakesTheFirstValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Host", "real.example.test, evil.test")
	if got := firstHeader(req, "X-Forwarded-Host"); got != "real.example.test" {
		t.Errorf("firstHeader = %q, want %q", got, "real.example.test")
	}
}

func TestOriginalURLRequiresProtoAndHost(t *testing.T) {
	cases := []struct {
		name, proto, host, uri, want string
	}{
		{"complete", "https", "app.example.test", "/x", "https://app.example.test/x"},
		{"empty uri defaults to root", "https", "app.example.test", "", "https://app.example.test/"},
		// Incomplete input yields "", which suppresses the rd parameter entirely.
		// Guessing a scheme here would be inventing part of a redirect target.
		{"no proto", "", "app.example.test", "/x", ""},
		{"no host", "https", "", "/x", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.proto != "" {
				req.Header.Set("X-Forwarded-Proto", c.proto)
			}
			if c.host != "" {
				req.Header.Set("X-Forwarded-Host", c.host)
			}
			if c.uri != "" {
				req.Header.Set("X-Forwarded-Uri", c.uri)
			}
			if got := originalURL(req); got != c.want {
				t.Errorf("originalURL = %q, want %q", got, c.want)
			}
		})
	}
}

// TestIsLoopback guards the check that decides whether http is acceptable.
//
// Both directions are dangerous. Too narrow and `n8n.localhost` -- the standard
// way to run several local services on real hostnames -- is rejected as
// insecure, which is the bug this test was written for. Too broad and a
// hostname an attacker controls gets to carry a redirect over plaintext.
func TestIsLoopback(t *testing.T) {
	loopback := []string{
		"localhost", "127.0.0.1", "::1",
		"n8n.localhost", "app.localhost", "LOCALHOST", "N8N.Localhost",
		"a.b.localhost", // RFC 6761 reserves the whole subtree, at any depth
	}
	for _, h := range loopback {
		if !isLoopback(h) {
			t.Errorf("isLoopback(%q) = false; RFC 6761 reserves .localhost and "+
				"browsers treat it as a secure context", h)
		}
	}

	notLoopback := []string{
		"example.test",
		"localhost.evil.test", // suffix the other way round -- resolves publicly
		"notlocalhost",        // no dot: not a subdomain of localhost
		"evil-localhost",      // ditto, with a separator that is not a label break
		"localhost.evil",      // the label is a prefix, not the TLD
		"127.0.0.1.evil.test", // looks loopback, is not
		"xn--localhost-vk9c",  // punycode homograph
		"",
	}
	for _, h := range notLoopback {
		if isLoopback(h) {
			t.Errorf("isLoopback(%q) = true; that host resolves over the network, "+
				"so plaintext there crosses it", h)
		}
	}
}

// TestCookieReaches covers the redirect-loop guard.
//
// Getting this wrong in either direction is bad: too strict and a valid
// deployment is refused, too loose and the operator gets an infinite loop with
// no error anywhere to explain it.
func TestCookieReaches(t *testing.T) {
	ok := [][2]string{
		{"example.com", "app.example.com"},
		{"example.com", "example.com"},      // the domain itself
		{".example.com", "app.example.com"}, // leading dot, as cookies are often written
		{"example.com", "a.b.example.com"},  // any depth
		{"localhost", "n8n.localhost"},      // the local development shape
		{"example.com", "app.example.com."}, // fully-qualified, trailing dot
		{"EXAMPLE.com", "APP.example.COM"},  // host comparison is case-insensitive
	}
	for _, c := range ok {
		if err := cookieReaches(c[0], c[1]); err != nil {
			t.Errorf("cookieReaches(%q, %q) = %v, want nil", c[0], c[1], err)
		}
	}

	bad := [][2]string{
		{"", "app.example.com"},                  // unset: the cookie is host-only
		{"example.com", "example.com.evil.test"}, // suffix the wrong way round
		{"example.com", "notexample.com"},        // no label boundary
		{"example.com", "evilexample.com"},       // ditto
		{"localhost", "127.0.0.1"},               // the case found by running it
		{"app.example.com", "other.example.com"}, // sibling, not descendant
	}
	for _, c := range bad {
		if err := cookieReaches(c[0], c[1]); err == nil {
			t.Errorf("cookieReaches(%q, %q) = nil, but the browser would never send "+
				"that cookie, so the deployment would loop", c[0], c[1])
		}
	}
}
