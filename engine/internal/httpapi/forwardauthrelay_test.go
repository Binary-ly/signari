package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/proxycheck"
)

// A proxy that relays the auth server's refusal to the browser unchanged, as
// Traefik's forwardAuth and Caddy's forward_auth do for any non-2xx answer:
// status, Location and body copied verbatim. Signari's 401 then left the
// browser on an error page, since a browser follows Location only on a 3xx,
// and `proxy check` counted the 401 as protection (2.57).
func relayingProxy(t *testing.T, s *Server, verifyPath string) *httptest.Server {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := httptest.NewRequest(http.MethodGet, verifyPath, nil)
		for k, v := range r.Header { // the client's headers, Accept among them
			auth.Header[k] = v
		}
		auth.Header.Set("X-Forwarded-Proto", "https")
		auth.Header.Set("X-Forwarded-Host", "app.example.test")
		auth.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
		auth.Header.Set("X-Forwarded-Method", r.Method)
		rec := httptest.NewRecorder()
		s.handleProxyVerify(rec, auth)
		if rec.Code >= 200 && rec.Code < 300 {
			_, _ = io.WriteString(w, "the application")
			return
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(p.Close)
	return p
}

func TestARelayingProxySendsABrowserToSignInOnTheRedirectVariant(t *testing.T) {
	s := newProxyServer()
	report := func(path string) *proxycheck.Report {
		t.Helper()
		rep, err := proxycheck.Run(context.Background(), proxycheck.Options{
			BaseURL: relayingProxy(t, s, path).URL, Issuer: s.cfg.Issuer})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	browser := func(rep *proxycheck.Report) proxycheck.Result {
		t.Helper()
		for _, r := range rep.Results {
			if strings.Contains(r.Probe, "browser") {
				return r
			}
		}
		t.Fatal("proxy check has no browser probe")
		return proxycheck.Result{}
	}

	old := report("/proxy/verify")
	if got := browser(old); got.Status != proxycheck.Stranded {
		t.Errorf("behind a relaying proxy on /proxy/verify the browser probe was %v (%s), want stranded: "+
			"proxy check passed a set-up nobody can sign in through", got.Status, got.Detail)
	}

	fixed := report(pathProxyVerifyRedirect)
	if got := browser(fixed); got.Status != proxycheck.Protected {
		t.Errorf("on the redirect variant the browser probe was %v (%s), want sent to sign in",
			got.Status, got.Detail)
	}
	for _, r := range fixed.Results {
		if r.Status == proxycheck.Exposed || r.Status == proxycheck.Stranded {
			t.Errorf("on the redirect variant %s was %v: %s", r.Probe, r.Status, r.Detail)
		}
	}

	// A call that is not a page load keeps the 401: an API client given a 302
	// would follow it to a sign-in page it cannot use.
	for _, c := range []struct{ method, accept string }{
		{http.MethodGet, "application/json"}, {http.MethodPost, "text/html"}} {
		req := httptest.NewRequest(http.MethodGet, pathProxyVerifyRedirect, nil)
		req.Header.Set("Accept", c.accept)
		req.Header.Set("X-Forwarded-Method", c.method)
		rec := httptest.NewRecorder()
		s.handleProxyVerify(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with Accept %s on the redirect variant answered %d, want 401", c.method, c.accept, rec.Code)
		}
	}
}
