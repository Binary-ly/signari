package httpapi

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// ASVS 5.0.0 V4.4.2: the Origin header field is checked during the initial
// WebSocket handshake.
//
// It was — by the WebSocket library, during the upgrade, which is the LAST thing
// the remote-access handler does. Before reaching it the handler evaluated the
// access policy, wrote an audit row, wrote a session row, and dialled guacd,
// which opens a connection to the target machine.
//
// A WebSocket handshake carries cookies, so a page on another origin could open
// one against a signed-in victim and every one of those checks would pass — the
// victim really is entitled to that host. The attacker reads nothing, because the
// upgrade is refused a moment later. The connection to the internal machine still
// happened, and happens again on every reload of their page.
//
// There were no tests for this handler of any kind.

// racServer gives the handler a guacd address pointing at a listener this test
// owns, so "was guacd dialled" is an observable rather than an assumption.
func racServer(t *testing.T) (*tokenFixture, *int64) {
	t.Helper()
	f := newTokenFixture(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var dials int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&dials, 1)
			_ = c.Close()
		}
	}()

	f.srv.guacdAddr = ln.Addr().String()
	return f, &dials
}

func TestACrossOriginRemoteAccessUpgradeIsRefusedBeforeAnythingHappens(t *testing.T) {
	f, dials := racServer(t)

	req := httptest.NewRequest(http.MethodGet, "/rac/connect/anything", nil)
	req.Host = "idp.example"
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403. A 401 here means the origin was never "+
			"checked and the request simply failed the session lookup instead --"+
			" which is what happens when the check is removed, and a signed-in "+
			"victim would have carried on past it: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); !contains(got, "only be opened from this site") {
		t.Errorf("refused for some other reason: %s", got)
	}
	if n := atomic.LoadInt64(dials); n != 0 {
		t.Errorf("guacd was dialled %d time(s) by a cross-origin request", n)
	}
}

// A same-origin request must get past the origin check. Without this the fix
// above could be "refuse everything", which passes the test above and breaks
// remote access entirely.
func TestASameOriginRemoteAccessRequestPassesTheOriginCheck(t *testing.T) {
	f, dials := racServer(t)

	req := httptest.NewRequest(http.MethodGet, "/rac/connect/anything", nil)
	req.Host = "idp.example"
	req.Header.Set("Origin", "https://idp.example")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	// 401, because this request carries no session — which is the point: it got
	// PAST the origin check and was stopped by the next one.
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: a same-origin request should reach the "+
			"session check, not be refused as cross-origin. %s",
			rec.Code, rec.Body.String())
	}
	// Still nothing dialled: the session check also precedes guacd.
	if n := atomic.LoadInt64(dials); n != 0 {
		t.Errorf("guacd was dialled %d time(s) for an unauthenticated request", n)
	}
}

func TestSameOriginRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		origin, host string
		want         bool
	}{
		"absent origin is allowed":  {"", "idp.example", true},
		"matching host":             {"https://idp.example", "idp.example", true},
		"case-insensitive host":     {"https://IDP.example", "idp.example", true},
		"matching host and port":    {"https://idp.example:8443", "idp.example:8443", true},
		"different host":            {"https://evil.example", "idp.example", false},
		"different port":            {"https://idp.example:9999", "idp.example:8443", false},
		"subdomain is not the same": {"https://a.idp.example", "idp.example", false},
		"malformed":                 {"://", "idp.example", false},
		"null origin":               {"null", "idp.example", false},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := sameOriginRequest(r); got != tc.want {
				t.Errorf("sameOriginRequest(origin=%q, host=%q) = %v, want %v",
					tc.origin, tc.host, got, tc.want)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
