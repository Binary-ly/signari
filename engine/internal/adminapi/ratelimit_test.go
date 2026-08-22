package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"signari.dev/engine/internal/ratelimit"
)

// The administrative interface is rate limited in two places, for two different
// reasons, and both need pinning because neither is visible from a call site.

// The global limiter runs BEFORE authentication, which is the point of it.
//
// Every request costs a SHA-256 and an indexed database probe before it can be
// refused, so a caller holding no credential at all could otherwise generate
// unbounded database load. The existing reasoning in `auth` is right that
// guessing a 256-bit token is not the threat — this is about work, not secrets.
func TestUnauthenticatedFloodIsThrottledBeforeAuthentication(t *testing.T) {
	s, _ := newTestServer(t)
	// A tiny bucket so the test does not have to send two hundred requests.
	s.arrivals = ratelimit.New(0, 3)

	h := s.Routes()
	codes := map[int]int{}
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/config-version", nil)
		// No Authorization header at all.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes[rec.Code]++
	}

	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("an unauthenticated flood was never throttled: %v", codes)
	}
	// The first few still reach authentication and are refused there, which is
	// what proves the limiter is not simply rejecting everything.
	if codes[http.StatusUnauthorized] == 0 {
		t.Errorf("nothing reached authentication; the limiter is refusing all "+
			"traffic rather than bounding it: %v", codes)
	}
	if codes[http.StatusUnauthorized]+codes[http.StatusTooManyRequests] != 10 {
		t.Errorf("unexpected statuses: %v", codes)
	}
}

// A throttled response must tell the caller when to come back. A client told
// only "no" retries immediately and makes the problem worse.
func TestAThrottledAdminResponseCarriesRetryAfter(t *testing.T) {
	s, _ := newTestServer(t)
	s.arrivals = ratelimit.New(0, 0)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/config-version", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a 429 without Retry-After")
	}
}

// The limiter must be part of what Routes() hands back.
//
// The alternative shape — a bare mux plus a separate wrapper the caller is
// expected to apply — leaves two ways to serve this API, one of them unlimited
// and shorter to type. This asserts the wrapping rather than the wrapper.
func TestRoutesReturnsTheLimitedHandler(t *testing.T) {
	s, _ := newTestServer(t)
	s.arrivals = ratelimit.New(0, 0)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/users", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Routes() served a request past an empty limiter (%d); the "+
			"limiter is not part of what callers receive", rec.Code)
	}
}

// The per-token limiter, which exists for fairness rather than defence.
//
// The global limiter above already bounds total work. This stops one
// integration's bulk run from consuming the whole allowance while an operator is
// trying to use the console during the same incident — which is the failure mode
// a single shared bucket produces and cannot avoid.
func TestOneAdminTokenCannotConsumeEverybodysAllowance(t *testing.T) {
	s, _ := newTestServer(t)
	// Leave the global limiter generous so this measures the per-token one.
	s.arrivals = ratelimit.New(1000, 1000)
	s.perToken = ratelimit.NewKeyed(0, 3, 16)

	h := s.Routes()
	authed := func() int {
		req := httptest.NewRequest(http.MethodGet, "/admin/config-version", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Three succeed, then the fourth is throttled — on the token, not globally.
	for i := 0; i < 3; i++ {
		if code := authed(); code == http.StatusTooManyRequests {
			t.Fatalf("request %d of the token's own burst was throttled", i+1)
		}
	}
	if code := authed(); code != http.StatusTooManyRequests {
		t.Fatalf("a fourth request past the token's burst gave %d, want 429", code)
	}

	// And the global limiter still has plenty: an unauthenticated request is
	// refused for the right reason, which shows the exhaustion was per-token.
	req := httptest.NewRequest(http.MethodGet, "/admin/config-version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("with one token exhausted, another caller got %d rather than "+
			"reaching authentication; the limit is shared when it should not be",
			rec.Code)
	}
}
