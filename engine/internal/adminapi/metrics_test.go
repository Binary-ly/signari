package adminapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/metrics"
)

// Every admin request is counted by its route pattern, method and status
// class, never its concrete path, which would export a client id per series.
// The admin API was not instrumented at all (2.36).
func TestAdminRequestsAreCountedByRoutePattern(t *testing.T) {
	s, _ := newTestServer(t)
	met := metrics.NewEngine()
	s.SetMetrics(met)

	call(t, s, http.MethodGet, "/admin/config-version", testToken, nil)
	call(t, s, http.MethodPatch, "/admin/clients/no-such-client-metrics", testToken,
		map[string]any{"enabled": true})

	rec := httptest.NewRecorder()
	met.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	scrape := string(body)
	for _, want := range []string{
		`signari_http_requests_total{route="/admin/config-version",method="GET",status="2xx"} 1`,
		`signari_http_requests_total{route="/admin/clients/{clientID}",method="PATCH",status="4xx"} 1`,
	} {
		if !strings.Contains(scrape, want) {
			t.Errorf("the scrape lacks %s", want)
		}
	}
	if strings.Contains(scrape, "no-such-client-metrics") {
		t.Error("a concrete client id reached a label")
	}
}
