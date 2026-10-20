package httpapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/logging"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/ratelimit"
)

// With the access log on, every request is one line: the route pattern, not
// the path, the status the client got, including a recovered panic's 500,
// and the correlation id (3.07). A path segment that is somebody's address
// never reaches it.
func TestTheAccessLogNamesTheRouteNotThePath(t *testing.T) {
	var out bytes.Buffer
	log, err := logging.New(&out, func(k string) string {
		return map[string]string{"SIGNARI_LOG_FORMAT": "json"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{log: log, login: ratelimit.New(5, 20), cfg: oidc.Config{Issuer: "https://id.example.test"}}
	s.SetAccessLog(true)
	routes := s.Routes()

	lines := func() []map[string]any {
		var got []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "request" {
				got = append(got, m)
			}
		}
		return got
	}

	for _, c := range []struct{ path, route string }{
		// No database behind this server: the handler panics, recovery
		// answers 500, and the access log records that 500.
		{"/login/with/alice@example.test", "/login/with/{slug}"},
		{"/no/such/route/alice@example.test", "other"},
	} {
		out.Reset()
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		got := lines()
		if len(got) != 1 {
			t.Fatalf("%s: %d access log lines, want 1:\n%s", c.path, len(got), out.String())
		}
		l := got[0]
		if l["route"] != c.route || int(l["status"].(float64)) != rec.Code || l["method"] != "GET" {
			t.Errorf("%s: logged route %v status %v, want %s %d", c.path, l["route"], l["status"], c.route, rec.Code)
		}
		if l["correlation_id"] != rec.Header().Get("X-Correlation-Id") || l["correlation_id"] == "" {
			t.Errorf("%s: logged correlation id %v, the response said %q", c.path, l["correlation_id"],
				rec.Header().Get("X-Correlation-Id"))
		}
		for _, raw := range strings.Split(out.String(), "\n") {
			if strings.Contains(raw, `"msg":"request"`) && strings.Contains(raw, "alice@example.test") {
				t.Errorf("%s: the access log line carries the address in the path: %s", c.path, raw)
			}
		}
	}

	out.Reset()
	(&Server{log: log, login: ratelimit.New(5, 20)}).Routes().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if len(lines()) != 0 {
		t.Errorf("with the access log off, a request was logged: %s", out.String())
	}
}

type hijackable struct {
	http.ResponseWriter
	hijacked bool
}

func (h *hijackable) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

// The recorder passes the connection through: a remote-access session's
// websocket upgrade hijacks it, and a wrapper that hid it would answer every
// such session 501 for as long as the access log was on.
func TestTheAccessLogLeavesTheConnectionHijackable(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := &hijackable{ResponseWriter: httptest.NewRecorder()}
	var herr error
	s.withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, herr = http.NewResponseController(w).Hijack()
	})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/rac/connect/x", nil))
	if errors.Is(herr, http.ErrNotSupported) || !w.hijacked {
		t.Errorf("hijacking through the access log: %v (hijacked %v)", herr, w.hijacked)
	}
}
