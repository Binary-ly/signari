package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// SetAccessLog turns on one log line per request (3.07): the method, the
// route that matched, the status, the bytes written and how long it took,
// with the request's correlation id. Off by default. The route is the
// pattern, `GET /admin/users/{userID}`, never the path, which would put a
// person's identifier in every line, and never the query string, which can
// carry a code or a login hint. There is no client address in it either.
func (s *Server) SetAccessLog(on bool) { s.accessLog = on }

type routeKey struct{}

// withAccessLog writes the line once the request has been answered,
// including a panic recovery's 500, which is why it sits outside recovery.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		route := new(string)
		rec := &accessRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), routeKey{}, route)))
		s.log.InfoContext(r.Context(), "request",
			"method", r.Method,
			"route", routeOf(*route),
			"status", rec.code,
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds())
	})
}

// noteRoute wraps the mux directly and hands the pattern it matched to
// withAccessLog. The mux writes Request.Pattern on the request it is given,
// which no outer wrapper holds, because each of them passed on a copy.
func noteRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p, ok := r.Context().Value(routeKey{}).(*string); ok {
				*p = r.Pattern
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// routeOf is the matched pattern without its method, or "other" when no
// route matched: the path of a 404 is whatever a scanner probed for.
func routeOf(pattern string) string {
	if pattern == "" {
		return "other"
	}
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[i:]
	}
	return pattern
}

type accessRecorder struct {
	http.ResponseWriter
	code    int
	bytes   int
	written bool
}

func (a *accessRecorder) WriteHeader(code int) {
	if !a.written {
		a.code, a.written = code, true
	}
	a.ResponseWriter.WriteHeader(code)
}

func (a *accessRecorder) Write(b []byte) (int, error) {
	a.written = true
	n, err := a.ResponseWriter.Write(b)
	a.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController, and the websocket upgrade behind a
// remote-access session, reach the connection underneath.
func (a *accessRecorder) Unwrap() http.ResponseWriter { return a.ResponseWriter }
