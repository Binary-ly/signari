package metrics

import (
	"net/http"
	"time"
)

// The engine's metric set.
//
// Deliberately small. Every series is a commitment: it is scraped forever, it
// costs memory in somebody's Prometheus, and — for anything labelled — it is a
// place an identifier could escape to. The bar for adding one is that an
// operator would page on it or debug with it, not that it was easy to collect.
//
// # What is NOT here, and why
//
// No per-client, per-user, per-organisation or per-session series. That is the
// label rule in the package comment, and it is worth restating as a design
// consequence rather than only a prohibition: this endpoint answers "is the
// deployment healthy", never "what is this tenant doing". The second question is
// the audit trail's, which is queryable, access-controlled, and erasable — three
// properties a metrics store has none of.
//
// No request path either. `/admin/users/{userID}` as a raw path IS an
// identifier, so the HTTP counter is labelled by the ROUTE PATTERN the mux
// matched. Getting that wrong would put a uuid into a label without anybody
// writing an identifier anywhere, which is exactly how this mistake usually
// happens.

// Engine is the registry plus the handles the server increments.
type Engine struct {
	Registry *Registry

	// Requests counts HTTP responses by route pattern, method and status class.
	//
	// Status CLASS rather than code: 2xx/3xx/4xx/5xx is what an alert is written
	// against, and the exact code is in the access log where it can be correlated
	// with a request id.
	Requests *Counter

	// Latency is the whole-server latency distribution, unlabelled.
	//
	// Bounds are set for an identity provider rather than a generic service: a
	// token endpoint answering in 5 ms and one answering in 500 ms are different
	// incidents, and the interesting range is the bottom of it. The top bucket is
	// 10s because anything slower has already timed out somewhere upstream.
	Latency *Histogram

	// Sign-ins by outcome. The single most useful series here: a deployment
	// whose failure rate moves is one with a broken integration or an attack,
	// and neither is visible in a request count.
	SignIns *Counter

	// Tokens issued by grant type. Bounded by the grants the server dispatches.
	Tokens *Counter

	// Authentication failures by mechanism, so a guessing run against LDAP or
	// RADIUS is visible without reading the audit trail.
	AuthFailures *Counter
}

// routePatterns is the set of route labels, filled during startup.
//
// Growable rather than fixed because the 123 registrations that populate it all
// run after this variable exists — see ValueSet for why conflating the two kinds
// of closed set panicked the first version of this package.
//
// It is still closed by the time anything is served: a pattern the mux matched
// that is not in here becomes "other". That is belt-and-braces, since a pattern
// contains no identifier by construction, but a route added later with a literal
// id in it, or a mux change that started handing over raw paths, would be
// contained rather than exported.
var routePatterns = NewGrowableSet()

// RegisterRoutePattern declares a route label as safe to export.
//
// Called by the server for every pattern it registers. The patterns come from
// the mux, so they carry `{userID}` rather than a uuid.
func RegisterRoutePattern(p string) { routePatterns.Add(p) }

func set(values ...string) ValueSet {
	m := make(FixedSet, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// NewEngine builds the engine's metrics on a fresh registry.
func NewEngine() *Engine {
	r := NewRegistry()
	e := &Engine{Registry: r}

	e.Requests = r.NewCounter("signari_http_requests_total",
		"HTTP responses by route pattern, method and status class.",
		[]string{"route", "method", "status"},
		[]ValueSet{
			routePatterns,
			set("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
			set("2xx", "3xx", "4xx", "5xx"),
		})

	e.Latency = r.NewHistogram("signari_http_request_duration_seconds",
		"Request latency in seconds.",
		[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10})

	e.SignIns = r.NewCounter("signari_signins_total",
		"Sign-in attempts by outcome.",
		[]string{"outcome"},
		[]ValueSet{
			set("succeeded", "failed", "mfa_required", "rate_limited", "refused"),
		})

	e.Tokens = r.NewCounter("signari_tokens_issued_total",
		"Tokens issued by grant type.",
		[]string{"grant"},
		[]ValueSet{
			set("authorization_code", "refresh_token", "client_credentials",
				"device_code", "ciba", "token_exchange", "jwt_bearer",
				"password", "preauthorized_code"),
		})

	e.AuthFailures = r.NewCounter("signari_auth_failures_total",
		"Failed authentications by mechanism.",
		[]string{"mechanism"},
		[]ValueSet{
			set("password", "ldap", "radius", "client_secret", "client_assertion",
				"mfa", "passkey", "kerberos"),
		})

	return e
}

// StatusClass maps a code to the label value.
func StatusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	}
	return OtherValue
}

// Middleware records one request.
//
// The route label comes from `http.Request.Pattern`, which Go's ServeMux sets to
// the pattern that matched — `GET /admin/users/{userID}`, never the concrete
// path. Using r.URL.Path here would export a uuid per user, which is both the
// privacy failure and the cardinality failure in one line.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)

		e.Latency.Observe(time.Since(start).Seconds())
		e.Requests.Inc(patternOf(r), r.Method, StatusClass(rec.code))
	})
}

// patternOf returns the matched route pattern without its method prefix.
func patternOf(r *http.Request) string {
	p := r.Pattern
	if p == "" {
		// No pattern means no route matched -- a 404. Reporting the path here
		// would export whatever a scanner probed for, which is unbounded by
		// definition and attacker-chosen.
		return OtherValue
	}
	// Patterns are "METHOD /path"; the method is already its own label.
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			return p[i:]
		}
	}
	return p
}

type statusRecorder struct {
	http.ResponseWriter
	code    int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.code, s.written = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}

// Flush lets the recorder sit in front of a streaming handler.
//
// Without it, wrapping the mux would silently break server-sent events and any
// other handler that flushes -- the response would be buffered until the handler
// returned, which for a stream is forever.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Handler serves the exposition format.
func (e *Engine) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		// Never cached. A scrape reads a counter at a moment; a cached one
		// reports a rate of zero for as long as it is served.
		w.Header().Set("Cache-Control", "no-store")
		e.Registry.Render(w)
	})
}
