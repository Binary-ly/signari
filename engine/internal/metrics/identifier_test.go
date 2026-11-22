package metrics

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// No metric label may ever carry an identifier.
//
// # Why this is a build-failing test and not a code review note
//
// A metric goes somewhere this system cannot reach. It is scraped into a
// time-series database, retained for months, copied into dashboards, and
// federated into long-term storage — all outside the boundary
// `subjects/{id}/erase` operates on. An identifier that reaches a label is
// therefore permanent: the crypto-shredding design destroys the subject's key
// here and touches none of that copy.
//
// That makes this the one instrumentation mistake with no remediation. A bad log
// line can be rotated away; a bad metric label is already in somebody else's
// database by the time anybody notices, and it is in every backup of it.
//
// The second cost is operational and lands sooner: one series per user is how a
// Prometheus server exhausts its memory, which takes the monitoring down at
// precisely the moment it is needed.
//
// So the containment is structural — every labelled metric declares its complete
// value set, and anything else becomes "other" — and these tests hold that
// property from the outside, against rendered output, rather than by reading the
// declarations back.

// identifierish matches label values that look like something about a person.
var identifierish = regexp.MustCompile(
	`(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` + // uuid
		`|@[a-z0-9.-]+\.[a-z]{2,}` + // email
		`|\b\d{1,3}(\.\d{1,3}){3}\b` + // IPv4
		`|[0-9a-f]{32,})`) // a hash or a token

func TestAnUndeclaredLabelValueBecomesOther(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("test_total", "help", []string{"outcome"},
		[]ValueSet{set("succeeded", "failed")})

	// The shape of the bug: somebody reaches for the nearest variable and it is
	// the subject id.
	c.Inc("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
	c.Inc("succeeded")

	var b bytes.Buffer
	r.Render(&b)
	out := b.String()

	if strings.Contains(out, "3f2504e0") {
		t.Fatalf("a uuid reached the exposition output:\n%s", out)
	}
	if !strings.Contains(out, `outcome="other"`) {
		t.Errorf("the undeclared value was not contained as %q:\n%s", OtherValue, out)
	}
	if !strings.Contains(out, `outcome="succeeded"`) {
		t.Errorf("the declared value was lost:\n%s", out)
	}
}

// Every value a caller can pass is contained, not just the ones anticipated.
func TestNoMetricLabelCanCarryAnIdentifier(t *testing.T) {
	e := NewEngine()
	RegisterRoutePattern("/authorize")

	hostile := []string{
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"alice@example.com",
		"203.0.113.7",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"/admin/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
	}

	for _, v := range hostile {
		e.SignIns.Inc(v)
		e.Tokens.Inc(v)
		e.AuthFailures.Inc(v)
		e.Requests.Inc(v, v, v)
		e.Latency.Observe(0.1, v)
		e.Providers.Inc(v, v)
	}

	var b bytes.Buffer
	e.Registry.Render(&b)
	out := b.String()

	if m := identifierish.FindString(out); m != "" {
		t.Fatalf("something identifier-shaped reached the exposition output: %q\n"+
			"A metric label is scraped outside this system and outlives every "+
			"erasure request, so this is the one instrumentation mistake with no "+
			"remediation.\n%s", m, out)
	}
}

// The HTTP label is the route PATTERN, never the path.
//
// This is where the mistake actually happens: nobody writes `user_id` as a label,
// they write `path`, and `/admin/users/{userID}` as a concrete path contains a
// uuid. The pattern is bounded by the routing table; the path is bounded by
// whatever anybody requests.
func TestTheRouteLabelIsThePatternNotThePath(t *testing.T) {
	RegisterRoutePattern("/admin/users/{userID}")
	e := NewEngine()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/users/{userID}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := e.Middleware(mux)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/admin/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the fixture route did not match: %d", rec.Code)
	}

	var b bytes.Buffer
	e.Registry.Render(&b)
	out := b.String()

	if strings.Contains(out, "3f2504e0") {
		t.Fatalf("the concrete path reached a label:\n%s", out)
	}
	if !strings.Contains(out, `route="/admin/users/{userID}"`) {
		t.Errorf("the route pattern was not recorded:\n%s", out)
	}
}

// An unmatched request must not export what was probed for.
//
// A 404 has no pattern, and reporting the path instead would make the label set
// attacker-chosen: a scanner walking a wordlist would create a series per probe.
func TestAnUnmatchedRequestDoesNotExportItsPath(t *testing.T) {
	e := NewEngine()
	h := e.Middleware(http.NewServeMux())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.env-or-some-probe", nil))

	var b bytes.Buffer
	e.Registry.Render(&b)
	if strings.Contains(b.String(), "env-or-some-probe") {
		t.Fatalf("a probed path became a label:\n%s", b.String())
	}
}

// A label with no declared values is refused at construction.
//
// The unbounded label is the failure this package exists to prevent, and the way
// it arrives is a caller who passed nil because they had not decided yet.
func TestAnUnboundedLabelIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a counter with an empty value set was accepted. That label " +
				"is unbounded, which is how an identifier reaches a metrics store.")
		}
	}()
	NewRegistry().NewCounter("bad_total", "help", []string{"anything"},
		[]ValueSet{FixedSet{}})
}

// The output parses as the Prometheus text format.
//
// Not a full parser — a shape check. A malformed exposition is rejected by the
// scraper as a whole, so one bad line takes out every metric rather than its own.
// Latency is a series per route pattern, and a route outside the closed set
// is counted as other (3.08). One histogram over every route averaged a slow
// token endpoint into the health checks around it.
func TestLatencyIsLabelledByRoute(t *testing.T) {
	e := NewEngine()
	RegisterRoutePattern("/token")
	e.Latency.Observe(0.4, "/token")
	e.Latency.Observe(0.002, "/never/registered")

	var b bytes.Buffer
	e.Registry.Render(&b)
	out := b.String()
	for _, want := range []string{
		`signari_http_request_duration_seconds_bucket{route="/token",le="0.5"} 1`,
		`signari_http_request_duration_seconds_bucket{route="/token",le="0.25"} 0`,
		`signari_http_request_duration_seconds_count{route="/token"} 1`,
		`signari_http_request_duration_seconds_count{route="other"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the exposition lacks %q", want)
		}
	}
	if strings.Contains(out, "/never/registered") {
		t.Error("a route outside the declared set reached the exposition")
	}
}

func TestTheExpositionOutputIsWellFormed(t *testing.T) {
	e := NewEngine()
	RegisterRoutePattern("/authorize")
	RegisterProviderHook("claims")
	e.SignIns.Inc("succeeded")
	e.Latency.Observe(0.02, "/authorize")
	e.Providers.Inc("claims", "failed_open")
	e.Registry.RegisterRuntime()
	e.Registry.NewInfo("signari_build_info", "build", []string{"version"}, []string{"v1.2.0"})

	var b bytes.Buffer
	e.Registry.Render(&b)

	var lastHelp string
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			lastHelp = strings.Fields(line)[2]
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(line)
			if f[2] != lastHelp {
				t.Errorf("TYPE %s does not follow HELP %s", f[2], lastHelp)
			}
			if f[3] != "counter" && f[3] != "gauge" && f[3] != "histogram" {
				t.Errorf("unknown metric type %q", f[3])
			}
		case line == "":
		default:
			// A sample line ends with a value.
			f := strings.Fields(line)
			if len(f) != 2 {
				t.Errorf("sample line has %d fields, want 2: %q", len(f), line)
				continue
			}
			var v float64
			if _, err := fmt.Sscanf(f[1], "%g", &v); err != nil {
				t.Errorf("sample value %q is not a number: %q", f[1], line)
			}
		}
	}
}
