package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/metrics"
)

// A report is counted by its directive and goes no further. What it carries is the URL
// a person was on, which here can hold a code, so a log line of it would put that
// somewhere it should never be.
func TestACSPReportIsCountedAndKeptNowhere(t *testing.T) {
	f := newTokenFixture(t)
	var logged bytes.Buffer
	f.srv.log = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.srv.metrics = metrics.NewEngine()
	report := func(body string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, cspReportPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/csp-report")
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	const secret = "code-that-must-go-nowhere"
	body := `{"csp-report":{"document-uri":"https://id.test/cb?code=` + secret + `",` +
		`"effective-directive":"script-src-elem","violated-directive":"script-src","blocked-uri":"inline"}}`
	for range 2 {
		if code := report(body); code != http.StatusNoContent {
			t.Fatalf("a report answered %d", code)
		}
	}
	for _, other := range []string{`{"csp-report":{"effective-directive":"made-up-by-a-stranger"}}`, `not json`} {
		if code := report(other); code != http.StatusNoContent {
			t.Fatalf("%q answered %d", other, code)
		}
	}
	if code := report(strings.Repeat("x", maxCSPReport+1)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("an enormous report answered %d", code)
	}

	exposition := httptest.NewRecorder()
	f.srv.metrics.Handler().ServeHTTP(exposition, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := exposition.Body.String()
	if !strings.Contains(out, `signari_csp_violations_total{directive="script-src"} 2`) {
		t.Errorf("the violations were not counted by directive:\n%s", grepLines(out, "csp"))
	}
	if !strings.Contains(out, `signari_csp_violations_total{directive="other"} 2`) {
		t.Errorf("what a stranger made up was not folded into other:\n%s", grepLines(out, "csp"))
	}
	if strings.Contains(out, "made-up-by-a-stranger") {
		t.Error("a stranger minted a label value")
	}
	if strings.Contains(logged.String(), secret) || strings.Contains(out, secret) {
		t.Errorf("what a report carried went somewhere:\n%s", logged.String())
	}
}

func grepLines(text, word string) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, word) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// Every policy says where to report to, as it comes from the one helper every page goes
// through, and the report path is answered with nothing to read and no session to spend.
func TestEveryPolicySaysWhereToReport(t *testing.T) {
	f := newTokenFixture(t)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "report-uri "+cspReportPath) {
		t.Errorf("the sign-in page's policy reports nowhere: %s", csp)
	}
}
