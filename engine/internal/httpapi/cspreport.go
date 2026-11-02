package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// cspReportPath is where a browser reports a page's policy refusing something (V3.4.7).
const cspReportPath = "/csp-report"

// maxCSPReport is more than a report comes to: it names a few URIs and a directive.
const maxCSPReport = 8 << 10

// handleCSPReport counts a policy violation by its directive, and that is all it does
// with what it is sent. An operator reading the counter climb learns that a page is
// being injected into, or that a theme of theirs is being refused.
//
// Nothing is logged or kept. A report carries `document-uri`, the page the browser was
// on, and on this server that can hold an authorization code, a reset token or an
// invitation, so the report of an attack would otherwise write those to a log. It takes
// no authentication, because a browser sends none, so what it counts is what anybody
// says: read a rise as a reason to look, and nothing here as a proof. That is also why
// it writes no row and takes no connection, leaving nothing for a stranger to fill.
func (s *Server) handleCSPReport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCSPReport))
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	if s.metrics != nil {
		s.metrics.CSPViolations.Inc(cspDirective(body))
	}
	w.WriteHeader(http.StatusNoContent)
}

// cspDirective reads a report's directive. Whatever it says goes to a label the metric
// holds to a closed set, so a stranger cannot mint a value there. Browsers name the
// finer directives, so `script-src-elem` counts as `script-src`.
func cspDirective(body []byte) string {
	var report struct {
		Report struct {
			Effective string `json:"effective-directive"`
			Violated  string `json:"violated-directive"`
		} `json:"csp-report"`
	}
	if json.Unmarshal(body, &report) != nil {
		return ""
	}
	directive := report.Report.Effective
	if directive == "" {
		directive = report.Report.Violated
	}
	return strings.TrimSuffix(strings.TrimSuffix(directive, "-elem"), "-attr")
}
