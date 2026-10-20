package docsync

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// registration finds a metric's name where the engine declares it, whichever
// constructor declares it.
var registration = regexp.MustCompile(`\.New(Counter|CounterFunc|Gauge|Histogram|HistogramVec|Info)\(\s*"([a-zA-Z_:][a-zA-Z0-9_:]*)"`)

// seriesName is a name an expression uses, once quoted label values are gone.
// Every series the engine exports starts with one of these.
var seriesName = regexp.MustCompile(`\b(?:signari|go|process)_[a-zA-Z0-9_]+\b`)

var quoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// labelLists are the parts of an expression that hold label names, not series:
// a selector's matchers and the grouping clauses. `go_version` is a label.
var labelLists = regexp.MustCompile(`\{[^}]*\}|\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)`)

// exportedSeries is every series name the engine's non-test code declares,
// with a histogram's three suffixed series.
func exportedSeries(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(repoRoot(t), "engine"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range registration.FindAllStringSubmatch(string(body), -1) {
			out[m[2]] = true
			if strings.HasPrefix(m[1], "Histogram") {
				for _, s := range []string{"_bucket", "_sum", "_count"} {
					out[m[2]+s] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 20 {
		t.Fatalf("found only %d metric registrations; the pattern no longer matches how the engine declares them", len(out))
	}
	return out
}

// exprsIn collects every "expr" string anywhere in a decoded JSON document.
func exprsIn(v any, out *[]string) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if s, ok := x.(string); ok && k == "expr" {
				*out = append(*out, s)
			} else {
				exprsIn(x, out)
			}
		}
	case []any:
		for _, x := range v {
			exprsIn(x, out)
		}
	}
}

// The alert rules and the dashboard name only series the engine exports, and
// every alert says how bad it is, what it means and where to read more, on a
// page a reader can open (3.27). A renamed series otherwise leaves an alert
// that can never fire and a panel that reads "No data", and neither says so.
func TestTheMonitoringNamesOnlyExportedSeries(t *testing.T) {
	root := repoRoot(t)
	exported := exportedSeries(t)
	dir := filepath.Join(root, "deploy", "monitoring")

	var rules struct {
		Groups []struct {
			Name  string
			Rules []struct {
				Alert       string
				Expr        string
				Labels      map[string]string
				Annotations map[string]string
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("alerts.yaml: %v", err)
	}
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Skipf("cannot ask git what is tracked: %v", err)
	}
	tracked := map[string]bool{}
	for _, f := range strings.Split(string(out), "\n") {
		tracked[f] = true
	}

	type use struct{ where, expr string }
	var uses []use
	seen := map[string]bool{}
	const repo = "https://github.com/binary-ly/signari/blob/main/"
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			if r.Alert == "" {
				t.Errorf("group %s has a rule with no alert name", g.Name)
				continue
			}
			if seen[r.Alert] {
				t.Errorf("%s is defined twice", r.Alert)
			}
			seen[r.Alert] = true
			uses = append(uses, use{r.Alert, r.Expr})
			if s := r.Labels["severity"]; s != "critical" && s != "warning" {
				t.Errorf("%s: severity %q, want critical or warning", r.Alert, s)
			}
			for _, a := range []string{"summary", "description", "runbook_url"} {
				if strings.TrimSpace(r.Annotations[a]) == "" {
					t.Errorf("%s has no %s", r.Alert, a)
				}
			}
			page, ok := strings.CutPrefix(r.Annotations["runbook_url"], repo)
			page, _, _ = strings.Cut(page, "#")
			if !ok || !tracked[page] {
				t.Errorf("%s: runbook %q is not a published page of this repository", r.Alert, r.Annotations["runbook_url"])
			}
		}
	}
	if len(seen) < 10 {
		t.Fatalf("alerts.yaml decoded to %d alerts; the file or its shape changed", len(seen))
	}

	raw, err = os.ReadFile(filepath.Join(dir, "dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var dash any
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard.json: %v", err)
	}
	var exprs []string
	exprsIn(dash, &exprs)
	if len(exprs) < 10 {
		t.Fatalf("dashboard.json has %d queries; the file or its shape changed", len(exprs))
	}
	for _, e := range exprs {
		uses = append(uses, use{"dashboard", e})
	}

	for _, u := range uses {
		names := seriesName.FindAllString(labelLists.ReplaceAllString(quoted.ReplaceAllString(u.expr, `""`), " "), -1)
		if len(names) == 0 {
			t.Errorf("%s: %q names no series the engine could export", u.where, u.expr)
		}
		for _, n := range names {
			if !exported[n] {
				t.Errorf("%s: %s is not a series the engine exports", u.where, n)
			}
		}
	}
}
