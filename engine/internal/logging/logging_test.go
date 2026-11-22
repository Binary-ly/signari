package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// The format and level are what the environment asks for, and a value the
// logger does not know refuses to start (3.07).
func TestTheLoggerIsWhatTheEnvironmentAsksFor(t *testing.T) {
	var out bytes.Buffer
	log, err := New(&out, env(map[string]string{"SIGNARI_LOG_FORMAT": "json", "SIGNARI_LOG_LEVEL": "warn"}))
	if err != nil {
		t.Fatal(err)
	}
	log.Info("below the level")
	log.Warn("at the level", "n", 1)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("at warn, %d lines were written: %q", len(lines), out.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil || rec["msg"] != "at the level" {
		t.Errorf("SIGNARI_LOG_FORMAT=json wrote %q (%v)", lines[0], err)
	}

	out.Reset()
	log, err = New(&out, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("below the default")
	log.Info("plain")
	if got := out.String(); !strings.Contains(got, "msg=plain") || strings.Contains(got, "below the default") {
		t.Errorf("the default logger wrote %q, want logfmt at info", got)
	}

	for _, bad := range []map[string]string{
		{"SIGNARI_LOG_FORMAT": "xml"}, {"SIGNARI_LOG_LEVEL": "loud"}, {"SIGNARI_LOG_LEVEL": "inf"},
	} {
		if _, err := New(&out, env(bad)); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

// A line logged with a request's context names the request, once, whether
// the call site remembered to or not, through a logger derived with With.
func TestALineLoggedWithARequestsContextNamesIt(t *testing.T) {
	var out bytes.Buffer
	log, err := New(&out, env(map[string]string{"SIGNARI_LOG_FORMAT": "json"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithCorrelation(context.Background(), "c0ffee00-0000-4000-8000-000000000001")
	log.With("component", "test").InfoContext(ctx, "forgot")
	log.InfoContext(ctx, "remembered", "correlation_id", "c0ffee00-0000-4000-8000-000000000001")
	log.Info("outside a request")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines: %q", len(lines), out.String())
	}
	for i, want := range []int{1, 1, 0} {
		if n := strings.Count(lines[i], `"correlation_id"`); n != want {
			t.Errorf("line %d carries correlation_id %d times, want %d: %s", i, n, want, lines[i])
		}
	}
	if !strings.Contains(lines[0], `"component":"test"`) {
		t.Errorf("a logger derived with With lost its attributes: %s", lines[0])
	}
}
