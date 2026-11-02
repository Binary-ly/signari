package httpapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A request's every log line carries its correlation id, and the id comes from the
// context (internal/logging), so a call without one is a line nobody can tie to the
// request that wrote it. The handler that adds it was built first; most calls went on
// not passing what it reads, and the ones that named the id by hand were the ones
// somebody had remembered. The LDAP listener's calls are not here: it has no HTTP
// request and no id to carry.
func TestNoHandlerLogsWithoutTheRequest(t *testing.T) {
	bare := regexp.MustCompile(`\b[sc]\.log\.(Info|Warn|Error|Debug)\(`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		checked += strings.Count(string(raw), "Context(")
		for _, m := range bare.FindAllStringIndex(string(raw), -1) {
			line := 1 + strings.Count(string(raw[:m[0]]), "\n")
			t.Errorf("%s:%d logs with no context, so the line carries no correlation id: use the …Context form",
				e.Name(), line)
		}
	}
	if checked < 800 {
		t.Fatalf("only %d context calls were found, so the scan is wrong", checked)
	}
}
