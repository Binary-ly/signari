package mail

import (
	"context"
	"os"
	"testing"
	"time"
)

// Run against real DNS. Skipped without SIGNARI_DNS_CHECK because a test that
// needs the network must not fail a build on a train.
func TestPreflightAgainstRealDNS(t *testing.T) {
	if os.Getenv("SIGNARI_DNS_CHECK") == "" {
		t.Skip("SIGNARI_DNS_CHECK not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, tc := range []struct {
		addr, selector string
	}{
		{"noreply@github.com", "s1"},
		{"noreply@" + os.Getenv("SIGNARI_DNS_DOMAIN"), ""},
	} {
		if tc.addr == "noreply@" {
			continue
		}
		rep := Preflight(ctx, tc.addr, tc.selector)
		t.Logf("--- %s (deliverable=%v)", rep.Domain, rep.Deliverable())
		for _, f := range rep.Findings {
			t.Logf("    %-6s %-6s %s", f.Check, f.Severity, truncate(f.Detail, 90))
			if f.Fix != "" {
				t.Logf("           fix: %s", truncate(f.Fix, 90))
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
