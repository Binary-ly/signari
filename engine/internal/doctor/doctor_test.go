package doctor

import (
	"os"
	"strings"
	"testing"
)

func findingsFor(t *testing.T, run func(*Report)) *Report {
	t.Helper()
	r := &Report{}
	run(r)
	return r
}

// TestPlaintextIssuerIsCriticalExceptLocally.
//
// An issuer over http means every token, code and client secret crosses the
// network readable. On localhost it is how everybody develops, and flagging it
// as critical there teaches people to ignore the checker.
func TestPlaintextIssuerIsCriticalExceptLocally(t *testing.T) {
	cases := map[string]Severity{
		"http://auth.example.com": Critical,
		"http://localhost:9411":   Info,
		"http://127.0.0.1:9411":   Info,
	}
	for issuer, want := range cases {
		r := findingsFor(t, func(r *Report) { checkIssuer(r, issuer) })
		if len(r.Findings) == 0 {
			t.Fatalf("%s produced no finding", issuer)
		}
		if r.Findings[0].Severity != want {
			t.Errorf("%s = %v, want %v", issuer, r.Findings[0].Severity, want)
		}
	}
}

func TestHTTPSIssuerIsClean(t *testing.T) {
	r := findingsFor(t, func(r *Report) { checkIssuer(r, "https://auth.example.com") })
	if len(r.Findings) != 0 {
		t.Errorf("a correct issuer produced findings: %+v", r.Findings)
	}
	if len(r.Checked) == 0 {
		t.Error("the check did not record that it ran; a clean report must be " +
			"distinguishable from one where nothing happened")
	}
}

// TestTrailingSlashIsFlagged. `iss` is compared exactly, and a trailing slash
// makes every token fail at relying parties that normalise.
func TestTrailingSlashIsFlagged(t *testing.T) {
	r := findingsFor(t, func(r *Report) { checkIssuer(r, "https://auth.example.com/") })
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Summary, "slash") {
			found = true
		}
	}
	if !found {
		t.Error("a trailing slash on the issuer was not flagged")
	}
}

func TestMissingRootKeyIsCritical(t *testing.T) {
	t.Setenv("SIGNARI_ROOT_KEY", "")
	t.Setenv("SIGNARI_ROOT_KEY_REF", "")
	r := findingsFor(t, checkRootKey)
	if r.Count(Critical) != 1 {
		t.Fatalf("findings = %+v, want one critical", r.Findings)
	}
}

func TestShortAdminTokenIsCritical(t *testing.T) {
	t.Setenv("SIGNARI_ADMIN_TOKEN", "short")
	r := findingsFor(t, checkAdminToken)
	if r.Count(Critical) != 1 {
		t.Fatalf("findings = %+v, want one critical", r.Findings)
	}
}

// TestNoAdminTokenIsNotAFinding. The admin API is off unless an address is
// given, and a deployment that does not run it needs no token. Flagging it
// would be noise on every default install.
func TestNoAdminTokenIsNotAFinding(t *testing.T) {
	t.Setenv("SIGNARI_ADMIN_TOKEN", "")
	r := findingsFor(t, checkAdminToken)
	if len(r.Findings) != 0 {
		t.Errorf("an absent admin token produced findings: %+v", r.Findings)
	}
}

func TestEveryFindingCarriesAFix(t *testing.T) {
	_ = os.Unsetenv("SIGNARI_ROOT_KEY")
	r := &Report{}
	checkIssuer(r, "http://auth.example.com/")
	checkRootKey(r)
	checkMail(r)

	if len(r.Findings) == 0 {
		t.Fatal("no findings to check")
	}
	for _, f := range r.Findings {
		if f.Severity == Info {
			continue
		}
		if strings.TrimSpace(f.Fix) == "" {
			t.Errorf("%q has no fix; a finding an operator cannot act on is one they "+
				"learn to ignore", f.Summary)
		}
		if strings.TrimSpace(f.Summary) == "" {
			t.Error("a finding with no summary")
		}
	}
}
