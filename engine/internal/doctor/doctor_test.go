package doctor

import (
	"fmt"
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

// A deployment holding subject keys is told how to erase one, and what that costs.
//
// This test used to assert the opposite. `keys.EraseSubject` was implemented,
// tested, and called by nothing — a mechanism with no handle, in a schema that
// advertised erasure support everywhere: `erased_at`, a constraint that a shredded
// key holds no DEK, an audit chain hashed over ciphertext specifically so it
// survives a shred.
//
// The finding stayed Info and the check stayed, because the NUMBER is still worth
// reporting: it says how much of this deployment is protected by subject keys and
// therefore how much a single erasure destroys. What changed is the advice, which
// now has to name a command that exists rather than a decision that was pending.
func TestADeploymentIsToldHowToErase(t *testing.T) {
	r := findingsFor(t, func(r *Report) { reportErasure(r, 42) })
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Severity != Info {
		t.Errorf("severity = %v, want Info: this reports scale, not a fault", f.Severity)
	}
	// The command, so the advice is actionable rather than a description.
	if !strings.Contains(f.Fix, "erase subject") {
		t.Errorf("the fix does not name the command that does it: %q", f.Fix)
	}
	// And the confirmation, because an operator who learns the command without
	// learning that it is irreversible has been told the dangerous half only.
	if !strings.Contains(f.Fix, "confirm") {
		t.Errorf("the fix does not mention the confirmation: %q", f.Fix)
	}
	if !strings.Contains(f.Fix, "permanent") {
		t.Errorf("the fix does not say the destruction is permanent: %q", f.Fix)
	}
}

// And a deployment storing nothing must not be nagged.
func TestNoSubjectKeysMeansNoErasureFinding(t *testing.T) {
	r := findingsFor(t, func(r *Report) { reportErasure(r, 0) })
	if len(r.Findings) != 0 {
		t.Errorf("a deployment with no subject keys was told it cannot erase them: %v",
			r.Findings)
	}
}

// A credential outliving the key that signed it is a failure nobody present can
// observe: it verifies today, and stops verifying weeks later at a verifier the
// operator does not run.
//
// `keys.MinPassiveBeforeRetire` is 24 hours and its comment says the value "must
// exceed the longest lifetime of any token it signed" — true when written, and
// untrue since OID4VCI, whose credential lifetime is an operator-configured
// interval with no ceiling and is signed by the same key.
//
// Retirement now exists and computes its dwell from these lifetimes rather than
// from the constant, so the failure cannot occur. The finding stayed because it
// changed meaning: these configurations are why a passive key remains published
// for weeks, and the operator looking at one should be told which.
func TestCredentialsOutlivingTheKeyWindowAreReported(t *testing.T) {
	r := findingsFor(t, func(r *Report) {
		reportCredentialLifetimes(r, []string{"IdentityCredential (720h0m0s)"})
	})
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Severity != Info {
		t.Errorf("severity = %v, want Info: the dwell already accounts for these "+
			"lifetimes, so nothing fails", f.Severity)
	}
	if !strings.Contains(f.Summary, "IdentityCredential") {
		t.Errorf("the finding does not name the configuration: %q", f.Summary)
	}
	if !strings.Contains(f.Fix, "keys retire") {
		t.Errorf("the fix does not point at the command that explains the dwell: %q", f.Fix)
	}
}

// A deployment issuing only short-lived credentials, or none, must not be told
// about a hazard it does not have.
func TestShortCredentialsProduceNoKeyWindowFinding(t *testing.T) {
	r := findingsFor(t, func(r *Report) { reportCredentialLifetimes(r, nil) })
	if len(r.Findings) != 0 {
		t.Errorf("a deployment with no long-lived credentials was warned: %v", r.Findings)
	}
}

// A list that is cut short without saying so reads as the complete answer. An
// operator who sees five names and fixes five configurations, when there were
// forty, has been told something false by omission.
func TestALongListSaysHowMuchItLeftOut(t *testing.T) {
	var many []string
	for i := 0; i < 12; i++ {
		many = append(many, fmt.Sprintf("cred-%d (2160h0m0s)", i))
	}
	r := findingsFor(t, func(r *Report) { reportCredentialLifetimes(r, many) })
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(r.Findings))
	}
	s := r.Findings[0].Summary
	if !strings.Contains(s, "12 credential") {
		t.Errorf("the true total is not stated: %q", s)
	}
	if !strings.Contains(s, "7 more") {
		t.Errorf("the list was truncated without saying by how much: %q", s)
	}
}
