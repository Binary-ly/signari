package oauth

import (
	"testing"
	"time"
)

// THE bypass this file exists to prevent.
//
// A live password-only session must not satisfy a client's multi-factor
// requirement. Getting this wrong means a bank's "step up before a transfer"
// request is decorative: the session says "authenticated", nobody rechecks how,
// and the second factor is never actually demanded again.
func TestPasswordOnlySessionCannotSatisfyMultiFactor(t *testing.T) {
	now := time.Now()
	authTime := now.Add(-time.Minute)

	for _, requested := range []string{ACRMultiFactor, ACRPapeMultiFactor, "2 1"} {
		reason, _ := SessionSufficient([]string{AMRPassword}, authTime, now, requested, nil, "")
		if requested == "2 1" {
			// "2 1" offers a choice; the single-factor session satisfies "1", so
			// reuse is correct here.
			if reason != StepUpNone {
				t.Errorf("acr_values=%q: forced step-up despite offering an acceptable alternative", requested)
			}
			continue
		}
		if reason != StepUpNeedStronger {
			t.Errorf("acr_values=%q: a password-only session was ACCEPTED for MFA", requested)
		}
	}
}

func TestMultiFactorSessionIsReused(t *testing.T) {
	now := time.Now()
	amr := []string{AMRPassword, AMROTP}

	for _, requested := range []string{"", ACRSingleFactor, ACRMultiFactor, ACRPapeMultiFactor} {
		if reason, _ := SessionSufficient(amr, now.Add(-time.Minute), now, requested, nil, ""); reason != StepUpNone {
			t.Errorf("acr_values=%q: a genuine MFA session was forced to re-authenticate (%s)", requested, reason)
		}
	}
}

// acr is derived from what happened, never stored. Anything that could write it
// once -- a bug, a migration, an importer bringing users from another IdP --
// could otherwise assert multi-factor for a session that never had one.
func TestACRIsDerivedFromTheFactorsActuallyUsed(t *testing.T) {
	for _, tc := range []struct {
		amr  []string
		want string
	}{
		{[]string{AMRPassword}, ACRSingleFactor},
		{[]string{AMROTP}, ACRSingleFactor},
		{[]string{AMRPassword, AMROTP}, ACRMultiFactor},
		{[]string{AMRPassword, AMRHardwareKey}, ACRMultiFactor},
		{[]string{AMRPIN, AMRHardwareKey}, ACRMultiFactor},
		{nil, ACRSingleFactor},

		// Two factors of the SAME kind are one factor. A password plus a PIN is
		// two things you know, and calling that multi-factor is the mistake the
		// whole "independent factors" rule exists to prevent.
		{[]string{AMRPassword, AMRPIN}, ACRSingleFactor},

		// Presence alone proves someone touched a device, not which someone.
		{[]string{AMRUserPresence}, ACRSingleFactor},
		{[]string{AMRPassword, AMRUserPresence}, ACRSingleFactor},
	} {
		if got := ACRFromAMR(tc.amr); got != tc.want {
			t.Errorf("amr=%v: got acr %q, want %q", tc.amr, got, tc.want)
		}
	}
}

// max_age is measured from auth_time, not from session activity. A session kept
// alive by ordinary browsing is not freshly authenticated, and treating it as
// such defeats the parameter entirely.
func TestMaxAgeIsMeasuredFromAuthenticationNotActivity(t *testing.T) {
	now := time.Now()
	sixty := 60

	if reason, _ := SessionSufficient([]string{AMRPassword}, now.Add(-30*time.Second), now, "", &sixty, ""); reason != StepUpNone {
		t.Error("an authentication inside max_age was rejected")
	}
	if reason, _ := SessionSufficient([]string{AMRPassword}, now.Add(-2*time.Minute), now, "", &sixty, ""); reason != StepUpTooOld {
		t.Error("an authentication older than max_age was accepted")
	}

	// max_age=0 means "authenticate now", and a client sending it has a reason.
	zero := 0
	if reason, _ := SessionSufficient([]string{AMRPassword}, now.Add(-time.Second), now, "", &zero, ""); reason != StepUpTooOld {
		t.Error("max_age=0 did not force re-authentication")
	}

	// A session with no recorded auth_time cannot prove freshness, so it fails.
	if reason, _ := SessionSufficient([]string{AMRPassword}, time.Time{}, now, "", &sixty, ""); reason != StepUpTooOld {
		t.Error("a session with no auth_time satisfied max_age")
	}
}

func TestPromptLoginAlwaysForcesReauthentication(t *testing.T) {
	now := time.Now()
	strong := []string{AMRPassword, AMROTP}

	for _, prompt := range []string{"login", "select_account"} {
		if reason, _ := SessionSufficient(strong, now, now, "", nil, prompt); reason != StepUpForced {
			t.Errorf("prompt=%s did not force re-authentication", prompt)
		}
	}
	if reason, _ := SessionSufficient(strong, now, now, "", nil, "none"); reason != StepUpNone {
		t.Error("prompt=none forced re-authentication")
	}
}

// An acr we do not implement must be refused, not silently treated as met.
// Telling a client its requirement was satisfied when we cannot interpret it is
// the worst available answer.
func TestUnknownACRIsRefused(t *testing.T) {
	now := time.Now()
	amr := []string{AMRPassword, AMROTP}

	for _, requested := range []string{"urn:example:loa:4", "phr", "3"} {
		if reason, _ := SessionSufficient(amr, now, now, requested, nil, ""); reason != StepUpNeedStronger {
			t.Errorf("unrecognised acr_values=%q was treated as satisfied", requested)
		}
	}
}

func TestParseACRValuesPreservesPreferenceOrder(t *testing.T) {
	got := ParseACRValues("  2   1  ")
	if len(got) != 2 || got[0] != "2" || got[1] != "1" {
		t.Fatalf("got %v, want [2 1] in that order", got)
	}
	if ParseACRValues("   ") != nil {
		t.Error("blank acr_values should parse to nothing, not an empty string entry")
	}
}

func TestRequiredFactorNamesWhatIsMissing(t *testing.T) {
	if got := RequiredFactor(ACRMultiFactor); got != "mfa" {
		t.Errorf("got %q, want mfa", got)
	}
	if got := RequiredFactor(ACRPapeMultiFactor); got != "mfa" {
		t.Errorf("PAPE URN: got %q, want mfa", got)
	}
	if got := RequiredFactor(""); got != "" {
		t.Errorf("no acr_values should require nothing, got %q", got)
	}
}

// RFC 8707 resource indicators become the access token's AUDIENCE, so they are
// validated rather than trusted. The parameter exists to NARROW a token; it must
// not be usable to widen one by naming an audience the client has no claim to.
func TestResourceIndicatorValidation(t *testing.T) {
	for _, ok := range [][]string{
		nil,
		{"https://api.example.com"},
		{"https://api.example.com/billing", "https://api.example.com/admin"},
	} {
		if err := validateResources(ok); err != nil {
			t.Errorf("rejected a valid resource set %v: %v", ok, err)
		}
	}

	for _, bad := range [][]string{
		{"api.example.com"},              // not absolute
		{"/billing"},                     // relative
		{"https://api.example.com#frag"}, // fragment: cannot be compared reliably
		{"urn:example:api"},              // not reachable, nearly always a typo
		{"ftp://api.example.com"},        // ditto
		// An unbounded audience list inflates every token and is compared by
		// resource servers on every request.
		{"https://a", "https://b", "https://c", "https://d",
			"https://e", "https://f", "https://g", "https://h", "https://i"},
	} {
		if err := validateResources(bad); err == nil {
			t.Errorf("accepted an invalid resource set %v", bad)
		}
	}
}
