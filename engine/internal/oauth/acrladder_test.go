package oauth

import (
	"testing"
	"time"
)

// The two rungs above multi-factor (4.15): "3" multi-factor including a
// WebAuthn assertion, "4" the same with a device-bound key. A session records
// "1" or "2" still, so what a relying party was told for a passkey sign-in
// does not change unless it asks for more.
func TestTheLadderReadsTheFactorsUsed(t *testing.T) {
	for _, c := range []struct {
		name      string
		amr       []string
		assurance string
		recorded  string
	}{
		{"a password", []string{"pwd"}, "1", "1"},
		{"a passkey tapped, no verification", []string{"user", "swk"}, "1", "1"},
		{"password and an app", []string{"pwd", "otp", "mfa"}, "2", "2"},
		{"password and a text", []string{"pwd", "sms", "mfa"}, "2", "2"},
		{"a federated sign-in trusted as MFA", []string{"fed", "mfa"}, "2", "2"},
		{"a synced passkey that verified", []string{"user", "swk", "mfa"}, "3", "2"},
		{"a device-bound key that verified", []string{"user", "hwk", "mfa"}, "4", "2"},
		{"password and a security key", []string{"pwd", "user", "hwk", "mfa"}, "4", "2"},
	} {
		if got := Assurance(c.amr); got != c.assurance {
			t.Errorf("%s: Assurance %s, want %s", c.name, got, c.assurance)
		}
		if got := ACRFromAMR(c.amr); got != c.recorded {
			t.Errorf("%s: ACRFromAMR %s, want %s", c.name, got, c.recorded)
		}
	}
}

func TestAHigherRungMeetsALowerAndNoOtherWay(t *testing.T) {
	synced := []string{"user", "swk", "mfa"}
	bound := []string{"user", "hwk", "mfa"}
	app := []string{"pwd", "otp", "mfa"}
	for _, c := range []struct {
		amr   []string
		floor string
		meets bool
	}{
		{app, "", true}, {app, "1", true}, {app, "2", true}, {app, "3", false}, {app, "4", false},
		{synced, "2", true}, {synced, "3", true}, {synced, "4", false},
		{bound, "3", true}, {bound, "4", true},
		{bound, "5", false}, {bound, "silver", false},
	} {
		if got := Meets(c.amr, c.floor); got != c.meets {
			t.Errorf("Meets(%v, %q) = %v, want %v", c.amr, c.floor, got, c.meets)
		}
	}
	// acr_values at the authorization endpoint, through the same rungs.
	now := time.Now()
	for _, c := range []struct {
		amr    []string
		values string
		ok     bool
	}{
		{app, "3", false}, {app, "3 2", true}, {synced, "3", true}, {synced, "4", false},
		{bound, "4", true}, {bound, ACRPapeMultiFactor, true},
	} {
		reason, _ := SessionSufficient(c.amr, now, now, c.values, nil, "")
		if (reason == StepUpNone) != c.ok {
			t.Errorf("acr_values %q for %v: %q", c.values, c.amr, reason)
		}
	}
}

// What an ID token reports: the rung the request asked for and got, only when
// it is above the session's own; and what a request needs, the lowest of what
// it accepts or the client's floor.
func TestWhatIsReportedAndWhatIsRequired(t *testing.T) {
	bound := []string{"user", "hwk", "mfa"}
	for _, c := range []struct {
		amr    []string
		values string
		want   string
	}{
		{bound, "4", "4"}, {bound, "3", "3"}, {bound, "4 3", "4"}, {bound, "2", ""}, {bound, "", ""},
		{[]string{"user", "swk", "mfa"}, "4 3", "3"}, {[]string{"pwd", "otp", "mfa"}, "3", ""},
	} {
		if got := SatisfiedACR(c.amr, c.values); got != c.want {
			t.Errorf("SatisfiedACR(%v, %q) = %q, want %q", c.amr, c.values, got, c.want)
		}
	}
	for _, c := range []struct {
		values, floor string
		want          int
	}{
		{"", "", 0}, {"3", "", 3}, {"4 2", "", 2}, {"2", "3", 3}, {"", "4", 4}, {"silver", "", 0},
	} {
		if got := RequiredRung(c.values, c.floor); got != c.want {
			t.Errorf("RequiredRung(%q, %q) = %d, want %d", c.values, c.floor, got, c.want)
		}
	}
	if RequiredFactor("3") != "passkey" || RequiredFactor("4 2") != "passkey" || RequiredFactor("2") != "mfa" {
		t.Error("RequiredFactor does not name the passkey for the upper rungs")
	}
}
