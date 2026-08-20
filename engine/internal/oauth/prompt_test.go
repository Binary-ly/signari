package oauth

import (
	"testing"
	"time"
)

// OIDC Core §3.1.2.1: prompt is a "Space delimited, case sensitive list".
//
// Every consumer in this server used `==` against a single value, which is right
// for a one-value request and silently wrong for every combination.
func TestPromptIsASpaceDelimitedList(t *testing.T) {
	for _, tc := range []struct {
		prompt, want string
		has          bool
	}{
		{"none", PromptNone, true},
		{"login", PromptLogin, true},
		{"consent", PromptConsent, true},

		// The combination that matters. A relying party sends this before a
		// high-value operation: re-authenticate AND re-consent.
		{"login consent", PromptLogin, true},
		{"login consent", PromptConsent, true},
		{"consent login", PromptLogin, true},
		{"select_account consent", PromptSelectAccount, true},

		// Extra whitespace is still a list.
		{"  login   consent  ", PromptConsent, true},

		// Case sensitive, per the same sentence.
		{"Login", PromptLogin, false},
		{"CONSENT", PromptConsent, false},

		// A value must match whole, not as a substring — "logins" is not "login",
		// and a prefix match would let an unknown value satisfy a known one.
		{"logins", PromptLogin, false},
		{"consentx", PromptConsent, false},

		{"", PromptNone, false},
		{"consent", PromptLogin, false},
	} {
		if got := HasPrompt(tc.prompt, tc.want); got != tc.has {
			t.Errorf("HasPrompt(%q, %q) = %v, want %v", tc.prompt, tc.want, got, tc.has)
		}
	}
}

// §3.1.2.1: "If this parameter contains none with any other value, an error is
// returned."
//
// The combination is self-contradictory — none promises the user will not be
// interrupted, every other value demands an interruption — so an implementation
// that silently drops one half picks a winner the client did not choose.
func TestPromptNoneCannotBeCombined(t *testing.T) {
	for _, bad := range []string{
		"none login", "login none", "none consent", "none select_account",
		"none login consent",
	} {
		if err := ValidatePrompt(bad); err == nil {
			t.Errorf("prompt %q was accepted; §3.1.2.1 requires an error", bad)
		}
	}
	for _, ok := range []string{
		"", "none", "login", "consent", "login consent",
		"select_account consent", "login consent select_account",
	} {
		if err := ValidatePrompt(ok); err != nil {
			t.Errorf("prompt %q was refused: %v", ok, err)
		}
	}
}

// The defect this fixes, expressed against the function that decides step-up.
//
// A relying party sending "login consent" is asking for re-authentication. Under
// the old exact comparison it matched neither branch, so the session was treated
// as sufficient and the user was not re-authenticated — while the relying party,
// receiving an ID token, had no way to tell.
func TestPromptLoginForcesStepUpEvenBesideOtherValues(t *testing.T) {
	fresh := time.Now().Add(-time.Minute)
	now := time.Now()

	for _, prompt := range []string{
		"login",
		"login consent",
		"consent login",
		"select_account consent",
	} {
		reason, _ := SessionSufficient([]string{"pwd"}, fresh, now, "", nil, prompt)
		if reason == StepUpNone {
			t.Errorf("prompt %q did not force re-authentication; a relying party "+
				"gating a sensitive action on it would believe the session had "+
				"just been re-verified", prompt)
		}
	}

	// The control: a prompt that does not ask for re-authentication must not
	// force it, or every consent request becomes a login.
	if reason, _ := SessionSufficient([]string{"pwd"}, fresh, now, "", nil, "consent"); reason != StepUpNone {
		t.Errorf("prompt=consent forced re-authentication (%v); it asks for "+
			"consent, not for a new authentication", reason)
	}
}
