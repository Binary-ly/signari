package httpapi

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"signari.dev/engine/internal/oauth"
)

// amr must describe what the assertion ACTUALLY proved, because acr is derived
// from it. A wrong value here silently upgrades every session that used a
// passkey, and the upgrade is invisible -- the session simply starts satisfying
// MFA requirements it never met.
func TestPasskeyAMRIsHonest(t *testing.T) {
	for _, tc := range []struct {
		name           string
		backupEligible bool
		userVerified   bool
		wantAMR        []string
		wantACR        string
	}{
		// A tapped security key with no PIN or biometric proves possession only.
		// If this yielded acr=2, a tap would satisfy an MFA requirement.
		{"security key, presence only", false, false, []string{"user", "hwk"}, oauth.ACRSingleFactor},

		// The same key after a PIN or biometric: possession plus verification.
		{"security key, verified", false, true, []string{"user", "hwk", "mfa"}, oauth.ACRMultiFactor},

		// A synced passkey is software-backed and lives in a keychain across
		// devices; claiming hwk would overstate what the user physically holds.
		{"synced passkey, presence only", true, false, []string{"user", "swk"}, oauth.ACRSingleFactor},
		{"synced passkey, verified", true, true, []string{"user", "swk", "mfa"}, oauth.ACRMultiFactor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := amrForPasskey(&webauthn.Credential{
				Flags: webauthn.CredentialFlags{
					BackupEligible: tc.backupEligible,
					UserVerified:   tc.userVerified,
				},
			})
			if len(got) != len(tc.wantAMR) {
				t.Fatalf("amr = %v, want %v", got, tc.wantAMR)
			}
			for i := range got {
				if got[i] != tc.wantAMR[i] {
					t.Fatalf("amr = %v, want %v", got, tc.wantAMR)
				}
			}
			if acr := oauth.ACRFromAMR(got); acr != tc.wantACR {
				t.Errorf("acr = %q, want %q (from amr %v)", acr, tc.wantACR, got)
			}
		})
	}
}
