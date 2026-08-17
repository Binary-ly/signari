package kerberos

import (
	"testing"
)

// Every case below is refused BEFORE the KDC is asked, and each would be an
// authentication bypass if it were not.
func TestPasswordVerifierRefusesWithoutAsking(t *testing.T) {
	v := PasswordVerifier{Realm: "EXAMPLE.COM", ConfPath: "/nonexistent/krb5.conf"}

	t.Run("an empty password", func(t *testing.T) {
		// Some KDC configurations accept an empty password as a pre-auth-less
		// bind, which produces an authenticated session for a password nobody
		// typed. Refused here rather than asked.
		if err := v.Verify(t.Context(), "alice", ""); err != ErrRefused {
			t.Errorf("an empty password produced %v, want a refusal", err)
		}
	})

	t.Run("an administrative principal", func(t *testing.T) {
		if err := v.Verify(t.Context(), "alice/admin", "pw"); err != ErrRefused {
			t.Errorf("alice/admin produced %v, want a refusal", err)
		}
	})

	t.Run("another realm", func(t *testing.T) {
		if err := v.Verify(t.Context(), "alice@PARTNER.EXAMPLE", "pw"); err != ErrRefused {
			t.Errorf("a foreign realm produced %v, want a refusal", err)
		}
	})
}

// A missing configuration is a configuration error, not a wrong password.
// Reporting it as a refusal sends people to reset passwords that are correct.
func TestMissingConfigIsNotARefusal(t *testing.T) {
	v := PasswordVerifier{Realm: "EXAMPLE.COM", ConfPath: "/nonexistent/krb5.conf"}
	err := v.Verify(t.Context(), "alice", "a-real-password")
	if err == nil {
		t.Fatal("a missing krb5.conf was accepted")
	}
	if err == ErrRefused {
		t.Error("a missing krb5.conf was reported as a wrong password, which sends " +
			"whoever hits it to reset a password that was correct")
	}
}

func TestNoRealmIsAnError(t *testing.T) {
	if err := (PasswordVerifier{}).Verify(t.Context(), "alice", "pw"); err == nil {
		t.Error("verification with no realm configured was accepted")
	}
}
