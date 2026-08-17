package kerberos

import (
	"os"
	"strings"
	"testing"
)

// The principal mapping is where a Kerberos integration is made safe or unsafe.
//
// Every case below that is REFUSED would be an authentication bypass if it were
// accepted, and each is a mapping a permissive implementation makes by default.
func TestPrincipalMapping(t *testing.T) {
	cfg := Config{Realm: "EXAMPLE.COM"}

	t.Run("an ordinary principal maps to an address", func(t *testing.T) {
		got, err := cfg.UsernameFor("alice@EXAMPLE.COM")
		if err != nil {
			t.Fatal(err)
		}
		// The realm is upper case by convention and email addresses are not.
		if got != "alice@example.com" {
			t.Errorf("got %q, want alice@example.com", got)
		}
	})

	t.Run("strip-realm mode", func(t *testing.T) {
		c := Config{Realm: "EXAMPLE.COM", StripRealm: true}
		got, err := c.UsernameFor("alice@EXAMPLE.COM")
		if err != nil || got != "alice" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("a foreign realm is refused", func(t *testing.T) {
		// The bypass: a KDC with a trust will happily issue tickets for another
		// realm, and accepting them makes every principal in the trusted forest
		// a user here.
		_, err := cfg.UsernameFor("alice@PARTNER.EXAMPLE")
		if err == nil {
			t.Fatal("a principal from another realm was accepted")
		}
		if !strings.Contains(err.Error(), "realm") {
			t.Errorf("the error should name the realm: %v", err)
		}
	})

	t.Run("an instance component is refused", func(t *testing.T) {
		// alice/admin is an administrative principal, not the person alice.
		// Mapping it to "alice" hands her account to whoever holds it.
		_, err := cfg.UsernameFor("alice/admin@EXAMPLE.COM")
		if err == nil {
			t.Fatal("an administrative principal was mapped to a user")
		}
	})

	t.Run("a service principal is refused", func(t *testing.T) {
		_, err := cfg.UsernameFor("HTTP/auth.example.com@EXAMPLE.COM")
		if err == nil {
			t.Fatal("a service principal was mapped to a user")
		}
	})

	t.Run("no realm is refused", func(t *testing.T) {
		_, err := cfg.UsernameFor("alice")
		if err == nil {
			t.Fatal("a principal with no realm was accepted")
		}
	})

	t.Run("realm comparison is case-insensitive", func(t *testing.T) {
		if _, err := cfg.UsernameFor("alice@example.com"); err != nil {
			t.Errorf("a lower-case realm should still match: %v", err)
		}
	})
}

// TestWeakEncryptionTypesAreNamed: a KDC reports a mismatch as an integer, and
// the integer is the whole error. Naming them is the difference between a
// five-minute fix and an afternoon.
func TestWeakEncryptionTypesAreNamed(t *testing.T) {
	if !Weak(23) {
		t.Error("rc4-hmac should be reported as weak; current KDCs disable it")
	}
	if Weak(18) {
		t.Error("aes256-cts-hmac-sha1-96 is not weak")
	}
	if !strings.Contains(EncTypeName(23), "WEAK") {
		t.Errorf("rc4 should be labelled: %q", EncTypeName(23))
	}
	if !strings.Contains(EncTypeName(18), "aes256") {
		t.Errorf("enctype 18 should be named: %q", EncTypeName(18))
	}
}

// A file that is not a keytab is the commonest setup mistake: people export a
// krb5.conf, or a certificate, and the error must say which file is wrong.
func TestNonKeytabIsRefusedClearly(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/not-a-keytab"
	if err := writeFile(path, "[libdefaults]\n  default_realm = EXAMPLE.COM\n"); err != nil {
		t.Fatal(err)
	}
	_, err := Config{KeytabPath: path}.Keytab()
	if err == nil {
		t.Fatal("a krb5.conf was accepted as a keytab")
	}
	if !strings.Contains(err.Error(), "ktpass") && !strings.Contains(err.Error(), "keytab") {
		t.Errorf("the error should say how to produce a real keytab: %v", err)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
