package kerberos

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
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

// A KDC that merely answers is not proof of anything: only the realm's holds this
// service's key, so a ticket has to open with it, and be for the person, and be current.
func TestOnlyTheRealmsKDCCanMakeATicketThatOpens(t *testing.T) {
	const spn, realm = "HTTP/auth.example.com", "EXAMPLE.COM"
	service := keytab.New()
	if err := service.AddEntry(spn, realm, "the-service-key", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	spoofed := keytab.New()
	if err := spoofed.AddEntry(spn, realm, "whatever-the-attacker-made-up", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sname, _ := types.ParseSPNString(spn)
	ticket := func(t *testing.T, kt *keytab.Keytab, who string, start, end time.Time) *messages.Ticket {
		t.Helper()
		cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, who)
		tkt, _, err := messages.NewTicket(cname, realm, sname, realm, asn1.BitString{Bytes: make([]byte, 4), BitLength: 32},
			kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1, start, start, end, end)
		if err != nil {
			t.Fatal(err)
		}
		return &tkt
	}
	if err := checkServiceTicket(ticket(t, service, "alice", now, now.Add(time.Hour)), service, spn, "alice", realm, now); err != nil {
		t.Fatalf("the realm's own ticket: %v", err)
	}
	for name, tkt := range map[string]*messages.Ticket{
		"made with a key the realm never had": ticket(t, spoofed, "alice", now, now.Add(time.Hour)),
		"for somebody else":                   ticket(t, service, "mallory", now, now.Add(time.Hour)),
		"long over":                           ticket(t, service, "alice", now.Add(-3*time.Hour), now.Add(-2*time.Hour)),
		"not begun":                           ticket(t, service, "alice", now.Add(time.Hour), now.Add(2*time.Hour)),
	} {
		err := checkServiceTicket(tkt, service, spn, "alice", realm, now)
		if !errors.Is(err, ErrKDCUnproven) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A KDC nobody can reach has said nothing about the password. This went unseen until a
// real KDC was stopped behind a real sign-in form, which told the person their password
// was wrong.
func TestAKDCThatIsNotThereIsNotAWrongPassword(t *testing.T) {
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := gone.Addr().String()
	if err := gone.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(conf, []byte(`[libdefaults]
 default_realm = EXAMPLE.COM
 dns_lookup_kdc = false
 udp_preference_limit = 1

[realms]
 EXAMPLE.COM = {
  kdc = `+addr+`
 }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	kt := keytab.New()
	if err := kt.AddEntry("HTTP/auth.example.com", "EXAMPLE.COM", "the-service-key", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "http.keytab")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	v := PasswordVerifier{Realm: "EXAMPLE.COM", ConfPath: conf, KeytabPath: path, ServicePrincipal: "HTTP/auth.example.com"}
	err = v.Verify(t.Context(), "alice", "a-real-password")
	if err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("a KDC that is not there answered %v", err)
	}
}

func TestAKDCsOwnNoIsARefusalWhateverItSays(t *testing.T) {
	for _, cause := range []string{krberror.KDCError, krberror.KRBMsgError, krberror.DecryptingError} {
		if err := loginFailure(krberror.New(cause, "no")); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", cause, err)
		}
	}
	for _, cause := range []string{krberror.NetworkingError, krberror.ConfigError} {
		if err := loginFailure(krberror.New(cause, "no")); errors.Is(err, ErrRefused) {
			t.Errorf("%s was called a wrong password", cause)
		}
	}
}

// With nothing to prove a KDC with, nothing is asked.
func TestAPasswordNeedsAKeytabToCheckAgainst(t *testing.T) {
	for _, v := range []PasswordVerifier{
		{Realm: "EXAMPLE.COM", ServicePrincipal: "HTTP/auth.example.com"},
		{Realm: "EXAMPLE.COM", KeytabPath: "/a/keytab"},
	} {
		err := v.Verify(t.Context(), "alice", "a-real-password")
		if err == nil || errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "keytab") {
			t.Errorf("%+v: %v", v, err)
		}
	}
}

// A missing configuration is a configuration error, not a wrong password.
// Reporting it as a refusal sends people to reset passwords that are correct.
func TestMissingConfigIsNotARefusal(t *testing.T) {
	v := PasswordVerifier{Realm: "EXAMPLE.COM", ConfPath: "/nonexistent/krb5.conf",
		KeytabPath: "/a/keytab", ServicePrincipal: "HTTP/auth.example.com"}
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
