package kerberos

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The check that this is not gokrb5 agreeing with itself: MIT's own KDC, and a second
// one standing where the first was, under the same realm's name, that says yes to a
// password of an attacker's choosing. Skipped where MIT Kerberos is not installed.

// kdcTool finds a server-side tool beside MIT's krb5kdc, which is not on a Mac's PATH
// and which a Mac's own Heimdal tools of the same names do not take the place of.
func kdcTool(t *testing.T, name string) string {
	t.Helper()
	kdc := "/opt/homebrew/opt/krb5/sbin/krb5kdc"
	if _, err := os.Stat(kdc); err != nil {
		if kdc, err = exec.LookPath("krb5kdc"); err != nil {
			t.Skip("MIT Kerberos is not installed; a real KDC is the independent check")
		}
	}
	return filepath.Join(filepath.Dir(kdc), name)
}

type realKDC struct {
	conf string
	stop func()
}

// startKDC makes a realm with a person and this service in it, and runs it.
func startKDC(t *testing.T, realm, person, password string) *realKDC {
	t.Helper()
	dir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "krb5.conf")
	profile := filepath.Join(dir, "kdc.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, `[libdefaults]
 default_realm = %[1]s
 dns_lookup_realm = false
 dns_lookup_kdc = false
 udp_preference_limit = 1
 default_tkt_enctypes = aes256-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96

[realms]
 %[1]s = {
  kdc = %[2]s
 }
`, realm, addr), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, fmt.Appendf(nil, `[kdcdefaults]
 kdc_listen = %[2]s
 kdc_tcp_listen = %[2]s

[realms]
 %[1]s = {
  database_name = %[3]s/principal
  key_stash_file = %[3]s/stash
  acl_file = %[3]s/kadm5.acl
  supported_enctypes = aes256-cts-hmac-sha1-96:normal
 }
`, realm, addr, dir), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kadm5.acl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "KRB5_CONFIG="+conf, "KRB5_KDC_PROFILE="+profile)
	run := func(tool string, args ...string) {
		t.Helper()
		cmd := exec.Command(kdcTool(t, tool), args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", tool, args, err, out)
		}
	}
	run("kdb5_util", "-r", realm, "create", "-s", "-P", "a-master-key-for-a-test")
	run("kadmin.local", "-r", realm, "-q", "addprinc -randkey HTTP/auth.example.test")
	run("kadmin.local", "-r", realm, "-q", "addprinc -pw "+password+" "+person)
	run("kadmin.local", "-r", realm, "-q", "ktadd -k "+filepath.Join(dir, "http.keytab")+
		" -e aes256-cts-hmac-sha1-96:normal HTTP/auth.example.test")

	kdc := exec.Command(kdcTool(t, "krb5kdc"), "-n", "-P", filepath.Join(dir, "pid"))
	kdc.Env = env
	if err := kdc.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = kdc.Process.Kill()
			_ = kdc.Wait()
		}
	}
	t.Cleanup(stop)
	for range 100 {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return &realKDC{conf: conf, stop: stop}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the KDC did not come up")
	return nil
}

func TestAPasswordIsCheckedAgainstARealKDCAndNotAnImpostor(t *testing.T) {
	const realm, spn = "EXAMPLE.TEST", "HTTP/auth.example.test"
	const password, attackers = "the-password-the-realm-knows", "a-password-of-the-attackers-choosing"
	real := startKDC(t, realm, "alice", password)
	impostor := startKDC(t, realm, "alice", attackers)

	keytabOf := func(k *realKDC) string { return filepath.Join(filepath.Dir(k.conf), "http.keytab") }
	v := PasswordVerifier{Realm: realm, ConfPath: real.conf, KeytabPath: keytabOf(real), ServicePrincipal: spn}

	if err := v.Verify(t.Context(), "alice", password); err != nil {
		t.Fatalf("the realm's own password: %v", err)
	}
	if err := v.Verify(t.Context(), "alice@"+realm, password); err != nil {
		t.Errorf("the same, with the realm named: %v", err)
	}
	if err := v.Verify(t.Context(), "alice", "not-the-password"); !errors.Is(err, ErrRefused) {
		t.Errorf("the wrong password: %v", err)
	}
	if err := v.Verify(t.Context(), "mallory", password); !errors.Is(err, ErrRefused) {
		t.Errorf("nobody the realm knows: %v", err)
	}

	// The whole point: the attacker's KDC answers, its password works, and it cannot
	// make a ticket this service's key opens.
	fooled := v
	fooled.ConfPath = impostor.conf
	if err := fooled.Verify(t.Context(), "alice", attackers); !errors.Is(err, ErrKDCUnproven) {
		t.Errorf("a KDC that does not hold this service's key: %v", err)
	}

	// With the wrong keytab it is the same to the real one, and a person is not told
	// their password is wrong for a mistake of the operator's.
	stale := v
	stale.KeytabPath = keytabOf(impostor)
	if err := stale.Verify(t.Context(), "alice", password); !errors.Is(err, ErrKDCUnproven) {
		t.Errorf("a keytab from elsewhere: %v", err)
	}

	real.stop()
	if err := v.Verify(t.Context(), "alice", password); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("a KDC that has gone: %v", err)
	}
}
