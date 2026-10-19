package delegated

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"signari.dev/engine/internal/delegated/ldaptest"
	"signari.dev/engine/internal/safedial"
)

// A directory's answer is classified (2.01): a wrong password is ErrRejected,
// charged to the person; a directory that cannot be reached or trusted is
// ErrUnavailable, charged to nobody. Every error was bare, so the sign-in
// path counted an outage at the old directory against the user and told them
// their password was wrong.
func TestALDAPSourceSaysWhetherItAnsweredOrCouldNotBeAsked(t *testing.T) {
	ctx := context.Background()
	url, caPEM, binds, _ := ldaptest.Directory(t, `uid=alice,ou=people,dc=example`, "correct horse")
	src := Source{Kind: "ldap", TokenEndpoint: url, BindDNTemplate: "uid={username},ou=people,dc=example", CAPEM: caPEM}
	v := New()

	// Loopback is private, so it is reached only when the operator named it.
	if err := v.Verify(ctx, src, "alice", "correct horse"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a directory on an address nobody allowed: %v, want ErrUnavailable", err)
	}
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.AllowPrivate("") })

	if err := v.Verify(ctx, src, "alice", "correct horse"); err != nil {
		t.Fatalf("the right password was refused: %v", err)
	}
	if err := v.Verify(ctx, src, "alice", "wrong"); !errors.Is(err, ErrRejected) || errors.Is(err, ErrUnavailable) {
		t.Errorf("a wrong password: %v, want ErrRejected alone", err)
	}
	// The username is escaped into the template, so it cannot name another DN.
	if err := v.Verify(ctx, src, "alice,ou=people,dc=example", "correct horse"); !errors.Is(err, ErrRejected) {
		t.Errorf("a username carrying a DN: %v, want ErrRejected", err)
	}
	// RFC 4514 §2.4: the commas are escaped; `=` inside a value need not be.
	if seen := binds(); seen[len(seen)-1] != `uid=alice\,ou=people\,dc=example,ou=people,dc=example` {
		last := seen[len(seen)-1]
		t.Errorf("the directory was asked to bind %q", last)
	}

	// A directory whose certificate the source does not trust is not asked.
	// A CA of its own, not httptest's: that package serves one fixed
	// certificate, so a second server would be trusted by the first's PEM.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{Subject: pkix.Name{CommonName: "another CA"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := src
	untrusted.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := v.Verify(ctx, untrusted, "alice", "correct horse"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an untrusted certificate: %v, want ErrUnavailable", err)
	}
	// Nor one reached in the clear.
	plain := src
	plain.TokenEndpoint = "ldap://" + url[len("ldaps://"):]
	if err := v.Verify(ctx, plain, "alice", "correct horse"); !errors.Is(err, ErrUnavailable) ||
		!errors.Is(err, ErrInsecureTransport) {
		t.Errorf("plaintext ldap://: %v, want ErrUnavailable and ErrInsecureTransport", err)
	}
}
