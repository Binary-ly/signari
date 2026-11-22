package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// `credential trust-root` is the writer the x5c proof check never had (2.07):
// one CA certificate, no key, registered, listed and withdrawn by name.
func TestCredentialTrustRootRegistersOnlyACertificateAuthority(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) }) // after the deletes below
	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	name := fmt.Sprintf("root-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.credential_proof_roots
			WHERE org_id = $1::uuid AND name = $2`, org, name)
	})

	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := func(isCA bool) []byte {
		t.Helper()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wallet provider"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: isCA, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	file := func(n string, blocks ...[]byte) string {
		t.Helper()
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, bytes.Join(blocks, nil), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	trust := func(path string) error {
		return run([]string{"credential", "trust-root", "-dsn", dsn, "-org", org, "-name", name, "-root-cert", path})
	}
	stored := func() int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM core.credential_proof_roots
			WHERE org_id = $1::uuid AND name = $2`, org, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	withKey := file("with-key.pem", cert(true), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	for path, why := range map[string]string{
		withKey:                                 "private key",
		file("two.pem", cert(true), cert(true)): "more than one certificate",
		file("leaf.pem", cert(false)):           "not a CA",
		file("empty.pem"):                       "no PEM certificate",
	} {
		if err := trust(path); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: gave %v, want a refusal naming %q", filepath.Base(path), err, why)
		}
	}
	if stored() != 0 {
		t.Fatal("a refused root was stored")
	}

	if err := trust(file("ca.pem", cert(true))); err != nil {
		t.Fatalf("a CA certificate was refused: %v", err)
	}
	if stored() != 1 {
		t.Fatal("the CA was not stored")
	}
	if err := run([]string{"credential", "roots", "-dsn", dsn}); err != nil {
		t.Errorf("credential roots: %v", err)
	}
	if err := run([]string{"credential", "untrust-root", "-dsn", dsn, "-org", org, "-name", name}); err != nil {
		t.Fatalf("credential untrust-root: %v", err)
	}
	if stored() != 0 {
		t.Error("the withdrawn root is still stored")
	}
	if err := run([]string{"credential", "untrust-root", "-dsn", dsn, "-org", org, "-name", name}); err == nil {
		t.Error("withdrawing a root that is not there succeeded")
	}
}
