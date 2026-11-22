package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testAuthority is a certificate authority that can sign a client.
type testAuthority struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthority{cert: cert, der: der, key: key}
}

func (a *testAuthority) client(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "console"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, key.Public(), a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (a *testAuthority) file(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Over a real TLS handshake, as a rule the handshake enforces can only be proved by one.
// Nobody reaches the handler without a certificate the authority signed, whatever
// token they hold, and the refusal comes before a request is read.
func TestTheAdminListenerAsksForTheAuthoritysCertificate(t *testing.T) {
	ours, theirs := newTestAuthority(t), newTestAuthority(t)
	config, err := adminClientAuth(ours.file(t), "server.pem")
	if err != nil {
		t.Fatal(err)
	}
	var reached int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }))
	srv.TLS = config
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ask := func(presented ...tls.Certificate) error {
		t.Helper()
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: presented, MinVersion: tls.VersionTLS12}}}
		resp, err := c.Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := ask(); err == nil {
		t.Error("a caller with no certificate was let in")
	}
	if err := ask(theirs.client(t)); err == nil {
		t.Error("a certificate from another authority was let in")
	}
	if reached != 0 {
		t.Fatalf("%d requests reached the handler with no good certificate", reached)
	}
	if err := ask(ours.client(t)); err != nil {
		t.Errorf("the authority's own certificate was refused: %v", err)
	}
	if reached != 1 {
		t.Errorf("%d requests reached the handler, want the one", reached)
	}
}

// Set where it can do nothing is refused at startup, and unset asks for nothing.
func TestAClientAuthoritySetWhereItCannotWorkIsRefused(t *testing.T) {
	if config, err := adminClientAuth("", ""); config != nil || err != nil {
		t.Errorf("with nothing set it gave %v, %v", config, err)
	}
	ca := newTestAuthority(t).file(t)
	if _, err := adminClientAuth(ca, ""); err == nil || !strings.Contains(err.Error(), "-tls-cert") {
		t.Errorf("on a plaintext listener it gave %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminClientAuth(empty, "server.pem"); err == nil || !strings.Contains(err.Error(), "no PEM") {
		t.Errorf("a file with no certificate gave %v", err)
	}
	if _, err := adminClientAuth(filepath.Join(t.TempDir(), "missing"), "server.pem"); err == nil {
		t.Error("a file that is not there was accepted")
	}
}
