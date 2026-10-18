package outpost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ldap.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// Without a certificate the outpost does not start, unless plaintext was asked
// for by name.
func TestAnLDAPOutpostWithoutTLSRefusesToListen(t *testing.T) {
	for _, c := range []struct {
		cert, key string
		insecure  bool
		want      string
	}{
		{"", "", false, "needs -tls-cert"},
		{"cert.pem", "", false, "both"},
		{"", "key.pem", false, "both"},
		{"cert.pem", "key.pem", true, "contradict"},
	} {
		if ln, err := ListenLDAP("127.0.0.1:0", c.cert, c.key, c.insecure); err == nil {
			_ = ln.Close()
			t.Errorf("ListenLDAP(%q, %q, insecure=%v) listened", c.cert, c.key, c.insecure)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ListenLDAP(%q, %q, insecure=%v) = %v, want it to say %q",
				c.cert, c.key, c.insecure, err, c.want)
		}
	}

	ln, err := ListenLDAP("127.0.0.1:0", "", "", true)
	if err != nil {
		t.Fatalf("plaintext asked for by name was refused: %v", err)
	}
	_ = ln.Close()
}

// With a certificate, the listener speaks TLS: a TLS client completes the
// handshake, and a plaintext bind is never answered as LDAP.
func TestAnLDAPOutpostWithACertificateServesLDAPS(t *testing.T) {
	certFile, keyFile, pool := writeCert(t)
	ln, err := ListenLDAP("127.0.0.1:0", certFile, keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				// A TLS connection handshakes on first use; a plaintext one
				// fails here and is closed without an LDAP byte written.
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{0x30})
			}()
		}
	}()

	tc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("a TLS client could not connect: %v", err)
	}
	_ = tc.Close()

	// An LDAPv3 simple bind for cn=x with password "secret", in the clear.
	bind := []byte{0x30, 0x16, 0x02, 0x01, 0x01, 0x60, 0x11, 0x02, 0x01, 0x03,
		0x04, 0x04, 'c', 'n', '=', 'x', 0x80, 0x06, 's', 'e', 'c', 'r', 'e', 't'}
	pc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	_, _ = pc.Write(bind)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, _ := io.ReadAll(pc)
	if len(reply) > 0 && reply[0] == 0x30 {
		t.Fatalf("a plaintext bind was answered as LDAP: % x", reply)
	}
}
