package ech

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 9848 Figure 1 (specs/rfc9848.txt:111-112, unwrapped per RFC 8792): an
// ECHConfigList whose public name is ech-sites.example.net. Read and written
// back byte for byte, the encoding here is the one in the specification, not
// the one this package and its own test happen to agree on.
const figure1 = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA="

func TestTheSpecificationsExampleIsReadAndWrittenExactly(t *testing.T) {
	list, err := base64.StdEncoding.DecodeString(figure1)
	if err != nil {
		t.Fatal(err)
	}
	configs, err := SplitConfigList(list)
	if err != nil || len(configs) != 1 {
		t.Fatalf("split: %d configs, %v", len(configs), err)
	}
	c, err := ParseConfig(configs[0])
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != 1 || c.KEM != kemX25519 || len(c.PublicKey) != 32 || c.PublicName != "ech-sites.example.net" ||
		c.MaxNameLength != 100 || len(c.Suites) != 1 || c.Suites[0] != (Suite{kdfHKDFSHA256, aeadAES128GCM}) {
		t.Fatalf("read %+v", c)
	}
	again, err := MarshalConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, configs[0]) {
		t.Fatalf("written back:\n%x\nwant:\n%x", again, configs[0])
	}
	whole, err := MarshalConfigList(again)
	if err != nil || base64.StdEncoding.EncodeToString(whole) != figure1 {
		t.Fatalf("the list written back is %s (%v)", base64.StdEncoding.EncodeToString(whole), err)
	}
}

// keyFile makes a key and writes its file.
func keyFile(t *testing.T, dir, name, publicName string, id byte) (string, Key) {
	t.Helper()
	k, err := New(publicName, id)
	if err != nil {
		t.Fatal(err)
	}
	data, err := k.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, k
}

// server is a TLS 1.3 listener holding keys, with a certificate for both the
// name asked for and the public name, as a deployment's would be.
func server(t *testing.T, keys []tls.EncryptedClientHelloKey) (addr string, roots *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ech test"},
		DNSNames: []string{"auth.example.test", "public.example.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, EncryptedClientHelloKeys: keys,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	return ln.Addr().String(), roots
}

// dial asks for auth.example.test with ECH under list.
func dial(t *testing.T, addr string, roots *x509.CertPool, list []byte) (tls.ConnectionState, error) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "auth.example.test", RootCAs: roots,
		MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list})
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = c.Close() }()
	return c.ConnectionState(), nil
}

func TestAClientWithTheKeysConfigurationIsAcceptedUnderECH(t *testing.T) {
	dir := t.TempDir()
	p, k := keyFile(t, dir, "ech.pem", "public.example.test", 7)
	keys, configs, err := Load([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if configs[0].ID != 7 || configs[0].PublicName != "public.example.test" {
		t.Fatalf("loaded %+v", configs[0])
	}
	addr, roots := server(t, keys)
	list, _ := k.List()
	st, err := dial(t, addr, roots, list)
	if err != nil {
		t.Fatalf("the handshake under the published configuration failed: %v", err)
	}
	if !st.ECHAccepted || st.ServerName != "auth.example.test" {
		t.Fatalf("ECH accepted %v, inner name %q", st.ECHAccepted, st.ServerName)
	}
}

// Refused, a client is handed the newest key to retry with (SendAsRetry), and a
// key from before it, still loaded for clients with an older DNS answer, is
// accepted but not handed out.
func TestKeysRotateNewestFirst(t *testing.T) {
	dir := t.TempDir()
	newPath, newKey := keyFile(t, dir, "new.pem", "public.example.test", 2)
	oldPath, oldKey := keyFile(t, dir, "old.pem", "public.example.test", 1)
	_, stranger := keyFile(t, dir, "stranger.pem", "public.example.test", 3)
	keys, _, err := Load([]string{newPath, oldPath})
	if err != nil {
		t.Fatal(err)
	}
	addr, roots := server(t, keys)

	oldList, _ := oldKey.List()
	if st, err := dial(t, addr, roots, oldList); err != nil || !st.ECHAccepted {
		t.Fatalf("the previous key, still loaded, was not accepted: %v %v", st.ECHAccepted, err)
	}
	strangerList, _ := stranger.List()
	_, err = dial(t, addr, roots, strangerList)
	var rejected *tls.ECHRejectionError
	if !errors.As(err, &rejected) {
		t.Fatalf("a key the server does not hold: %v, want a rejection with retry configurations", err)
	}
	newList, _ := newKey.List()
	if !bytes.Equal(rejected.RetryConfigList, newList) {
		t.Fatalf("retry configurations %x, want only the newest key's %x", rejected.RetryConfigList, newList)
	}
}

func TestAKeyFileThatCannotWorkIsRefused(t *testing.T) {
	dir := t.TempDir()
	a, ka := keyFile(t, dir, "a.pem", "public.example.test", 5)
	b, _ := keyFile(t, dir, "b.pem", "public.example.test", 5)
	if _, _, err := Load([]string{a, b}); err == nil || !strings.Contains(err.Error(), "config id 5") {
		t.Errorf("two keys under one config id: %v", err)
	}

	// A configuration that is not the file's own key's: clients would encrypt to
	// a key the server does not hold.
	_, kc := keyFile(t, dir, "c.pem", "public.example.test", 6)
	swapped := Key{Private: ka.Private, Config: kc.Config}
	data, err := swapped.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePEM(data); err == nil {
		t.Error("a file whose configuration is another key's was read")
	}

	for _, name := range []string{"192.0.2.7", "[2001:db8::1]", "localhost", "a..b.test", "-x.example.test", ""} {
		if _, err := New(name, 1); err == nil {
			t.Errorf("the public name %q was taken", name)
		}
	}
}
