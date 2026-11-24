package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert writes a self-signed certificate for names, valid from notBefore
// to notAfter, and its key, returning both paths.
func writeCert(t *testing.T, dir string, names []string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, priv := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

// A certificate is taken only when serve could use it for the issuer's host
// (B5): its key is its own, a name covers the host, and it holds today; one
// that ends within 14 days is taken with a warning.
func TestACertificateIsHeldToTheIssuersHost(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	good, goodKey := writeCert(t, filepath.Join(dir, "good"), []string{"login.example.com"}, now.Add(-time.Hour), now.AddDate(0, 3, 0))
	if facts, warn, err := checkTLSFiles(good, goodKey, "login.example.com", now); err != nil || warn != "" ||
		!facts.notAfter.After(now) {
		t.Errorf("a good certificate: %v, warning %q", err, warn)
	}
	if _, _, err := checkTLSFiles(good, goodKey, "other.example.com", now); err == nil ||
		!strings.Contains(err.Error(), "not other.example.com") {
		t.Errorf("a certificate for another host: %v", err)
	}
	_, otherKey := writeCert(t, filepath.Join(dir, "other"), []string{"login.example.com"}, now.Add(-time.Hour), now.AddDate(0, 3, 0))
	if _, _, err := checkTLSFiles(good, otherKey, "login.example.com", now); err == nil {
		t.Error("a key that is not the certificate's was taken")
	}
	old, oldKey := writeCert(t, filepath.Join(dir, "old"), []string{"login.example.com"}, now.AddDate(0, -3, 0), now.Add(-time.Hour))
	if _, _, err := checkTLSFiles(old, oldKey, "login.example.com", now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired certificate: %v", err)
	}
	soon, soonKey := writeCert(t, filepath.Join(dir, "soon"), []string{"*.example.com"}, now.Add(-time.Hour), now.AddDate(0, 0, 5))
	if _, warn, err := checkTLSFiles(soon, soonKey, "login.example.com", now); err != nil || !strings.Contains(warn, "14 days") {
		t.Errorf("a certificate ending in 5 days, by a wildcard: %v, warning %q", err, warn)
	}
	if err := os.WriteFile(filepath.Join(dir, "junk.pem"), []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkTLSFiles(filepath.Join(dir, "junk.pem"), goodKey, "login.example.com", now); err == nil {
		t.Error("a file that is not PEM was taken")
	}
}

// What listens on 443 and 80 is read from /proc, named by the process that
// holds the socket; nothing else, and nothing in another state.
func TestAProxyIsFoundByWhatListensOn443(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4443 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 8080 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0050 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4480 1 0000000000000000 100 0 0 10 0
`
	for name, body := range map[string]string{"tcp": tcp, "tcp6": tcp6} {
		if err := os.WriteFile(filepath.Join(proc, "net", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd := filepath.Join(proc, "812", "fd")
	if err := os.MkdirAll(fd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[4443]", filepath.Join(fd, "6")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "812", "comm"), []byte("nginx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := webListeners(proc)
	if len(got) != 2 || got[0] != (listener{443, "nginx"}) || got[1] != (listener{80, ""}) {
		t.Errorf("listeners %+v, want nginx on 443 first, then an unnamed one on 80", got)
	}
	if got := webListeners(t.TempDir()); got != nil {
		t.Errorf("a machine with no /proc: %+v", got)
	}
}

// The TLS question (B5) is asked only for an https:// address, answered by
// default from what is here, and each answer writes what serve reads for it.
// A re-run reads the answer back from the env file, and a flag that disagrees
// with it is refused.
func TestTheTLSQuestionFollowsWhatIsHere(t *testing.T) {
	now := time.Now()
	h := testHost(t)
	prior := envFile{path: filepath.Join(h.home, "conf", envFileName), values: map[string]string{}}
	answer := func(f setupFlags, h setupHost, prior envFile) (setupAnswers, error) {
		t.Helper()
		f.email = "ada@example.com"
		a, _, err := resolveAnswers(f, h, prior, nil, false)
		return a, err
	}
	must := func(f setupFlags, h setupHost) setupAnswers {
		t.Helper()
		a, err := answer(f, h, prior)
		if err != nil {
			t.Fatalf("%+v: %v", f, err)
		}
		return a
	}

	if a := must(setupFlags{}, h); a.tls != tlsNone || len(a.tlsEnv()) != 0 {
		t.Errorf("http://localhost: TLS %q, settings %v", a.tls, a.tlsEnv())
	}
	if _, err := answer(setupFlags{tls: tlsProxy}, h, prior); exitCode(err) != 2 || !strings.Contains(err.Error(), "https://") {
		t.Errorf("-tls with an http:// address: %v", err)
	}

	https := setupFlags{issuer: "https://login.example.com"}
	a := must(https, h)
	if env := a.tlsEnv(); a.tls != tlsProxy || a.addr != "127.0.0.1:8080" ||
		env["SIGNARI_TRUSTED_PROXIES"] != defaultTrustedProxies || env["SIGNARI_CLIENT_IP_SOURCE"] != "x-forwarded-for" {
		t.Errorf("nothing here: %+v, settings %v", a, env)
	}
	busy := h
	busy.listeners = func() []listener { return []listener{{443, "nginx"}} }
	if a := must(https, busy); a.tls != tlsProxy || !strings.Contains(a.tlsWhy, "nginx listens on port 443") {
		t.Errorf("a proxy on 443: %q, %q", a.tls, a.tlsWhy)
	}

	le := h
	le.leLive = filepath.Join(t.TempDir(), "live")
	writeCert(t, filepath.Join(le.leLive, "login.example.com"), []string{"login.example.com"}, now.Add(-time.Hour),
		now.AddDate(0, 2, 0))
	a = must(https, le)
	if a.tls != tlsFiles || a.addr != ":443" || a.lineage != filepath.Join(le.leLive, "login.example.com") {
		t.Errorf("a Let's Encrypt certificate for the host: %+v", a)
	}
	if err := (&setupRun{h: le, a: a}).inspectTLS(); err == nil || !strings.Contains(err.Error(), "run setup as root") {
		t.Errorf("its key, which only root reads, as somebody else: %v", err)
	}

	own, ownKey := writeCert(t, filepath.Join(t.TempDir(), "own"), []string{"login.example.com"}, now.Add(-time.Hour),
		now.AddDate(0, 2, 0))
	f := https
	f.tlsCert, f.tlsKey = own, ownKey
	r := &setupRun{h: h, a: must(f, h)}
	if err := r.inspectTLS(); err != nil || r.a.tls != tlsFiles || r.a.lineage != "" ||
		r.a.tlsEnv()["SIGNARI_TLS_CERT"] != own || r.cert.notAfter.IsZero() {
		t.Errorf("files of one's own: %v, %+v", err, r.a)
	}
	f.issuer = "https://other.example.com"
	if err := (&setupRun{h: h, a: must(f, h)}).inspectTLS(); err == nil {
		t.Error("a certificate for another host was taken")
	}
	f = https
	f.tls, f.tlsCert = tlsProxy, own
	if _, err := answer(f, h, prior); exitCode(err) != 2 {
		t.Errorf("-tls proxy with -tls-cert: %v", err)
	}

	r = &setupRun{h: h, a: must(https, h), engineDSN: "postgres://signari_engine:x@127.0.0.1:5432/signari"}
	content, _, err := prior.render(r.envValues())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(prior.path, []byte(content), true, h.euid, nil); err != nil {
		t.Fatal(err)
	}
	back, err := readEnvFile(prior.path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := answer(https, busy, back)
	if err != nil || again.tls != tlsProxy || again.from["tls"] != "env file" || again.trustedProxies != defaultTrustedProxies {
		t.Errorf("a re-run: %v, %+v", err, again)
	}
	f = https
	f.trustedProxies = "10.0.0.1"
	if _, err := answer(f, h, back); exitCode(err) != 2 || !strings.Contains(err.Error(), "-trusted-proxies") {
		t.Errorf("-trusted-proxies against the env file: %v", err)
	}
}

// The certbot hook copies one certificate, for the service, and restarts it
// only if it runs: serve reads its certificate once, when it starts.
func TestTheCertbotHookCopiesAndRestarts(t *testing.T) {
	text, err := certbotHookText("/etc/letsencrypt/live/login.example.com", "/etc/signari/tls", 997, 996)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#!/bin/sh\n", `[ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/login.example.com" ] || exit 0`,
		"install -m 0600 -o 997 -g 996", `mv -f "/etc/signari/tls/.$name.new" "/etc/signari/tls/$name"`,
		"systemctl try-restart signari.service"} {
		if !strings.Contains(text, want) {
			t.Errorf("the hook lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "{{") {
		t.Errorf("the hook has a placeholder left:\n%s", text)
	}
	if _, err := certbotHookText("/etc/letsencrypt/live/x; rm -rf /", "/etc/signari/tls", 1, 1); err == nil {
		t.Error("a path that would be shell was written into the hook")
	}
	if !lowPort(":443") || lowPort("127.0.0.1:8080") || lowPort("nonsense") {
		t.Error("lowPort")
	}
}
