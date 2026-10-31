package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"signari.dev/engine/internal/rac"
	"signari.dev/engine/internal/store"
)

// Remote access through the real endpoint (8.29): a place is taken before guacd is
// asked, so a connection with room for one never asks for a second, and a session past
// the connection's maximum duration ends with that reason.

// holdingGuacd answers every handshake and holds the channel open, as a session to an
// idle desktop does, counting what it was asked for.
func holdingGuacd(t *testing.T) (addr string, opened chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	opened = make(chan string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				r, w := rac.NewReader(conn), rac.NewWriter(conn)
				if _, err := r.ReadInstruction(); err != nil { // select
					return
				}
				_ = w.Write(rac.Instruction{Opcode: "args", Args: []string{"VERSION_1_5_0", "hostname", "port"}})
				for {
					in, err := r.ReadInstruction()
					if err != nil {
						return
					}
					if in.Opcode == "connect" {
						break
					}
				}
				_ = w.Write(rac.Instruction{Opcode: "ready", Args: []string{"$held"}})
				opened <- "opened"
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), opened
}

// racFixture is a signed-in person, a connection and the endpoint.
func racFixture(t *testing.T, maxConnections, maxDurationSeconds int) (f *tokenFixture, opened chan string,
	connect func() (*websocket.Conn, *http.Response, error)) {
	t.Helper()
	f = newTokenFixture(t)
	addr, opened := holdingGuacd(t)
	f.srv.guacdAddr = addr
	ctx := context.Background()
	if _, err := store.AddRACConnection(ctx, f.pool, nil, f.orgID, store.RACSpec{Slug: "desk", Protocol: "rdp",
		Host: "10.0.4.21"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.rac_sessions WHERE org_id = $1::uuid`, f.orgID)
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.rac_connections WHERE org_id = $1::uuid`, f.orgID)
	})
	if err := store.SetRACLimits(ctx, f.pool, f.orgID, "desk", &maxConnections, &maxDurationSeconds); err != nil {
		t.Fatal(err)
	}
	cookie, _ := f.signedInCookies(t)
	srv := httptest.NewServer(f.srv.Routes())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/rac/connect/desk"
	return f, opened, func() (*websocket.Conn, *http.Response, error) {
		dial, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return websocket.Dial(dial, url, &websocket.DialOptions{Subprotocols: []string{"guacamole"},
			HTTPHeader: http.Header{"Cookie": {sessionCookieHeader(cookie)}}})
	}
}

// sessionCookieHeader is the session cookie as a browser sends it.
func sessionCookieHeader(value string) string {
	r := httptest.NewRecorder()
	http.SetCookie(r, &http.Cookie{Name: SessionCookieName, Value: value})
	return strings.SplitN(r.Header().Get("Set-Cookie"), ";", 2)[0]
}

func TestAConnectionWithACapRefusesTheNextPersonBeforeGuacdIsAsked(t *testing.T) {
	f, opened, connect := racFixture(t, 1, 0)

	first, _, err := connect()
	if err != nil {
		t.Fatalf("the first connection: %v", err)
	}
	defer func() { _ = first.CloseNow() }()
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("guacd was never asked for the first connection")
	}

	_, res, err := connect()
	if err == nil {
		t.Fatal("a second connection was admitted to a connection with room for one")
	}
	if res == nil || res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the second connection answered %v, want 429", res)
	}
	select {
	case <-opened:
		t.Error("guacd was asked for a connection there was no room for")
	case <-time.After(100 * time.Millisecond):
	}

	// Closing gives the place back, at once and not after the stale limit.
	_ = first.Close(websocket.StatusNormalClosure, "")
	deadline := time.Now().Add(5 * time.Second)
	for {
		var open int
		if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.rac_sessions
			WHERE org_id = $1::uuid AND ended_at IS NULL`, f.orgID).Scan(&open); err != nil {
			t.Fatal(err)
		}
		if open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first session was never recorded as ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	next, _, err := connect()
	if err != nil {
		t.Fatalf("the place was not given back: %v", err)
	}
	_ = next.CloseNow()
}

func TestASessionEndsAtTheConnectionsMaximumDuration(t *testing.T) {
	prev := rac.RecheckInterval
	rac.RecheckInterval = 20 * time.Millisecond
	t.Cleanup(func() { rac.RecheckInterval = prev })

	f, opened, connect := racFixture(t, 0, 1)
	began := time.Now()
	ws, _, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.CloseNow() }()
	<-opened

	read, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		if _, _, err := ws.Read(read); err != nil {
			break
		}
	}
	if read.Err() != nil {
		t.Fatal("the channel was still open long after its maximum duration")
	}
	if took := time.Since(began); took < time.Second {
		t.Errorf("the channel ended after %v, before its maximum duration of a second", took)
	}
	var reason *string
	var seen *time.Time
	deadline := time.Now().Add(5 * time.Second)
	for reason == nil && time.Now().Before(deadline) {
		if err := f.pool.QueryRow(context.Background(), `SELECT ended_reason, last_seen_at FROM core.rac_sessions
			WHERE org_id = $1::uuid`, f.orgID).Scan(&reason, &seen); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reason == nil || !strings.Contains(*reason, "maximum duration") {
		t.Errorf("recorded as ended for %v", reason)
	}
	if seen == nil {
		t.Error("an open channel never said it was still there")
	}
}

// guacd is reached the way the environment says, and a setting that does not work is
// refused, because the fallback would be a target's credentials in the clear.
func TestGuacdTLSFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "guacd"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true}, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "guacd"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		on, ca, addr string
		refused      string
	}{
		"plaintext unless asked for": {addr: "127.0.0.1:4822"},
		"a CA that would be ignored": {ca: ca, addr: "127.0.0.1:4822", refused: "would be ignored"},
		"an address with no host":    {on: "1", addr: "guacd", refused: "needs a host and port"},
		"a CA that cannot be read":   {on: "1", ca: filepath.Join(dir, "absent.pem"), addr: "guacd:4822", refused: "reading"},
		"a CA that holds nothing":    {on: "1", ca: empty, addr: "guacd:4822", refused: "holds no certificate"},
		"the system's roots":         {on: "1", addr: "guacd:4822"},
		"a private CA":               {on: "1", ca: ca, addr: "guacd:4822"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SIGNARI_GUACD_TLS", c.on)
			t.Setenv("SIGNARI_GUACD_CA", c.ca)
			config, err := guacdTLSFromEnv(c.addr)
			if c.refused != "" {
				if err == nil || !strings.Contains(err.Error(), c.refused) {
					t.Fatalf("answered %v, want a refusal saying %q", err, c.refused)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case c.on == "" && config != nil:
				t.Error("TLS without being asked for it")
			case c.on == "":
			case config == nil:
				t.Fatal("plaintext when TLS was asked for")
			case config.InsecureSkipVerify:
				t.Error("the certificate is not checked")
			case config.ServerName != "guacd":
				t.Errorf("checked against %q", config.ServerName)
			case (c.ca != "") != (config.RootCAs != nil):
				t.Errorf("trust is %v with a CA of %q", config.RootCAs, c.ca)
			}
		})
	}
}
