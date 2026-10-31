package outpost

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- RADIUS's own construction, in a test of it.
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"signari.dev/engine/internal/radius"
)

const deviceSecret = "a-long-random-shared-secret-for-a-device"

// accessRequest is an Access-Request as a network device sends one.
func accessRequest(t *testing.T, username, password string) []byte {
	t.Helper()
	var auth [16]byte
	if _, err := io.ReadFull(rand.Reader, auth[:]); err != nil {
		t.Fatal(err)
	}
	pw := []byte(password)
	for len(pw)%16 != 0 {
		pw = append(pw, 0)
	}
	hidden := make([]byte, 0, len(pw))
	prev := auth[:]
	for i := 0; i < len(pw); i += 16 {
		h := md5.New() // #nosec G401
		h.Write([]byte(deviceSecret))
		h.Write(prev)
		key := h.Sum(nil)
		block := make([]byte, 16)
		for j := range block {
			block[j] = pw[i+j] ^ key[j]
		}
		hidden = append(hidden, block...)
		prev = block
	}
	var body bytes.Buffer
	add := func(typ byte, v []byte) {
		body.WriteByte(typ)
		body.WriteByte(byte(len(v) + 2))
		body.Write(v)
	}
	add(radius.AttrUserName, []byte(username))
	add(radius.AttrUserPassword, hidden)
	add(radius.AttrMessageAuthenticator, make([]byte, 16))
	pkt := make([]byte, 20, 20+body.Len())
	pkt[0], pkt[1] = radius.CodeAccessRequest, 7
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+body.Len()))
	copy(pkt[4:20], auth[:])
	pkt = append(pkt, body.Bytes()...)
	mac := hmac.New(md5.New, []byte(deviceSecret))
	mac.Write(pkt)
	copy(pkt[len(pkt)-16:], mac.Sum(nil))
	return pkt
}

// A RADIUS outpost, over UDP, in front of a core (8.31): a password the core takes is an
// Access-Accept, one it refuses an Access-Reject, and when the core cannot be asked the
// device hears nothing, so it goes on to its next server rather than being told a person's
// password is wrong.
func TestARADIUSOutpostAnswersThroughItsCore(t *testing.T) {
	var down atomic.Bool
	var seen sync.Map
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		var ask map[string]string
		_ = json.NewDecoder(r.Body).Decode(&ask)
		seen.Store("client_ip", ask["client_ip"])
		if ask["password"] != "correct horse" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"username":"alice","active":true}`))
	}))
	t.Cleanup(core.Close)
	client, err := New(core.URL, "token", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	_, network, _ := net.ParseCIDR("127.0.0.0/8")
	srv, err := radius.New(radius.Config{Clients: []radius.Client{{Name: "ap", Net: network, Secret: deviceSecret}}},
		RADIUS{Client: client}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, conn) }()
	t.Cleanup(func() { cancel(); _ = conn.Close() })

	device, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	ask := func(password string) byte {
		t.Helper()
		if _, err := device.Write(accessRequest(t, "alice", password)); err != nil {
			t.Fatal(err)
		}
		_ = device.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		answer := make([]byte, 4096)
		n, err := device.Read(answer)
		if err != nil || n == 0 {
			return 0
		}
		return answer[0]
	}
	if got := ask("correct horse"); got != radius.CodeAccessAccept {
		t.Errorf("a password the core took gave code %d, want Access-Accept", got)
	}
	if ip, _ := seen.Load("client_ip"); ip != "" {
		t.Errorf("the core was given %q as where a person came from; a device is not a person", ip)
	}
	if got := ask("wrong horse"); got != radius.CodeAccessReject {
		t.Errorf("a password the core refused gave code %d, want Access-Reject", got)
	}
	down.Store(true)
	if got := ask("correct horse"); got != 0 {
		t.Errorf("an outage gave code %d; the device should hear nothing and try its next server", got)
	}
}

// The file is as private as a key, and what is wrong with it is said by line number,
// because a line of it holds a secret.
func TestADevicesFileIsAsPrivateAsAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.conf")
	write := func(body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	good := "# the second floor\n\nap-2  10.20.0.0/24  " + deviceSecret + "\nap-3 10.30.0.1/32 " + deviceSecret + "\n"
	write(good, 0o600)
	got, err := ReadRADIUSClients(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "ap-2" || got[1].Secret != deviceSecret ||
		got[1].Net.String() != "10.30.0.1/32" {
		t.Errorf("read %+v", got)
	}
	write(good, 0o640)
	if _, err := ReadRADIUSClients(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("a file its group can read gave %v", err)
	}
	for _, c := range []struct{ name, body, want string }{
		{"too few fields", "ap-2 10.20.0.0/24", "line 1"},
		{"too many fields", "\nap-2 10.20.0.0/24 " + deviceSecret + " extra", "line 2"},
		{"every address", "ap-2 0.0.0.0/0 " + deviceSecret, "line 1"},
		{"not a network", "ap-2 nowhere " + deviceSecret, "line 1"},
		{"a short secret", "ap-2 10.20.0.0/24 short", "line 1"},
	} {
		write(c.body, 0o600)
		_, err := ReadRADIUSClients(path)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to name %s", c.name, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), deviceSecret) {
			t.Errorf("%s: the error carries the secret", c.name)
		}
	}
}

// A running outpost keeps saying hello with nobody using it, and logs losing its core once
// and getting it back once, rather than a line a minute through an outage.
func TestAnOutpostSaysHelloUntilItStops(t *testing.T) {
	var calls atomic.Int64
	var refusing atomic.Bool
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get(VersionHeader); got != "1.2.3" {
			t.Errorf("a hello said it was %q", got)
		}
		if refusing.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"name":"x","kind":"ldap"}`))
	}))
	t.Cleanup(core.Close)
	client, err := New(core.URL, "token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.Identify("1.2.3")
	var mu sync.Mutex
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return log.Write(b)
	}), nil))
	logged := func() string {
		mu.Lock()
		defer mu.Unlock()
		return log.String()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { client.Heartbeat(ctx, 5*time.Millisecond, logger); close(done) }()
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); !ok(); {
			if time.Now().After(deadline) {
				t.Fatalf("waited for %s", what)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	waitFor("hellos", func() bool { return calls.Load() >= 3 })
	refusing.Store(true)
	seen := calls.Load()
	waitFor("hellos through an outage", func() bool { return calls.Load() >= seen+5 })
	refusing.Store(false)
	waitFor("the core coming back", func() bool { return strings.Contains(logged(), "has its core back") })
	if got := strings.Count(logged(), "lost its core"); got != 1 {
		t.Errorf("losing the core was logged %d times:\n%s", got, logged())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("it did not stop with its context")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
