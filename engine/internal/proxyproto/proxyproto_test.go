package proxyproto

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"

	"signari.dev/engine/internal/ldapd"
)

// header builds a v2 header: version 2 with cmd, then family and protocol.
func header(cmd, famProto byte, src, dst netip.AddrPort, tlv []byte) []byte {
	out := append([]byte(nil), signature...)
	out = append(out, 0x20|cmd, famProto)
	var addrs []byte
	switch famProto >> 4 {
	case 1:
		s, d := src.Addr().As4(), dst.Addr().As4()
		addrs = append(append(addrs, s[:]...), d[:]...)
	case 2:
		s, d := src.Addr().As16(), dst.Addr().As16()
		addrs = append(append(addrs, s[:]...), d[:]...)
	}
	if addrs != nil {
		addrs = binary.BigEndian.AppendUint16(addrs, src.Port())
		addrs = binary.BigEndian.AppendUint16(addrs, dst.Port())
	}
	addrs = append(addrs, tlv...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(addrs)))
	return append(out, addrs...)
}

var (
	client  = netip.MustParseAddrPort("198.51.100.7:40000")
	client6 = netip.MustParseAddrPort("[2001:db8::7]:40000")
	server  = netip.MustParseAddrPort("192.0.2.1:636")
	server6 = netip.MustParseAddrPort("[2001:db8::1]:636")
)

// listen returns a listener whose loopback peers are trusted or not, and a
// function that sends raw bytes from a new connection and hands back the
// accepted side.
func listen(t *testing.T, trusted bool) func(send []byte) net.Conn {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &Listener{Listener: inner, Trusted: func(netip.Addr) bool { return trusted }}
	t.Cleanup(func() { _ = ln.Close() })
	return func(send []byte) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if _, err := c.Write(send); err != nil {
			t.Fatal(err)
		}
		if tc, ok := c.(*net.TCPConn); ok && len(send) < 16 {
			_ = tc.CloseWrite() // a partial header, and then nothing
		}
		got, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = got.Close() })
		return got
	}
}

func readAll(t *testing.T, c net.Conn, n int) ([]byte, error) {
	t.Helper()
	buf := make([]byte, n)
	// A deadline, so a header consumed that should not have been fails the
	// test rather than hanging it on bytes that will never come.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := io.ReadFull(c, buf)
	return buf, err
}

func TestATrustedBalancersHeaderNamesTheClient(t *testing.T) {
	accept := listen(t, true)
	for name, h := range map[string][]byte{
		"TCP over IPv4": header(1, 0x11, client, server, nil),
		"TCP over IPv6, with TLVs skipped": header(1, 0x21, client6, server6,
			[]byte{0x01, 0x00, 0x02, 'h', '2', 0x04, 0x00, 0x00}),
	} {
		c := accept(append(h, []byte("payload")...))
		want := client
		if name != "TCP over IPv4" {
			want = client6
		}
		if got := c.RemoteAddr().String(); got != want.String() {
			t.Errorf("%s: RemoteAddr is %s, want %s", name, got, want)
		}
		// Exactly the header is consumed: what follows reaches the protocol whole.
		if data, err := readAll(t, c, 7); err != nil || string(data) != "payload" {
			t.Errorf("%s: after the header the connection read %q, %v", name, data, err)
		}
	}

	// LOCAL is the balancer's own connection, a health check: it is served,
	// as the balancer, whatever addresses or family the block carries (§2.2).
	// Served is checked as well as the address, because a refused connection
	// also reports the balancer's address.
	for name, h := range map[string][]byte{
		"a LOCAL header with a client in it": header(0, 0x11, client, server, nil),
		"a LOCAL header with a bogus family": header(0, 0xFF, client, server, nil),
	} {
		c := accept(append(h, []byte("ping")...))
		if got, _ := addrOf(c.RemoteAddr()); got.String() != "127.0.0.1" {
			t.Errorf("%s: the connection is %s, want the balancer itself", name, c.RemoteAddr())
		}
		if data, err := readAll(t, c, 4); err != nil || string(data) != "ping" {
			t.Errorf("%s: not served: %q, %v", name, data, err)
		}
	}
	// AF_UNSPEC: the real endpoint too.
	if got, _ := addrOf(accept(header(1, 0x00, client, server, nil)).RemoteAddr()); got.String() != "127.0.0.1" {
		t.Errorf("an UNSPEC connection is %s, want the balancer itself", got)
	}
}

// A trusted peer that must send a header and sends none, or a malformed one,
// is dropped before anything reads it: §2 forbids guessing that the header is
// absent, and §2.2 says to drop unexpected values and partial headers.
func TestATrustedPeersMissingOrMalformedHeaderIsRefused(t *testing.T) {
	accept := listen(t, true)
	v4 := header(1, 0x11, client, server, nil)
	bad := func(i int, b byte) []byte {
		h := append([]byte(nil), v4...)
		h[i] = b
		return h
	}
	short := append([]byte(nil), v4...)
	binary.BigEndian.PutUint16(short[14:16], 8)
	for name, send := range map[string][]byte{
		"no header":                   []byte("\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
		"version 1":                   bad(12, 0x11),
		"command 2":                   bad(12, 0x22),
		"a datagram":                  bad(13, 0x12),
		"a UNIX socket":               bad(13, 0x31),
		"an unknown family":           bad(13, 0x41),
		"too short for its addresses": short[:16+8],
		"a partial header":            v4[:10],
	} {
		c := accept(send)
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: the first read returned %v, want a refusal", name, err)
		}
		if got, _ := addrOf(c.RemoteAddr()); got.String() != "127.0.0.1" {
			t.Errorf("%s: a refused connection names %s", name, got)
		}
	}
}

// A deadline the server set before its first read still holds after the
// header is read under one of its own; clearing it would leave the connection
// with no deadline at all.
func TestACallersDeadlineSurvivesTheHeader(t *testing.T) {
	c := listen(t, true)(header(1, 0x11, client, server, nil))
	if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("the read ended with %v, want the caller's timeout", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("the caller's deadline fired after %s", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the caller's deadline was cleared by reading the header")
	}
}

// From a peer that is not a named balancer nothing is parsed: the header is
// the first bytes of the protocol, and the address is the socket's.
func TestAnUntrustedPeersHeaderIsNotRead(t *testing.T) {
	accept := listen(t, false)
	h := header(1, 0x11, client, server, nil)
	c := accept(h)
	if got, _ := addrOf(c.RemoteAddr()); got.String() != "127.0.0.1" {
		t.Errorf("an untrusted peer named its own address: %s", c.RemoteAddr())
	}
	if data, err := readAll(t, c, len(h)); err != nil || string(data) != string(h) {
		t.Errorf("an untrusted peer's header was consumed: %q, %v", data, err)
	}
}

// recordingAuth refuses every bind and remembers the address it was charged to.
type recordingAuth struct {
	mu    sync.Mutex
	peers []string
}

func (a *recordingAuth) Authenticate(ctx context.Context, _, _ string) (*ldapd.Identity, error) {
	a.mu.Lock()
	a.peers = append(a.peers, ldapd.PeerAddr(ctx))
	a.mu.Unlock()
	return nil, errors.New("refused")
}
func (a *recordingAuth) Lookup(context.Context, string) (*ldapd.Identity, error) { return nil, nil }
func (a *recordingAuth) List(context.Context, int) ([]*ldapd.Identity, error)    { return nil, nil }

// The LDAP listener behind a balancer charges a bind to the client the header
// names, and a header from anyone else gets no bind at all.
func TestAnLDAPBindBehindABalancerIsChargedToTheClient(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		auth := &recordingAuth{}
		srv := ldapd.New(ldapd.Config{BaseDN: "dc=example,dc=test", UserAttr: "uid",
			ReadTimeout: 5 * time.Second}, auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			_ = srv.Serve(ctx, &Listener{Listener: inner,
				Trusted: func(netip.Addr) bool { return trusted }})
		}()

		raw, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Write(header(1, 0x11, client, server, nil)); err != nil {
			t.Fatal(err)
		}
		c := ldapclient.NewConn(raw, false)
		c.Start()
		c.SetTimeout(3 * time.Second)
		bindErr := c.Bind("uid=alice,dc=example,dc=test", "wrong")
		_ = c.Close()
		cancel()
		_ = inner.Close()

		auth.mu.Lock()
		peers := append([]string(nil), auth.peers...)
		auth.mu.Unlock()
		if trusted {
			if len(peers) != 1 || peers[0] != client.Addr().String() {
				t.Errorf("behind a trusted balancer the bind was charged to %q, want %s (%v)",
					peers, client.Addr(), bindErr)
			}
		} else if len(peers) != 0 {
			t.Errorf("an untrusted peer's header reached a bind, charged to %q", peers)
		}
	}
}
