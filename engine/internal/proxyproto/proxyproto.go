// Package proxyproto reads the PROXY protocol version 2 header a TCP load
// balancer puts in front of a connection, so a listener behind one sees the
// client's address instead of the balancer's.
//
// # Why
//
// An HTTP reverse proxy says who the client is in a header, and
// internal/clientip reads it. A TCP balancer has no header to write: the LDAP
// listener and an HTTP listener behind one both saw the balancer's address
// on every connection, so every per-address budget -- failed binds, failed
// passwords -- was one bucket shared by every client, and twenty bad binds from
// anybody refused everybody.
//
// # The rules, from the specification
//
// HAProxy's "The PROXY protocol, Versions 1 & 2"
// (https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt):
//
//   - §2: "The receiver MUST NOT start processing the connection before it
//     receives a complete and valid PROXY protocol header", and it "MUST not try
//     to guess whether the protocol header is present or not". So a peer that
//     must send one and does not is refused, never served as if it had.
//   - §2: "The receiver SHOULD ensure proper access filtering so that only
//     trusted proxies are allowed to use this protocol." A header is read only
//     from a peer in SIGNARI_TRUSTED_PROXIES. From anyone else it is not read at
//     all: its bytes reach the LDAP or HTTP parser as the start of the protocol,
//     which refuses them, so nobody can name their own source address.
//   - §2.2: the version nibble "must always be sent as \x2 and the receiver must
//     only accept this value", and "Receivers must drop connections presenting
//     unexpected values" for the command; a LOCAL connection is accepted "and
//     must use the real connection endpoints"; partial headers are rejected.
//
// Which peers must send one is configuration (SIGNARI_PROXY_PROTOCOL names the
// listeners, SIGNARI_TRUSTED_PROXIES the peers), never what the first bytes look
// like, which is what §2 means by not guessing. Version 1, the text form, is not
// read: nothing that speaks only version 1 is worth a second parser.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// signature is §2.2's twelve bytes. It holds a NUL, so it is compared as bytes.
var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// HeaderTimeout bounds how long a trusted peer has to send its header. §2.2:
// "This block is always smaller than an MSS", so it arrives with the first
// segment or not at all.
const HeaderTimeout = 5 * time.Second

// ErrRefused wraps every reason a connection was dropped for its header.
var ErrRefused = errors.New("proxy protocol header refused")

// Listener reads a PROXY v2 header from every connection whose peer Trusted
// accepts, and passes every other connection through untouched.
type Listener struct {
	net.Listener
	Trusted func(netip.Addr) bool
}

// Accept returns the next connection. The header is read on the connection's
// own first Read or RemoteAddr, in the goroutine serving it, so a slow or
// silent peer cannot hold up the accept loop.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if peer, ok := addrOf(c.RemoteAddr()); ok && l.Trusted != nil && l.Trusted(peer) {
		return &Conn{Conn: c}, nil
	}
	return c, nil
}

// Conn is a connection from a trusted peer, which must begin with a header.
type Conn struct {
	net.Conn
	once   sync.Once
	remote net.Addr
	err    error

	mu sync.Mutex
	// readDeadline is the last one the caller set, restored after the header
	// is read under a deadline of its own.
	readDeadline time.Time
}

// SetDeadline records the read half so reading the header cannot clear it.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline records the deadline so reading the header cannot clear it.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *Conn) readHeader() {
	c.once.Do(func() {
		c.remote = c.Conn.RemoteAddr()
		c.mu.Lock()
		caller := c.readDeadline
		c.mu.Unlock()
		limit := time.Now().Add(HeaderTimeout)
		if !caller.IsZero() && caller.Before(limit) {
			limit = caller
		}
		_ = c.Conn.SetReadDeadline(limit)
		src, err := Read(c.Conn)
		// The caller's own deadline again, or none if it set none.
		_ = c.Conn.SetReadDeadline(caller)
		if err != nil {
			c.err = err
			_ = c.Conn.Close()
			return
		}
		if src != nil {
			c.remote = src
		}
	})
}

// Read reads the connection's data, after its header.
func (c *Conn) Read(p []byte) (int, error) {
	c.readHeader()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

// RemoteAddr is the client the header named, or the peer itself for a LOCAL
// connection or one whose header was refused.
func (c *Conn) RemoteAddr() net.Addr {
	c.readHeader()
	return c.remote
}

// Read consumes one PROXY v2 header from r and returns the source address it
// carries, or nil when the real endpoints apply (LOCAL, or AF_UNSPEC). It reads
// exactly the header, never past it.
func Read(r io.Reader) (net.Addr, error) {
	var head [16]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, fmt.Errorf("%w: no complete header (%v)", ErrRefused, err)
	}
	if !bytes.Equal(head[:12], signature) {
		return nil, fmt.Errorf("%w: the connection does not begin with the v2 signature", ErrRefused)
	}
	if v := head[12] >> 4; v != 2 {
		return nil, fmt.Errorf("%w: version %d", ErrRefused, v)
	}
	cmd := head[12] & 0x0F
	if cmd > 1 {
		return nil, fmt.Errorf("%w: command %d", ErrRefused, cmd)
	}
	family, proto := head[13]>>4, head[13]&0x0F
	length := int(binary.BigEndian.Uint16(head[14:16]))
	block := io.LimitReader(r, int64(length))
	defer func() { _, _ = io.Copy(io.Discard, block) }() // TLVs, skipped (§2.2)

	if cmd == 0 {
		return nil, nil // LOCAL: the real endpoints, and the family is ignored
	}
	if family > 3 || proto > 2 {
		return nil, fmt.Errorf("%w: family %d, protocol %d", ErrRefused, family, proto)
	}
	if family == 0 || proto == 0 {
		return nil, nil // UNSPEC: the real endpoints
	}
	if proto != 1 {
		return nil, fmt.Errorf("%w: a datagram header on a stream listener", ErrRefused)
	}
	var size int
	switch family {
	case 1:
		size = 4
	case 2:
		size = 16
	default:
		return nil, fmt.Errorf("%w: a UNIX-socket source has no address to charge", ErrRefused)
	}
	if length < 2*size+4 {
		return nil, fmt.Errorf("%w: %d bytes cannot hold the addresses", ErrRefused, length)
	}
	addrs := make([]byte, 2*size+4)
	if _, err := io.ReadFull(block, addrs); err != nil {
		return nil, fmt.Errorf("%w: partial address block (%v)", ErrRefused, err)
	}
	ip, _ := netip.AddrFromSlice(addrs[:size])
	port := binary.BigEndian.Uint16(addrs[2*size : 2*size+2])
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), port)), nil
}

func addrOf(a net.Addr) (netip.Addr, bool) {
	if a == nil {
		return netip.Addr{}, false
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}
