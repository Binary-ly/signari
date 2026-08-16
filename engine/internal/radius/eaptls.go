package radius

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)


const (
	// eapTLSMaxFragment bounds one EAP-TLS fragment.
	//
	// 1024 is conservative on purpose. The theoretical limit is what the RADIUS
	// packet can hold, but a fragment that survives every access point in the
	// field is worth more than one that is maximally efficient and gets dropped
	// by somebody's five-year-old controller.
	eapTLSMaxFragment = 1024

	// eapSessionTTL bounds an unfinished conversation.
	eapSessionTTL = 60 * time.Second

	// eapMaxSessions caps concurrent handshakes. Reached, the oldest are
	// dropped: refusing new ones instead would let an attacker who fills the
	// table lock every legitimate user out.
	eapMaxSessions = 256
)

// CertificateAuthenticator maps a verified client certificate to a user.
//
// Separate from Authenticator because the question is different: not "is this
// password right" but "whose certificate is this, and may they be here".
type CertificateAuthenticator interface {
	// AuthenticateCertificate returns the username the certificate represents.
	// An error refuses the login.
	AuthenticateCertificate(cert *x509.Certificate) (string, error)
}

// EAPTLSConfig is what the server needs to run EAP-TLS.
type EAPTLSConfig struct {
	// Certificate is the RADIUS server's own certificate, which supplicants
	// verify. Its name must match what they are configured to expect.
	Certificate tls.Certificate
	// ClientCAs verify supplicant certificates. Required: without it there is
	// nothing to check a client certificate against.
	ClientCAs *x509.CertPool
	// Auth maps a verified certificate to a user.
	Auth CertificateAuthenticator
}

// eapSession is one in-flight conversation.
type eapSession struct {
	// state is the RADIUS State attribute value, and the map key.
	state string

	// conn is the in-memory pipe crypto/tls reads and writes.
	conn *eapConn
	tls  *tls.Conn

	// identifier is the EAP identifier of the last request we sent. A response
	// carrying a different one is out of sequence.
	identifier byte

	// outbound is what TLS has produced and we have not finished sending.
	outbound []byte
	// inbound accumulates a fragmented TLS message from the supplicant.
	inbound []byte
	// expecting is the TotalLength the supplicant declared, so a fragment set
	// that never ends is caught rather than accumulated forever.
	expecting uint32

	handshakeDone chan struct{}
	handshakeErr  error

	username string
	created  time.Time
	lastSeen time.Time
}

// eapSessions holds conversations in progress.
type eapSessions struct {
	mu sync.Mutex
	m  map[string]*eapSession
}

func newEAPSessions() *eapSessions {
	return &eapSessions{m: map[string]*eapSession{}}
}

func (s *eapSessions) get(state string) (*eapSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[state]
	if !ok {
		return nil, false
	}
	if time.Since(sess.lastSeen) > eapSessionTTL {
		delete(s.m, state)
		sess.close()
		return nil, false
	}
	sess.lastSeen = time.Now()
	return sess, true
}

func (s *eapSessions) put(sess *eapSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Expire before counting, so a table full of abandoned handshakes does not
	// evict live ones.
	for k, v := range s.m {
		if time.Since(v.lastSeen) > eapSessionTTL {
			delete(s.m, k)
			v.close()
		}
	}
	for len(s.m) >= eapMaxSessions {
		var oldestKey string
		var oldest time.Time
		for k, v := range s.m {
			if oldest.IsZero() || v.lastSeen.Before(oldest) {
				oldestKey, oldest = k, v.lastSeen
			}
		}
		if oldestKey == "" {
			break
		}
		s.m[oldestKey].close()
		delete(s.m, oldestKey)
	}
	s.m[sess.state] = sess
}

func (s *eapSessions) drop(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[state]; ok {
		sess.close()
		delete(s.m, state)
	}
}

func (s *eapSession) close() {
	if s.conn != nil {
		s.conn.closeBoth()
	}
}

// eapConn is the net.Conn crypto/tls runs over.
//
// Not a real socket. Writes go into a buffer the EAP layer drains and fragments
// into challenges; reads block until the EAP layer has fed in what arrived from
// the supplicant. crypto/tls is written against a stream, and this is the
// smallest thing that is one.
type eapConn struct {
	mu     sync.Mutex
	cond   *sync.Cond
	in     []byte // from the supplicant, waiting for tls to read
	out    []byte // from tls, waiting to be sent
	closed bool
}

func newEAPConn() *eapConn {
	c := &eapConn{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *eapConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.in) == 0 && !c.closed {
		c.cond.Wait()
	}
	if len(c.in) == 0 && c.closed {
		return 0, io.EOF
	}
	n := copy(b, c.in)
	c.in = c.in[n:]
	return n, nil
}

func (c *eapConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	c.out = append(c.out, b...)
	c.cond.Broadcast()
	return len(b), nil
}

// feed hands the supplicant's bytes to the TLS state machine.
func (c *eapConn) feed(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.in = append(c.in, b...)
	c.cond.Broadcast()
}

// waitOut blocks until TLS has produced output, the handshake ends, or the
// deadline passes.
//
// The deadline is what stops a stalled handshake holding a goroutine forever.
func (c *eapConn) waitOut(done <-chan struct{}, timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	for {
		c.mu.Lock()
		if len(c.out) > 0 || c.closed {
			out := c.out
			c.out = nil
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()

		select {
		case <-done:
			// The handshake finished; take whatever it left behind.
			c.mu.Lock()
			out := c.out
			c.out = nil
			c.mu.Unlock()
			return out
		case <-time.After(2 * time.Millisecond):
			if time.Now().After(deadline) {
				return nil
			}
		}
	}
}

func (c *eapConn) closeBoth() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.cond.Broadcast()
}

func (c *eapConn) Close() error { c.closeBoth(); return nil }

func (c *eapConn) LocalAddr() net.Addr  { return eapAddr{} }
func (c *eapConn) RemoteAddr() net.Addr { return eapAddr{} }

// Deadlines are not honoured: this conn is driven entirely by the EAP layer,
// which applies its own bounds through waitOut and the session TTL. Returning
// nil rather than an error keeps crypto/tls from treating the transport as
// broken when it sets one.
func (c *eapConn) SetDeadline(time.Time) error      { return nil }
func (c *eapConn) SetReadDeadline(time.Time) error  { return nil }
func (c *eapConn) SetWriteDeadline(time.Time) error { return nil }

type eapAddr struct{}

func (eapAddr) Network() string { return "eap" }
func (eapAddr) String() string  { return "eap" }

// newState returns a fresh RADIUS State value.
func newState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// startEAPTLS begins a conversation and returns the EAP-TLS Start request.
func (s *Server) startEAPTLS(id byte) (*eapSession, *EAPPacket, error) {
	if s.eapTLS == nil {
		return nil, nil, errors.New("EAP-TLS is not configured")
	}
	state, err := newState()
	if err != nil {
		return nil, nil, err
	}

	conn := newEAPConn()
	sess := &eapSession{
		state: state, conn: conn, identifier: id,
		handshakeDone: make(chan struct{}),
		created:       time.Now(), lastSeen: time.Now(),
	}

	sess.tls = tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{s.eapTLS.Certificate},
		ClientCAs:    s.eapTLS.ClientCAs,
		// RequireAndVerifyClientCert: a handshake that completes without a
		// client certificate has authenticated nobody. EAP-TLS has no other
		// credential, so anything weaker here is anonymous network access.
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	})

	// The handshake runs in its own goroutine because crypto/tls is blocking and
	// the EAP layer is a series of separate UDP packets. It ends when the
	// handshake completes, fails, or the session is dropped and the conn closed.
	go func() {
		sess.handshakeErr = sess.tls.Handshake()
		close(sess.handshakeDone)
	}()

	// The EAP-TLS Start packet carries no TLS data, only the S flag.
	frame := &EAPTLSFrame{Start: true}
	req := &EAPPacket{Code: EAPRequest, Identifier: id, Type: EAPTypeTLS,
		Data: frame.Encode()}
	return sess, req, nil
}

// continueEAPTLS feeds a supplicant response into the handshake and produces
// the next EAP packet.
//
// Returns done=true when the conversation has reached a verdict; ok says which
// verdict it is.
func (s *Server) continueEAPTLS(sess *eapSession, resp *EAPPacket) (
	next *EAPPacket, done, ok bool) {

	frame, err := DecodeEAPTLS(resp.Data)
	if err != nil {
		return nil, true, false
	}

	// A supplicant with more to send: acknowledge with an empty EAP-TLS packet
	// and wait. This is the fragment ACK, and omitting it stalls every
	// certificate chain larger than one fragment.
	if frame.More {
		if frame.LengthIncluded {
			if frame.TotalLength > 1<<20 {
				// A megabyte of certificate chain is not a certificate chain.
				return nil, true, false
			}
			sess.expecting = frame.TotalLength
		}
		sess.inbound = append(sess.inbound, frame.Data...)
		if sess.expecting > 0 && uint64(len(sess.inbound)) > uint64(sess.expecting) {
			return nil, true, false
		}
		sess.identifier++
		ack := &EAPTLSFrame{}
		return &EAPPacket{Code: EAPRequest, Identifier: sess.identifier,
			Type: EAPTypeTLS, Data: ack.Encode()}, false, false
	}

	// Final fragment: the whole TLS message is now in hand.
	sess.inbound = append(sess.inbound, frame.Data...)
	payload := sess.inbound
	sess.inbound = nil
	sess.expecting = 0

	if len(payload) > 0 {
		sess.conn.feed(payload)
	}

	// If we still have TLS output queued, keep sending it rather than waiting
	// for more: this is the middle of a fragmented flight going out.
	if len(sess.outbound) == 0 {
		sess.outbound = sess.conn.waitOut(sess.handshakeDone, 5*time.Second)
	}

	// Nothing left to send and the handshake is over: this is the verdict.
	if len(sess.outbound) == 0 {
		select {
		case <-sess.handshakeDone:
			if sess.handshakeErr != nil {
				return nil, true, false
			}
			return nil, true, s.finishEAPTLS(sess)
		default:
			// No output, no verdict: the supplicant sent something that moved
			// nothing forward.
			return nil, true, false
		}
	}

	return s.nextFragment(sess), false, false
}

// nextFragment sends the next piece of queued TLS output.
func (s *Server) nextFragment(sess *eapSession) *EAPPacket {
	sess.identifier++

	frame := &EAPTLSFrame{}
	if len(sess.outbound) > eapTLSMaxFragment {
		// First fragment of a set declares the total; the rest do not. Sending
		// the length on every fragment is a common bug and confuses supplicants
		// that trust it.
		if sess.expecting == 0 {
			frame.LengthIncluded = true
			// A TLS flight over 4 GiB is not a TLS flight; the conversion is
			// bounded by what crypto/tls produces for a handshake.
			frame.TotalLength = uint32(len(sess.outbound)) // #nosec G115
			sess.expecting = frame.TotalLength
		}
		frame.More = true
		frame.Data = sess.outbound[:eapTLSMaxFragment]
		sess.outbound = sess.outbound[eapTLSMaxFragment:]
	} else {
		frame.Data = sess.outbound
		sess.outbound = nil
		sess.expecting = 0
	}

	return &EAPPacket{Code: EAPRequest, Identifier: sess.identifier,
		Type: EAPTypeTLS, Data: frame.Encode()}
}

// finishEAPTLS decides whether a completed handshake is an authentication.
func (s *Server) finishEAPTLS(sess *eapSession) bool {
	state := sess.tls.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		// Cannot happen with RequireAndVerifyClientCert, and checked anyway:
		// this is the single line between "a TLS handshake completed" and
		// "somebody proved who they are".
		return false
	}

	username, err := s.eapTLS.Auth.AuthenticateCertificate(state.PeerCertificates[0])
	if err != nil {
		s.log.Info("EAP-TLS certificate refused", "err", err,
			"subject", state.PeerCertificates[0].Subject.String())
		return false
	}
	sess.username = username
	return true
}

// MSK returns the master session key the access point needs.
//
// RFC 5216 §2.3: the first 64 bytes of keying material exported with the label
// "client EAP encryption". RFC 9190 changes the label for TLS 1.3, and Go's
// exporter handles the version difference underneath.
//
// Without this the supplicant authenticates and then cannot encrypt anything,
// which on wifi means the association succeeds and no traffic passes -- a
// failure that looks like a driver problem and is not.
func (sess *eapSession) MSK() ([]byte, error) {
	state := sess.tls.ConnectionState()
	label := "client EAP encryption"
	if state.Version >= tls.VersionTLS13 {
		label = "EXPORTER_EAP_TLS_Key_Material"
	}
	km, err := state.ExportKeyingMaterial(label, nil, 64)
	if err != nil {
		return nil, fmt.Errorf("exporting EAP keying material: %w", err)
	}
	return km, nil
}
