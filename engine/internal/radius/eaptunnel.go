package radius

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// EAP-TTLS with PAP inside (7.08, specs/rfc5281.txt).
//
// The handshake proves the server and nobody else: the supplicant checks this
// certificate, and then sends the person's name and password as AVPs inside the
// tunnel (§7.2, §11.2.5), which go to the same Authenticator as a PAP request. So
// the password is protected by a TLS session the supplicant authenticated, not by
// the RADIUS shared secret, and it is checked against the person's own credential
// here, which is what a password method needs and EAP-TLS cannot offer someone
// with no certificate.
//
// Two choices the RFC forces:
//
//   - No resumption. A resumed TTLS session skips the second phase, the master
//     secret standing in for the password (§7.5, :880-883), and a server "MUST NOT
//     permit a session to be resumed if that session did not result in a
//     successful authentication of the user during phase 2" (:913-919), with a note
//     that TLS toolkits cache sessions on their own (:921-925). Here nothing is
//     cached at all, so every conversation asks for the password, and a person
//     deactivated since is refused the next time.
//   - TLS 1.2 only. The keying material is the TLS PRF of §8, defined over a TLS
//     1.2 master secret; how a tunnel derives it under TLS 1.3 is another document,
//     not followed here, and a key the access point and the supplicant derive
//     differently is an association that carries no traffic.

// EAPTunnelConfig is what the tunnelled methods need, and which of them are on.
type EAPTunnelConfig struct {
	// Certificate is the server's, which supplicants verify before sending a
	// password. It can be EAP-TLS's own.
	Certificate tls.Certificate
	// TTLS turns on EAP-TTLS with PAP inside, PEAP turns on PEAPv0 with EAP-GTC
	// inside (eappeap.go).
	TTLS, PEAP bool
}

// tunnelTLSConfig is the tunnel's TLS: the server's certificate, no client
// certificate asked for, TLS 1.2, and nothing kept to resume.
func tunnelTLSConfig(c *EAPTunnelConfig) *tls.Config {
	return &tls.Config{
		Certificates:           []tls.Certificate{c.Certificate},
		ClientAuth:             tls.NoClientCert,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
}

// startTunnel begins an EAP-TTLS or PEAP conversation.
func (s *Server) startTunnel(id, method byte) (*eapSession, *EAPPacket, error) {
	if !s.tunnelOn(method) {
		return nil, nil, fmt.Errorf("EAP type %d is not configured", method)
	}
	return s.startTLSMethod(id, method, s.tunnelConfig)
}

// tunnelOn reports whether a tunnelled method is on.
func (s *Server) tunnelOn(method byte) bool {
	t := s.cfg.EAPTunnels
	return t != nil && s.tunnelConfig != nil &&
		(method == EAPTypeTTLS && t.TTLS || method == EAPTypePEAP && t.PEAP)
}

// AVP codes: the RADIUS attributes of the same numbers (§10.1, RFC 2865 §5).
const (
	avpUserName     = 1
	avpUserPassword = 2
	avpFlagVendor   = 0x80
	avpFlagMust     = 0x40
)

type tunnelAVP struct {
	code   uint32
	flags  byte
	vendor uint32
	data   []byte
}

// errAVPShort is a sequence whose last AVP has not all arrived.
var errAVPShort = errors.New("the AVP sequence is not complete")

// parseAVPs reads a sequence of AVPs (§10.1, §10.2): code, flags, a three-octet
// length counting the header and the data and not the padding, a Vendor-ID when the
// V bit is set, and each AVP padded to four octets.
func parseAVPs(b []byte) ([]tunnelAVP, error) {
	var out []tunnelAVP
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errAVPShort
		}
		a := tunnelAVP{code: binary.BigEndian.Uint32(b[0:4]), flags: b[4]}
		length := int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		header := 8
		if a.flags&avpFlagVendor != 0 {
			header = 12
		}
		if length < header {
			return nil, fmt.Errorf("an AVP of %d octets is shorter than its own header", length)
		}
		if len(b) < length {
			return nil, errAVPShort
		}
		if header == 12 {
			a.vendor = binary.BigEndian.Uint32(b[8:12])
		}
		a.data = b[header:length]
		out = append(out, a)
		padded := (length + 3) &^ 3
		if padded > len(b) {
			// The last AVP's padding may be left off; nothing follows it.
			padded = len(b)
		}
		b = b[padded:]
	}
	return out, nil
}

// continueTunnel is an EAP-TTLS conversation once its response is whole: the
// handshake while it lasts, then the person's AVPs.
func (s *Server) continueTunnel(ctx context.Context, sess *eapSession, payload []byte) (*EAPPacket, bool, bool) {
	if len(payload) > 0 {
		sess.conn.feed(payload)
	}
	// The rest of a flight going out: the supplicant has acknowledged a fragment.
	if len(sess.outbound) > 0 {
		return s.nextFragment(sess), false, false
	}
	if !isClosed(sess.handshakeDone) {
		sess.outbound = sess.conn.waitOut(sess.handshakeDone, 5*time.Second)
		if len(sess.outbound) > 0 {
			return s.nextFragment(sess), false, false
		}
		if !isClosed(sess.handshakeDone) {
			// Nothing came of it: the response moved the handshake nowhere.
			return nil, true, false
		}
	}
	if sess.handshakeErr != nil {
		return nil, true, false
	}
	if sess.app == nil {
		sess.app = make(chan []byte, 16)
		go tunnelReader(sess)
	}
	if sess.method == EAPTypePEAP {
		return s.peapPhase2(ctx, sess)
	}

	// The second phase. The client goes first (§7.6), with its AVPs after the
	// server's Finished; an acknowledgement with none is a client with nothing to
	// say, and a tunnel that proved only the server has authenticated nobody.
	avps, ok := readAVPs(sess, 2*time.Second)
	if !ok {
		return nil, true, false
	}
	var username, password []byte
	for _, a := range avps {
		switch {
		case a.vendor == 0 && a.code == avpUserName:
			username = a.data
		case a.vendor == 0 && a.code == avpUserPassword:
			// §11.2.5 (:1777-1778): the client SHOULD null-pad the password to a
			// multiple of sixteen octets to hide its length.
			password = bytes.TrimRight(a.data, "\x00")
		case a.flags&avpFlagMust != 0:
			// §10.1 (:1323-1329): an AVP the server does not understand with the M
			// bit set fails the negotiation.
			s.log.Info("EAP-TTLS AVP that must be understood and is not", "code", a.code, "vendor", a.vendor)
			return nil, true, false
		}
	}
	if len(username) == 0 || len(password) == 0 {
		s.log.Info("EAP-TTLS second phase without a name and a password")
		return nil, true, false
	}
	err := s.auth.Authenticate(ctx, string(username), string(password))
	switch {
	case err == nil:
		sess.username = string(username)
		return nil, true, true
	case errors.Is(err, ErrSecondFactor):
		// The person also gives a code, and this asks for none inside the tunnel;
		// the Authenticator reads one typed after the password, `password;123456`.
		s.log.Info("EAP-TTLS password right, and a code is needed: it can be typed after the password, " +
			"separated by a semicolon")
	default:
		s.log.Info("EAP-TTLS password refused", "err", err)
	}
	return nil, true, false
}

// tunnelReader reads what the supplicant sends inside the tunnel, until the
// session is dropped and its pipe closed.
func tunnelReader(sess *eapSession) {
	defer close(sess.app)
	buf := make([]byte, 16<<10)
	for {
		n, err := sess.tls.Read(buf)
		if n > 0 {
			sess.app <- append([]byte(nil), buf[:n]...)
		}
		if err != nil {
			return
		}
	}
}

// readAVPs waits for a whole AVP sequence from the tunnel. A sequence arrives in
// one EAP response, reassembled before it was fed, so what it holds is all there
// will be: after the first record the wait is short.
func readAVPs(sess *eapSession, wait time.Duration) ([]tunnelAVP, bool) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case b, open := <-sess.app:
			if !open {
				return nil, false
			}
			sess.appBuf = append(sess.appBuf, b...)
			if len(sess.appBuf) > maxReassembly {
				return nil, false
			}
			avps, err := parseAVPs(sess.appBuf)
			if err == nil {
				sess.appBuf = nil
				return avps, true
			}
			if !errors.Is(err, errAVPShort) {
				return nil, false
			}
			timer.Reset(200 * time.Millisecond)
		case <-timer.C:
			return nil, false
		}
	}
}

// eapMethodName is a method's name, for the log.
func eapMethodName(method byte) string {
	switch method {
	case EAPTypeTTLS:
		return "EAP-TTLS"
	case EAPTypePEAP:
		return "PEAP"
	}
	return "EAP-TLS"
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
