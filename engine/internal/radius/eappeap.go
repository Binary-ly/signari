package radius

import (
	"context"
	"encoding/binary"
	"errors"
	"time"
)

// PEAPv0 with EAP-GTC inside (7.08, specs/ms-peap.txt, specs/rfc3748.txt §5.6).
//
// The first phase is EAP-TLS's handshake under type 25 (MS-PEAP §3.1.5.4), the
// server's certificate the only one, with the tunnel's settings (eaptunnel.go): TLS
// 1.2 and nothing kept to resume, so fast reconnect never happens and every
// connection asks for the password. The second phase is inner EAP inside the
// tunnel, the server asking (§3.3.7.1):
//
//  1. an Identity request, compressed, as every inner packet but the TLV method's
//     is: no Code, Identifier or Length, which the outer packet supplies (§3.1.5.6);
//  2. a GTC request, whose response is what the person typed (RFC 3748 §5.6),
//     checked through the same Authenticator as a PAP request; a second one for a
//     code when the password was right and a code is needed, which is the use GTC
//     was made for;
//  3. the TLV Extensions method with a Result TLV, Success or Failure, uncompressed
//     (§2.2.8.1, §3.3.7.3, §3.3.7.4), and the peer's own Result back;
//  4. EAP-Success or EAP-Failure, outside the tunnel (§3.1.5.6, :2091-2102).
//
// GTC exists for token cards, and "MUST NOT be used to provide support for
// cleartext passwords in the absence of a protected tunnel with server
// authentication" (RFC 3748 §5.6); PEAP's tunnel is that. MSCHAPv2, the inner method
// Windows offers by itself, needs the password's NT hash, which nothing here keeps.
//
// No cryptobinding: §3.1.5.5 makes it optional (MAY), and without it the access
// point's keys are EAP-TLS's own, the first 64 octets of "client EAP encryption"
// keying material, the server's Recv-Key first (§3.1.5.7, :2151-2170), which is what
// MSK and mppeKeyAttributes already give.

type peapStep int

const (
	peapEstablished peapStep = iota
	peapIdentitySent
	peapPasswordSent
	peapCodeSent
	peapResultSent
	peapFailureSent
)

// gtcPrompt is the GTC request's displayable message.
const gtcPrompt = "Password"

// PEAP TLVs (§2.2.4): an M bit, a reserved bit, a 14-bit type and a 16-bit length.
const (
	tlvMandatory  = 0x8000
	tlvTypeResult = 3
	tlvSuccess    = 1
	tlvFailure    = 2
)

// peapPhase2 runs the second phase, one response at a time.
func (s *Server) peapPhase2(ctx context.Context, sess *eapSession) (*EAPPacket, bool, bool) {
	switch sess.peap {
	case peapEstablished:
		// The peer's answer to the server's Finished, an acknowledgement. The server
		// asks first in PEAP.
		sess.peap = peapIdentitySent
		return s.peapSend(sess, []byte{EAPTypeIdentity})

	case peapIdentitySent:
		in, ok := readTunnel(sess, 2*time.Second)
		if !ok || len(in) < 1 || in[0] != EAPTypeIdentity {
			return s.peapResult(sess, false)
		}
		// The name inside the tunnel is the one that counts; the outer Identity is
		// commonly "anonymous" (RFC 5281 §7.3 says why, and PEAP peers do the same).
		sess.inner = string(in[1:])
		sess.peap = peapPasswordSent
		return s.peapSend(sess, append([]byte{EAPTypeGTC}, gtcPrompt...))

	case peapPasswordSent, peapCodeSent:
		in, ok := readTunnel(sess, 2*time.Second)
		if !ok || len(in) < 1 {
			return s.peapResult(sess, false)
		}
		if in[0] == EAPTypeNak {
			// RFC 3748 §5.6: the peer would rather another method, and there is none.
			s.log.Info("PEAP peer refused EAP-GTC", "wants", in[1:])
			return s.peapResult(sess, false)
		}
		if in[0] != EAPTypeGTC || len(in) < 2 || sess.inner == "" {
			return s.peapResult(sess, false)
		}
		answer := string(in[1:])
		if sess.peap == peapCodeSent {
			v, ok := s.auth.(CodeVerifier)
			return s.peapResult(sess, ok && v.VerifyCode(ctx, sess.inner, answer) == nil)
		}
		err := s.auth.Authenticate(ctx, sess.inner, answer)
		if errors.Is(err, ErrSecondFactor) {
			if _, ok := s.auth.(CodeVerifier); ok {
				sess.peap = peapCodeSent
				return s.peapSend(sess, append([]byte{EAPTypeGTC}, codePrompt...))
			}
		}
		if err != nil {
			s.log.Info("PEAP password refused", "err", err)
		}
		return s.peapResult(sess, err == nil)

	case peapResultSent, peapFailureSent:
		// The peer's TLV packet, uncompressed, carrying its own Result (§3.3.5.4.7).
		in, ok := readTunnel(sess, 2*time.Second)
		if !ok {
			return nil, true, false
		}
		result, ok := peapPeerResult(in)
		if !ok || sess.peap == peapFailureSent || result != tlvSuccess {
			return nil, true, false
		}
		sess.username = sess.inner
		return nil, true, true
	}
	return nil, true, false
}

// peapResult sends the TLV Extensions method with a Result TLV (§2.2.8.1.2). It is
// a full EAP packet, the compression of §3.1.5.6 not applying to it, carrying the
// Identifier of the outer request it goes in.
func (s *Server) peapResult(sess *eapSession, success bool) (*EAPPacket, bool, bool) {
	value := uint16(tlvFailure)
	sess.peap = peapFailureSent
	if success {
		value = tlvSuccess
		sess.peap = peapResultSent
	}
	tlv := make([]byte, 6)
	binary.BigEndian.PutUint16(tlv[0:2], tlvMandatory|tlvTypeResult)
	binary.BigEndian.PutUint16(tlv[2:4], 2)
	binary.BigEndian.PutUint16(tlv[4:6], value)
	inner := &EAPPacket{Code: EAPRequest, Identifier: sess.identifier + 1, Type: EAPTypeTLVExtensions, Data: tlv}
	return s.peapSend(sess, inner.Encode())
}

// peapSend puts an inner packet into the tunnel and sends what TLS made of it.
func (s *Server) peapSend(sess *eapSession, inner []byte) (*EAPPacket, bool, bool) {
	if _, err := sess.tls.Write(inner); err != nil {
		return nil, true, false
	}
	sess.outbound = sess.conn.take()
	if len(sess.outbound) == 0 {
		return nil, true, false
	}
	return s.nextFragment(sess), false, false
}

// peapPeerResult reads the peer's TLV Extensions response and its Result TLV. A TLV
// it does not know marked mandatory means the packet is discarded (§2.2.4), which
// here is the conversation failing.
func peapPeerResult(in []byte) (uint16, bool) {
	p, err := DecodeEAP(in)
	if err != nil || p.Code != EAPResponse || p.Type != EAPTypeTLVExtensions {
		return 0, false
	}
	var result uint16
	found := false
	for b := p.Data; len(b) > 0; {
		if len(b) < 4 {
			return 0, false
		}
		head, length := binary.BigEndian.Uint16(b[0:2]), int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+length {
			return 0, false
		}
		value := b[4 : 4+length]
		switch head & 0x3fff {
		case tlvTypeResult:
			if length != 2 {
				return 0, false
			}
			result, found = binary.BigEndian.Uint16(value), true
		default:
			if head&tlvMandatory != 0 {
				return 0, false
			}
		}
		b = b[4+length:]
	}
	return result, found
}

// readTunnel waits for what the peer sent inside the tunnel: one inner packet, in
// one record, from one EAP response.
func readTunnel(sess *eapSession, wait time.Duration) ([]byte, bool) {
	select {
	case b, open := <-sess.app:
		return b, open
	case <-time.After(wait):
		return nil, false
	}
}
