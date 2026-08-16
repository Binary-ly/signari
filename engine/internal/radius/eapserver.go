package radius

import (
	// #nosec G501 -- RFC 2548 specifies MD5 for MPPE key encoding. It is not a
	// choice: every access point in existence expects exactly this, and the
	// keys it protects live for one wireless association.
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// The EAP conversation, driven one RADIUS packet at a time.
//
// Each Access-Challenge carries a State attribute the supplicant must echo, and
// that value is how the next packet finds the half-finished TLS handshake it
// belongs to. Losing the correlation means every round trip starts a new
// handshake and the conversation never completes -- which looks exactly like a
// certificate problem and is not.

// handleEAP advances one EAP conversation.
func (s *Server) handleEAP(conn net.PacketConn, addr net.Addr, p *Packet,
	secret []byte, client Client, raw []byte) {

	eap, err := DecodeEAP(raw)
	if err != nil {
		s.log.Info("malformed EAP packet", "client", client.Name, "err", err)
		s.rejectEAP(conn, addr, p, secret, 0)
		return
	}
	if eap.Code != EAPResponse {
		// Only responses arrive here. A supplicant sending a Request is either
		// confused or probing.
		s.rejectEAP(conn, addr, p, secret, eap.Identifier)
		return
	}

	switch eap.Type {
	case EAPTypeIdentity:
		// The identity is advisory and is NOT the authentication. RFC 5216 is
		// explicit: the identity in this packet is unauthenticated, and the name
		// that matters is the one in the certificate. It is logged for
		// operators and never used to decide anything.
		s.log.Debug("EAP identity", "client", client.Name, "identity", string(eap.Data))

		if s.eapTLS == nil {
			// No EAP-TLS configured. Refused rather than offered a password
			// method: a supplicant that asked for certificates and is answered
			// with MD5 has been downgraded to a method this server does not
			// implement anyway.
			s.log.Info("EAP requested but EAP-TLS is not configured", "client", client.Name)
			s.rejectEAP(conn, addr, p, secret, eap.Identifier)
			return
		}

		sess, req, err := s.startEAPTLS(eap.Identifier + 1)
		if err != nil {
			s.rejectEAP(conn, addr, p, secret, eap.Identifier)
			return
		}
		s.sessions.put(sess)
		s.challenge(conn, addr, p, secret, sess, req)

	case EAPTypeTLS:
		state, ok := p.Attr(AttrState)
		if !ok {
			s.rejectEAP(conn, addr, p, secret, eap.Identifier)
			return
		}
		sess, ok := s.sessions.get(string(state))
		if !ok {
			// Unknown or expired. The supplicant starts again; saying more would
			// tell an attacker which State values exist.
			s.log.Debug("EAP-TLS response for an unknown session", "client", client.Name)
			s.rejectEAP(conn, addr, p, secret, eap.Identifier)
			return
		}

		next, done, ok := s.continueEAPTLS(sess, eap)
		switch {
		case !done:
			s.challenge(conn, addr, p, secret, sess, next)
		case ok:
			s.acceptEAP(conn, addr, p, secret, sess, eap.Identifier)
			s.sessions.drop(sess.state)
		default:
			s.log.Info("EAP-TLS authentication failed", "client", client.Name)
			s.rejectEAP(conn, addr, p, secret, eap.Identifier)
			s.sessions.drop(sess.state)
		}

	case EAPTypeNak:
		// The supplicant refuses the method offered. Nothing else is on offer.
		s.log.Info("supplicant refused EAP-TLS", "client", client.Name)
		s.rejectEAP(conn, addr, p, secret, eap.Identifier)

	default:
		s.rejectEAP(conn, addr, p, secret, eap.Identifier)
	}
}

// challenge answers Access-Challenge with the next EAP request.
func (s *Server) challenge(conn net.PacketConn, addr net.Addr, p *Packet,
	secret []byte, sess *eapSession, eap *EAPPacket) {

	attrs := EAPAttributes(eap.Encode())
	attrs = append(attrs, Attribute{Type: AttrState, Value: []byte(sess.state)})

	out, err := Response(p, CodeAccessChallenge, secret, attrs)
	if err != nil {
		s.log.Error("building an EAP challenge", "err", err)
		return
	}
	_, _ = conn.WriteTo(out, addr)
}

// acceptEAP answers Access-Accept with EAP-Success and the session keys.
func (s *Server) acceptEAP(conn net.PacketConn, addr net.Addr, p *Packet,
	secret []byte, sess *eapSession, id byte) {

	attrs := EAPAttributes((&EAPPacket{Code: EAPSuccess, Identifier: id}).Encode())

	// The user's real name comes from the certificate, not from the identity the
	// supplicant announced. An access point that logs or authorises on
	// User-Name would otherwise be acting on an unauthenticated string.
	if sess.username != "" {
		attrs = append(attrs, Attribute{Type: AttrUserName, Value: []byte(sess.username)})
	}

	// The keys, without which the supplicant authenticates and then cannot
	// encrypt: on wifi the association succeeds and no traffic passes, which
	// looks like a driver fault and is not.
	msk, err := sess.MSK()
	if err != nil {
		s.log.Error("deriving EAP keying material", "err", err)
		s.rejectEAP(conn, addr, p, secret, id)
		return
	}
	keys, err := mppeKeyAttributes(msk, secret, p.Authenticator[:])
	if err != nil {
		s.log.Error("encoding MPPE keys", "err", err)
		s.rejectEAP(conn, addr, p, secret, id)
		return
	}
	attrs = append(attrs, keys...)

	out, err := Response(p, CodeAccessAccept, secret, attrs)
	if err != nil {
		return
	}
	s.log.Info("EAP-TLS authentication succeeded", "username", sess.username)
	_, _ = conn.WriteTo(out, addr)
}

// rejectEAP answers Access-Reject carrying EAP-Failure.
//
// The EAP-Failure matters: a supplicant that receives Access-Reject with no EAP
// packet inside retries the whole conversation, often several times, before
// giving up. With it, it stops and shows the user an authentication failure.
func (s *Server) rejectEAP(conn net.PacketConn, addr net.Addr, p *Packet,
	secret []byte, id byte) {

	attrs := EAPAttributes((&EAPPacket{Code: EAPFailure, Identifier: id}).Encode())
	out, err := Response(p, CodeAccessReject, secret, attrs)
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(out, addr)
}

// MPPE key encoding (RFC 2548 §2.4.2 and §2.4.3).
//
// Microsoft's vendor attributes, and the only way to hand session keys to an
// access point. The encryption is MD5-based and dated; it is not a choice, it
// is what every access point in existence expects, and the keys it protects
// live for one association.
const (
	vendorMicrosoft   = 311
	vendorTypeSendKey = 16
	vendorTypeRecvKey = 17
)

// errNotEnoughKeyMaterial means the TLS exporter gave us less than EAP needs.
var errNotEnoughKeyMaterial = errors.New("EAP keying material is shorter than 64 bytes")

func mppeKeyAttributes(msk, secret, requestAuthenticator []byte) ([]Attribute, error) {
	if len(msk) < 64 {
		return nil, errNotEnoughKeyMaterial
	}
	// RFC 5216 §2.3: the peer's receive key is the FIRST half and its send key
	// the second, which is the opposite way round from the attribute names --
	// they are written from the access point's point of view. Swapping them
	// produces a supplicant that associates and then cannot decrypt anything.
	recvKey := msk[:32]
	sendKey := msk[32:64]

	send, err := encodeMPPEKey(vendorTypeSendKey, sendKey, secret, requestAuthenticator)
	if err != nil {
		return nil, err
	}
	recv, err := encodeMPPEKey(vendorTypeRecvKey, recvKey, secret, requestAuthenticator)
	if err != nil {
		return nil, err
	}
	return []Attribute{send, recv}, nil
}

// encodeMPPEKey builds one vendor-specific attribute holding an encrypted key.
func encodeMPPEKey(vendorType byte, key, secret, requestAuthenticator []byte) (
	Attribute, error) {

	// A two-byte salt with the top bit set, per the RFC. It must differ between
	// the two keys in one packet, which random bytes give us.
	var salt [2]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return Attribute{}, err
	}
	salt[0] |= 0x80

	// The plaintext is a length byte followed by the key, padded to a multiple
	// of 16.
	// A RADIUS attribute's length is one byte, and the key length prefix is one
	// byte, so a key over 255 bytes cannot be encoded at all. MSK halves are 32
	// bytes; anything else is a caller error rather than something to truncate.
	if len(key) > 255 {
		return Attribute{}, fmt.Errorf("MPPE key is %d bytes, maximum is 255", len(key))
	}
	plain := make([]byte, 1+len(key))
	plain[0] = byte(len(key)) // #nosec G115 -- bounded above
	copy(plain[1:], key)
	if pad := len(plain) % 16; pad != 0 {
		plain = append(plain, make([]byte, 16-pad)...)
	}

	// c(1) = p(1) xor MD5(secret + requestAuthenticator + salt)
	// c(n) = p(n) xor MD5(secret + c(n-1))
	cipher := make([]byte, 0, len(plain))
	prev := append(append([]byte(nil), requestAuthenticator...), salt[:]...)
	for i := 0; i < len(plain); i += 16 {
		h := md5.New() // #nosec G401 -- RFC 2548 specifies MD5; every access point expects it
		h.Write(secret)
		h.Write(prev)
		b := h.Sum(nil)

		block := make([]byte, 16)
		for j := 0; j < 16; j++ {
			block[j] = plain[i+j] ^ b[j]
		}
		cipher = append(cipher, block...)
		prev = block
	}

	// Vendor-Specific: 4 bytes of vendor id, then type, length, salt, cipher.
	value := make([]byte, 0, 4+2+2+len(cipher))
	var vid [4]byte
	binary.BigEndian.PutUint32(vid[:], vendorMicrosoft)
	value = append(value, vid[:]...)
	// 4 vendor id + 2 header + 2 salt + cipher must fit in one attribute (255
	// bytes including its own type and length).
	if 6+2+len(cipher) > 253 {
		return Attribute{}, fmt.Errorf("MPPE attribute would be %d bytes, over the "+
			"253 a RADIUS attribute can carry", 6+2+len(cipher))
	}
	value = append(value, vendorType, byte(2+2+len(cipher))) // #nosec G115 -- bounded above
	value = append(value, salt[:]...)
	value = append(value, cipher...)

	return Attribute{Type: AttrVendorSpecific, Value: value}, nil
}
