// Package radius implements the subset of RFC 2865 needed to authenticate
// people against network equipment.
//
// # Built around CVE-2024-3596 (Blast-RADIUS)
//
// The protocol authenticates responses with an MD5 "Response Authenticator".
// MD5 chosen-prefix collisions are practical, and the published attack turns
// that into forgery: an attacker positioned on the path can take a real
// Access-Reject and turn it into an Access-Accept. The NVD entry puts it
// plainly -- "susceptible to forgery attacks by a local attacker who can modify
// any valid Response ... using a chosen-prefix collision attack against MD5
// Response Authenticator signature."
//
// The published short-term mitigation is to "mandate that clients and servers
// always send and require Message-Authenticator attributes for all requests and
// responses", with the attribute placed FIRST in accept and reject responses.
// Message-Authenticator is HMAC-MD5, and HMAC is not affected by the collision
// attacks that break bare MD5.
//
// So this server:
//
//   - REFUSES an Access-Request that carries no Message-Authenticator. Not a
//     warning, not a setting: a request without it cannot be authenticated, and
//     accepting it is the vulnerability.
//   - Always emits Message-Authenticator, first, in every response.
//
// The real answer is RADIUS over TLS (RFC 6614), which removes the attacker's
// position entirely. That is a deployment decision, and it is what the
// documentation recommends.
package radius

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- RFC 2865 specifies MD5. See the package comment.
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// Packet codes (RFC 2865 §3).
const (
	CodeAccessRequest   = 1
	CodeAccessAccept    = 2
	CodeAccessReject    = 3
	CodeAccessChallenge = 11
)

// Attribute types we handle.
const (
	AttrUserName             = 1
	AttrUserPassword         = 2
	AttrNASIPAddress         = 4
	AttrNASPort              = 5
	AttrReplyMessage         = 18
	AttrNASIdentifier        = 32
	AttrMessageAuthenticator = 80
)

const (
	headerLen = 20
	authLen   = 16
	maxPacket = 4096
	// minSecretLen is enforced at configuration time. The shared secret is the
	// only thing standing between a network device and an authentication oracle,
	// and RADIUS gives an attacker offline material to grind against it.
	minSecretLen = 16
)

// Attribute is one type-value pair.
type Attribute struct {
	Type  byte
	Value []byte
}

// Packet is a decoded RADIUS packet.
type Packet struct {
	Code          byte
	Identifier    byte
	Authenticator [authLen]byte
	Attributes    []Attribute
	// raw is the packet as received, needed to verify Message-Authenticator over
	// the exact bytes rather than a re-encoding of them.
	raw []byte
}

// Decode parses a packet.
func Decode(b []byte) (*Packet, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("packet is %d bytes, shorter than a header", len(b))
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < headerLen || length > maxPacket {
		return nil, fmt.Errorf("declared length %d is out of range", length)
	}
	if len(b) < length {
		// The declared length exceeds what arrived. Trusting the declaration and
		// reading on is how a length field becomes a read past the buffer.
		return nil, fmt.Errorf("packet declares %d bytes, %d arrived", length, len(b))
	}
	b = b[:length]

	p := &Packet{Code: b[0], Identifier: b[1], raw: b}
	copy(p.Authenticator[:], b[4:20])

	for i := headerLen; i < length; {
		if i+2 > length {
			return nil, fmt.Errorf("truncated attribute header")
		}
		attrType, attrLen := b[i], int(b[i+1])
		if attrLen < 2 {
			// A zero or one length would not advance the cursor: the loop would
			// spin forever on a malformed packet an attacker sends once.
			return nil, fmt.Errorf("attribute %d declares length %d", attrType, attrLen)
		}
		if i+attrLen > length {
			return nil, fmt.Errorf("attribute %d runs past the end of the packet", attrType)
		}
		p.Attributes = append(p.Attributes, Attribute{
			Type: attrType, Value: append([]byte(nil), b[i+2:i+attrLen]...),
		})
		i += attrLen
	}
	return p, nil
}

// Attr returns the first attribute of a type.
//
// FIRST, deliberately. A packet carrying two User-Name attributes is malformed,
// and taking the last would let an attacker append one that overrides whatever
// the device sent.
func (p *Packet) Attr(t byte) ([]byte, bool) {
	for _, a := range p.Attributes {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// Count returns how many attributes of a type are present.
func (p *Packet) Count(t byte) int {
	n := 0
	for _, a := range p.Attributes {
		if a.Type == t {
			n++
		}
	}
	return n
}

// VerifyMessageAuthenticator checks the HMAC-MD5 over the packet.
//
// # Why this is mandatory here
//
// It is the whole mitigation for CVE-2024-3596. The Response Authenticator is
// bare MD5 and forgeable by collision; Message-Authenticator is HMAC-MD5, which
// is not. A request without it cannot be authenticated at all, so this returns
// an error rather than a "not present, carry on".
//
// The HMAC is computed over the packet with the Message-Authenticator VALUE
// zeroed but its header left in place -- the attribute is part of the length it
// signs.
func (p *Packet) VerifyMessageAuthenticator(secret []byte) error {
	// For a REQUEST the authenticator in the packet is the one the HMAC was
	// computed over, so it verifies against itself.
	return p.VerifyMessageAuthenticatorWith(secret, p.Authenticator[:])
}

// VerifyMessageAuthenticatorWith checks the HMAC against a supplied
// authenticator.
//
// # Why a response needs this and a request does not
//
// RFC 3579 §3.2: in a RESPONSE, Message-Authenticator is computed over the
// packet carrying the REQUEST authenticator -- and the sender then overwrites
// those same sixteen bytes with the Response Authenticator before transmitting.
// So a receiver cannot verify a response from the response alone; it has to
// substitute back the request authenticator it sent.
//
// Verifying a response against its own bytes fails every time. That is not a
// theoretical distinction: it is what network equipment does, and getting it
// wrong means every Access-Accept we send is discarded by the device that asked.
// Caught here by round-tripping our own response through our own verifier.
func (p *Packet) VerifyMessageAuthenticatorWith(secret, requestAuthenticator []byte) error {
	if p.Count(AttrMessageAuthenticator) == 0 {
		return fmt.Errorf("the request carries no Message-Authenticator, so it cannot " +
			"be authenticated (CVE-2024-3596); configure the device to send one")
	}
	if p.Count(AttrMessageAuthenticator) > 1 {
		// Two of them leaves which one was verified up to the parser, and lets an
		// attacker append a second that validates while the first is acted on.
		return fmt.Errorf("the request carries more than one Message-Authenticator")
	}
	got, _ := p.Attr(AttrMessageAuthenticator)
	if len(got) != 16 {
		return fmt.Errorf("Message-Authenticator is %d bytes, expected 16", len(got))
	}

	zeroed := p.withZeroedMessageAuthenticator()
	if len(requestAuthenticator) == authLen {
		copy(zeroed[4:20], requestAuthenticator)
	}
	// #nosec G401 -- HMAC-MD5 is what RFC 3579 specifies for this attribute, and
	// HMAC is unaffected by the MD5 collision attacks that motivate its use.
	mac := hmac.New(md5.New, secret)
	mac.Write(zeroed)
	want := mac.Sum(nil)

	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("Message-Authenticator did not verify")
	}
	return nil
}

// withZeroedMessageAuthenticator rebuilds the packet bytes with the attribute's
// value set to zero, which is what the HMAC is computed over.
func (p *Packet) withZeroedMessageAuthenticator() []byte {
	out := append([]byte(nil), p.raw...)
	for i := headerLen; i+2 <= len(out); {
		attrLen := int(out[i+1])
		if attrLen < 2 || i+attrLen > len(out) {
			break
		}
		if out[i] == AttrMessageAuthenticator {
			for j := i + 2; j < i+attrLen; j++ {
				out[j] = 0
			}
		}
		i += attrLen
	}
	return out
}

// DecodePassword recovers the User-Password (RFC 2865 §5.2).
//
// The obfuscation is an MD5 keystream XORed with the password. It is weak by any
// modern standard -- it is not encryption and offers no integrity -- which is
// exactly why the shared secret has a length floor and why the documentation
// pushes RADIUS over TLS.
func (p *Packet) DecodePassword(secret []byte) (string, error) {
	ct, ok := p.Attr(AttrUserPassword)
	if !ok {
		return "", fmt.Errorf("no User-Password attribute")
	}
	if len(ct) == 0 || len(ct)%16 != 0 || len(ct) > 128 {
		return "", fmt.Errorf("User-Password is %d bytes, which is not a valid length", len(ct))
	}

	out := make([]byte, 0, len(ct))
	prev := p.Authenticator[:]
	for i := 0; i < len(ct); i += 16 {
		// #nosec G401 -- RFC 2865 §5.2 specifies this construction exactly.
		h := md5.New()
		h.Write(secret)
		h.Write(prev)
		key := h.Sum(nil)

		block := make([]byte, 16)
		for j := 0; j < 16; j++ {
			block[j] = ct[i+j] ^ key[j]
		}
		out = append(out, block...)
		prev = ct[i : i+16]
	}

	// Trailing NULs are padding, not password. Trimming from the right only:
	// a NUL in the middle is somebody's actual byte and removing it would change
	// the credential being checked.
	for len(out) > 0 && out[len(out)-1] == 0 {
		out = out[:len(out)-1]
	}
	return string(out), nil
}

// Response builds a reply.
//
// Message-Authenticator goes FIRST, which is what the Blast-RADIUS guidance
// specifies for accept and reject responses. Its value is computed after the
// packet is otherwise assembled, then written back in place -- the HMAC covers
// the whole packet including its own zeroed slot.
func Response(req *Packet, code byte, secret []byte, extra []Attribute) ([]byte, error) {
	attrs := make([]Attribute, 0, len(extra)+1)
	attrs = append(attrs, Attribute{Type: AttrMessageAuthenticator, Value: make([]byte, 16)})
	attrs = append(attrs, extra...)

	body := make([]byte, 0, 64)
	for _, a := range attrs {
		if len(a.Value) > 253 {
			return nil, fmt.Errorf("attribute %d is %d bytes, over the limit",
				a.Type, len(a.Value))
		}
		// #nosec G115 -- bounded two lines above: an attribute over 253 bytes is
		// refused, so the length always fits the single byte the wire format has.
		body = append(body, a.Type, byte(len(a.Value)+2))
		body = append(body, a.Value...)
	}

	length := headerLen + len(body)
	if length > maxPacket {
		return nil, fmt.Errorf("response would be %d bytes", length)
	}
	pkt := make([]byte, headerLen, length)
	pkt[0] = code
	pkt[1] = req.Identifier
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
	// The REQUEST authenticator goes here while both MACs are computed; the
	// Response Authenticator replaces it at the end.
	copy(pkt[4:20], req.Authenticator[:])
	pkt = append(pkt, body...)

	// Message-Authenticator over the packet with its own value zeroed, which is
	// the state it is in right now.
	mac := hmac.New(md5.New, secret) // #nosec G401 -- RFC 3579
	mac.Write(pkt)
	copy(pkt[headerLen+2:headerLen+18], mac.Sum(nil))

	// Response Authenticator = MD5(code+id+len+RequestAuth+attributes+secret).
	// Computed last, over a packet that now contains a valid HMAC.
	// #nosec G401 -- RFC 2865 §3 specifies MD5 here; the HMAC above is what
	// actually defends the response.
	h := md5.New()
	h.Write(pkt)
	h.Write(secret)
	copy(pkt[4:20], h.Sum(nil))

	return pkt, nil
}

// ValidSecret reports whether a shared secret is long enough to be worth having.
func ValidSecret(s string) error {
	if len(s) < minSecretLen {
		return fmt.Errorf("the shared secret is %d characters; at least %d are required. "+
			"RADIUS hands an attacker material to grind offline, and this secret is the "+
			"only thing between a network device and an authentication oracle",
			len(s), minSecretLen)
	}
	return nil
}
