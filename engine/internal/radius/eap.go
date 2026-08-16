package radius

import (
	"encoding/binary"
	"fmt"
)

// EAP over RADIUS (RFC 3579), the transport EAP-TLS runs on.
//
// # Two layers of fragmentation, and they are not the same fragmentation
//
// This is where implementations go wrong, because the word means two different
// things one inside the other:
//
//	RADIUS   an attribute carries at most 253 bytes, so ONE EAP packet is split
//	         across as many consecutive EAP-Message attributes as it needs. The
//	         receiver concatenates them in order. This is pure transport and the
//	         EAP layer never sees it.
//
//	EAP-TLS  a TLS handshake flight is far larger than one EAP packet, so the
//	         EAP-TLS layer splits it across several EAP packets, each a separate
//	         request/response round trip with the supplicant, using the M (more)
//	         flag. See eaptls.go.
//
// Treating either as the other produces a server that works with one supplicant
// and not another: small certificates fit in a single fragment and hide the bug
// entirely, so it appears the first time somebody deploys a real certificate
// chain.

const (
	// AttrState correlates the round trips of one conversation (RFC 2865 §5.24).
	AttrState = 24
	// AttrEAPMessage carries EAP, split across as many attributes as needed
	// (RFC 3579 §3.1).
	AttrEAPMessage = 79
	// AttrVendorSpecific carries the MPPE keys the access point needs.
	AttrVendorSpecific = 26
)

// EAP codes (RFC 3748 §4).
const (
	EAPRequest  = 1
	EAPResponse = 2
	EAPSuccess  = 3
	EAPFailure  = 4
)

// EAP method types.
const (
	EAPTypeIdentity = 1
	EAPTypeNotify   = 2
	EAPTypeNak      = 3
	EAPTypeMD5      = 4
	EAPTypeTLS      = 13
)

// maxEAPMessageChunk is what one RADIUS attribute can hold: 255 total, less the
// type and length bytes.
const maxEAPMessageChunk = 253

// EAPPacket is one EAP message.
type EAPPacket struct {
	Code       byte
	Identifier byte
	// Type is meaningful for Request and Response only. Success and Failure
	// carry no type and no data at all.
	Type byte
	Data []byte
}

// DecodeEAP parses one EAP packet.
func DecodeEAP(b []byte) (*EAPPacket, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("EAP packet is %d bytes, minimum is 4", len(b))
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 4 || length > len(b) {
		// The declared length must be inside what actually arrived. A length
		// larger than the buffer is how a parser is persuaded to read past the
		// end of it.
		return nil, fmt.Errorf("EAP length field says %d, packet is %d bytes",
			length, len(b))
	}
	p := &EAPPacket{Code: b[0], Identifier: b[1]}

	switch p.Code {
	case EAPSuccess, EAPFailure:
		// Exactly four bytes, and anything after them is a lie about the
		// packet's own shape.
		if length != 4 {
			return nil, fmt.Errorf("EAP Success/Failure must be 4 bytes, got %d", length)
		}
		return p, nil
	case EAPRequest, EAPResponse:
		if length < 5 {
			return nil, fmt.Errorf("EAP Request/Response has no type byte")
		}
		p.Type = b[4]
		p.Data = append([]byte(nil), b[5:length]...)
		return p, nil
	default:
		return nil, fmt.Errorf("unknown EAP code %d", p.Code)
	}
}

// Encode renders an EAP packet.
func (p *EAPPacket) Encode() []byte {
	switch p.Code {
	case EAPSuccess, EAPFailure:
		out := make([]byte, 4)
		out[0], out[1] = p.Code, p.Identifier
		binary.BigEndian.PutUint16(out[2:4], 4)
		return out
	default:
		// EAP's length field is 16 bits, so a packet cannot represent more than
		// 65535 bytes. Truncating silently would produce a packet whose declared
		// length disagrees with its contents -- which the receiver resolves by
		// reading the wrong number of bytes. Everything this package sends is
		// bounded by eapTLSMaxFragment, so the clamp is unreachable today; it is
		// here because "unreachable today" is how a parser bug is introduced by
		// a change three years from now.
		data := p.Data
		if len(data) > 0xFFFF-5 {
			data = data[:0xFFFF-5]
		}
		out := make([]byte, 5+len(data))
		out[0], out[1] = p.Code, p.Identifier
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out))) // #nosec G115 -- clamped above
		out[4] = p.Type
		copy(out[5:], data)
		return out
	}
}

// EAPMessage reassembles the EAP packet from a RADIUS request.
//
// Concatenated in the order the attributes appear, which RFC 3579 §3.1 requires
// and which is why Packet.Attributes preserves order. Sorting or de-duplicating them
// would silently corrupt any EAP packet over 253 bytes -- and every certificate
// message is over 253 bytes.
func (p *Packet) EAPMessage() ([]byte, bool) {
	var out []byte
	found := false
	for _, a := range p.Attributes {
		if a.Type == AttrEAPMessage {
			out = append(out, a.Value...)
			found = true
		}
	}
	return out, found
}

// EAPAttributes splits an EAP packet across as many attributes as it needs.
func EAPAttributes(eap []byte) []Attribute {
	var out []Attribute
	for len(eap) > maxEAPMessageChunk {
		out = append(out, Attribute{Type: AttrEAPMessage,
			Value: append([]byte(nil), eap[:maxEAPMessageChunk]...)})
		eap = eap[maxEAPMessageChunk:]
	}
	// The final chunk is appended even when empty: an EAP packet is never zero
	// bytes, so this only runs with something in it.
	out = append(out, Attribute{Type: AttrEAPMessage, Value: append([]byte(nil), eap...)})
	return out
}

// EAP-TLS flags (RFC 5216 §3.1), the top three bits of the first data byte.
const (
	tlsFlagLengthIncluded = 0x80
	tlsFlagMoreFragments  = 0x40
	tlsFlagStart          = 0x20
)

// EAPTLSFrame is one EAP-TLS packet's payload.
type EAPTLSFrame struct {
	Start          bool
	More           bool
	LengthIncluded bool
	// TotalLength is the size of the whole TLS message being fragmented, present
	// only on the first fragment of a set.
	TotalLength uint32
	Data        []byte
}

// DecodeEAPTLS parses the payload of an EAP-TLS packet.
func DecodeEAPTLS(data []byte) (*EAPTLSFrame, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("EAP-TLS payload is empty")
	}
	f := &EAPTLSFrame{
		Start:          data[0]&tlsFlagStart != 0,
		More:           data[0]&tlsFlagMoreFragments != 0,
		LengthIncluded: data[0]&tlsFlagLengthIncluded != 0,
	}
	rest := data[1:]
	if f.LengthIncluded {
		if len(rest) < 4 {
			return nil, fmt.Errorf("EAP-TLS says a length follows but only %d bytes do",
				len(rest))
		}
		f.TotalLength = binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
	}
	f.Data = append([]byte(nil), rest...)
	return f, nil
}

// Encode renders an EAP-TLS payload.
func (f *EAPTLSFrame) Encode() []byte {
	var flags byte
	if f.Start {
		flags |= tlsFlagStart
	}
	if f.More {
		flags |= tlsFlagMoreFragments
	}
	if f.LengthIncluded {
		flags |= tlsFlagLengthIncluded
	}

	out := []byte{flags}
	if f.LengthIncluded {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], f.TotalLength)
		out = append(out, l[:]...)
	}
	return append(out, f.Data...)
}
