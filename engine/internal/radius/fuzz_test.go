package radius

import (
	"bytes"
	"testing"
)

// A RADIUS packet is a UDP datagram from any address that can reach the port, read
// before its Message-Authenticator is checked. Decoding ends in a packet or an error,
// a decoded packet's attributes and EAP message can be read, and checking its
// authenticator answers rather than panics.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{1, 1, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{1, 7, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 'a', 'd', 'a', '1'})
	f.Add([]byte{1, 7, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79, 2})
	f.Add([]byte{1, 1, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Decode(raw)
		if err != nil {
			return
		}
		for typ := 0; typ < 256; typ++ {
			if v, ok := p.Attr(byte(typ)); ok && !bytes.Contains(raw, v) {
				t.Fatalf("attribute %d is not bytes of the packet", typ)
			}
			_ = p.Count(byte(typ))
		}
		if msg, ok := p.EAPMessage(); ok {
			_, _ = DecodeEAP(msg)
		}
		_ = p.VerifyMessageAuthenticator([]byte("secret"))
	})
}

// EAP and the EAP-TLS framing inside it come from the supplicant through the RADIUS
// client, unauthenticated until the tunnel completes.
func FuzzDecodeEAP(f *testing.F) {
	f.Add([]byte{2, 1, 0, 9, 1, 'a', 'd', 'a', '1'})
	f.Add([]byte{2, 2, 0, 6, 13, 0x80})
	f.Add([]byte{2, 3, 0, 10, 13, 0xc0, 0, 0, 0, 4})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if p, err := DecodeEAP(raw); err == nil && p != nil {
			_, _ = DecodeEAPTLS(p.Data)
		}
		_, _ = DecodeEAPTLS(raw)
	})
}
