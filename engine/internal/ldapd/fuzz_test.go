package ldapd

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// A search filter arrives from any client that can open the port, before or after a
// bind. Whatever bytes it is, decoding ends in a filter or an error, and a filter that
// decodes evaluates against an entry without panicking (specs/rfc4511.txt:1268, the
// three answers a filter gives).
func FuzzDecodeFilter(f *testing.F) {
	for _, seed := range [][]byte{
		// (uid=ada), (&(objectClass=*)(cn=a*b)), (!(mail=x)), and an extensible match.
		{0xa3, 0x0a, 0x04, 0x03, 'u', 'i', 'd', 0x04, 0x03, 'a', 'd', 'a'},
		{0xa0, 0x18, 0x87, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
			0xa4, 0x09, 0x04, 0x02, 'c', 'n', 0x30, 0x03, 0x80, 0x01, 'a'},
		{0xa2, 0x0b, 0xa3, 0x09, 0x04, 0x04, 'm', 'a', 'i', 'l', 0x04, 0x01, 'x'},
		{0xa9, 0x08, 0x82, 0x02, 'c', 'n', 0x83, 0x02, 'a', 'b'},
		{0xa0, 0x00}, {}, {0xff, 0xff, 0xff},
	} {
		f.Add(seed)
	}
	e := &entry{DN: "uid=ada,dc=example,dc=com", Attrs: map[string][]string{
		"uid": {"ada"}, "cn": {"Ada Lovelace"}, "mail": {"ada@example.com"}, "objectClass": {"person"}}}
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := ber.DecodePacketErr(raw)
		if err != nil {
			return
		}
		flt, err := decodeFilter(p)
		if err != nil || flt == nil {
			return
		}
		_ = flt.Matches(e)
	})
}
