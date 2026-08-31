package radius

import (
	"bytes"
	"testing"
)

// VLAN assignment on the wire, checked against the RFC text rather than against
// what seemed reasonable.
//
// The two details that catch people are both here:
//
//   - The tunnel attributes are TAGGED (RFC 2868). The tag octet occupies the
//     first of what would otherwise be a 4-octet integer, so the value is 3
//     octets and the attribute Length stays 6. Writing four produces Length 7
//     and a reply many devices discard without saying why.
//   - The VLANID is a STRING (RFC 3580 §3.31: "the VLANID integer value is
//     encoded as a string"). Sending four raw bytes gets the reply rejected or,
//     worse, a VLAN nobody chose.

func TestNothingConfiguredSendsNoAttributes(t *testing.T) {
	if attrs := (Authorization{}).Attributes(); attrs != nil {
		t.Fatalf("an empty authorisation produced %d attributes; an Access-Accept "+
			"for a deployment that configured nothing must be what it always was",
			len(attrs))
	}
}

func TestAVLANIsSentAsTheFullTunnelTriple(t *testing.T) {
	attrs := Authorization{VLANID: 42}.Attributes()

	got := map[byte][]byte{}
	for _, a := range attrs {
		got[a.Type] = a.Value
	}

	// All three together. A Tunnel-Private-Group-ID on its own is not a VLAN
	// assignment, and several switch firmwares ignore the lot.
	for _, typ := range []byte{AttrTunnelType, AttrTunnelMediumType, AttrTunnelPrivateGroupID} {
		if _, ok := got[typ]; !ok {
			t.Fatalf("attribute %d is missing; the triple must be sent together", typ)
		}
	}

	// RFC 2868: tag octet, then a 3-octet value. RFC 3580 §3.31: VLAN is 13.
	if want := []byte{0x00, 0, 0, 13}; !bytes.Equal(got[AttrTunnelType], want) {
		t.Errorf("Tunnel-Type value = %v, want %v (tag 0x00 then 3 octets)",
			got[AttrTunnelType], want)
	}
	// RFC 3580 §3.31: Tunnel-Medium-Type=802, which RFC 2868 numbers 6.
	if want := []byte{0x00, 0, 0, 6}; !bytes.Equal(got[AttrTunnelMediumType], want) {
		t.Errorf("Tunnel-Medium-Type value = %v, want %v", got[AttrTunnelMediumType], want)
	}
	// RFC 3580 §3.31: the VLANID encoded as a STRING, after the tag.
	if want := append([]byte{0x00}, []byte("42")...); !bytes.Equal(got[AttrTunnelPrivateGroupID], want) {
		t.Errorf("Tunnel-Private-Group-ID = %v, want %v. The VLANID is a string, "+
			"not four raw bytes.", got[AttrTunnelPrivateGroupID], want)
	}
}

// The tagged integers are 4 bytes total, so the attribute Length is 6.
func TestATaggedIntegerLeavesTheAttributeLengthAtSix(t *testing.T) {
	attrs := Authorization{VLANID: 1}.Attributes()
	for _, a := range attrs {
		if a.Type != AttrTunnelType && a.Type != AttrTunnelMediumType {
			continue
		}
		// Type + Length + value.
		if got := 2 + len(a.Value); got != 6 {
			t.Errorf("attribute %d encodes to Length %d, want 6. The tag occupies "+
				"the first octet of the integer, so the value is 3 octets and not 4.",
				a.Type, got)
		}
	}
}

// Out of range is dropped, never clamped.
//
// RFC 3580 §3.31 bounds the VLANID at 1-4094. Putting somebody on VLAN 1 because
// their intended one was invalid is worse than saying nothing: the switch then
// applies its own default, which an operator can see and diagnose.
func TestAnOutOfRangeVLANIsDroppedNotClamped(t *testing.T) {
	for _, bad := range []int{0, -1, 4095, 99999} {
		attrs := Authorization{VLANID: bad}.Attributes()
		for _, a := range attrs {
			if a.Type == AttrTunnelPrivateGroupID || a.Type == AttrTunnelType {
				t.Errorf("VLAN %d produced a tunnel attribute; it must be dropped", bad)
			}
		}
	}
}

// A filter is sent on its own, with no tunnel attributes.
func TestAFilterIDIsSentWithoutTunnelAttributes(t *testing.T) {
	attrs := Authorization{FilterID: "contractors"}.Attributes()
	if len(attrs) != 1 {
		t.Fatalf("got %d attributes, want just Filter-Id", len(attrs))
	}
	if attrs[0].Type != AttrFilterID {
		t.Errorf("attribute type = %d, want %d", attrs[0].Type, AttrFilterID)
	}
	if string(attrs[0].Value) != "contractors" {
		t.Errorf("Filter-Id = %q", attrs[0].Value)
	}
}

// A filter alongside a VLAN sends both.
func TestAFilterAndAVLANAreBothSent(t *testing.T) {
	attrs := Authorization{VLANID: 100, FilterID: "guest"}.Attributes()
	if len(attrs) != 4 {
		t.Fatalf("got %d attributes, want 4 (Filter-Id plus the tunnel triple)", len(attrs))
	}
}
