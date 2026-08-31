package radius

import (
	"strconv"
)

// Authorisation attributes in an Access-Accept.
//
// # What the reply carries, and what it deliberately does not
//
// A VLAN id and a filter name. No email, no display name, no user attributes.
// The reasoning is the one already recorded on RADIUSAuthenticator: an
// Access-Accept "is not a place to start leaking a directory". VLAN assignment
// is not leakage — it is the answer to the question the switch asked — so it
// belongs here, and everything about the person does not.
//
// # Encoding, taken from the RFCs rather than from memory
//
// RFC 2868 defines the three tunnel attributes as TAGGED: an octet of Tag sits
// between Length and Value, and for Tunnel-Type and Tunnel-Medium-Type the Value
// is 3 octets, giving a total Length of 6.
//
//	"If the Tag field is unused, it MUST be zero (0x00)." — RFC 2868
//
// RFC 3580 §3.31 gives the values for VLAN assignment:
//
//	"Tunnel-Type=VLAN (13)", "Tunnel-Medium-Type=802",
//	"Tunnel-Private-Group-ID=VLANID"
//
// and the tag guidance:
//
//	"where it is only desired to specify the VLANID, the tag field SHOULD be
//	set to zero (0x00) in all tunnel attributes."
//
// One tunnel is all this sends, so every tag here is 0x00.
//
// The VLANID is a STRING, not an integer, which is the detail that catches
// people: RFC 3580 §3.31 says "the VLANID integer value is encoded as a string".
// Sending four raw bytes produces a switch that either rejects the reply or
// assigns a VLAN nobody chose.
const (
	// RADIUS attribute types. IANA-assigned; the tunnel three are defined by
	// RFC 2868 and the filter by RFC 2865.
	AttrFilterID             = 11
	AttrTunnelType           = 64
	AttrTunnelMediumType     = 65
	AttrTunnelPrivateGroupID = 81
)

const (
	// RFC 3580 §3.31: "Tunnel-Type=VLAN (13)".
	tunnelTypeVLAN = 13
	// RFC 3580 §3.31: "Tunnel-Medium-Type=802". RFC 2868 lists 6 as
	// "802 (includes all 802 media plus Ethernet)".
	tunnelMedium802 = 6
	// RFC 3580 §3.31: one tunnel only, so the tag is unused.
	unusedTag = 0x00
)

// Authorization is what an operator decided a person's groups grant.
type Authorization struct {
	// VLANID is 1-4094 when set, per RFC 3580 §3.31: "the VLANID is 12-bits,
	// taking a value between 1 and 4094, inclusive."
	VLANID int
	// FilterID names a filter list already configured on the device.
	FilterID string
}

// Empty reports whether there is nothing to say.
func (a Authorization) Empty() bool { return a.VLANID == 0 && a.FilterID == "" }

// Attributes renders the authorisation as RADIUS attributes.
//
// Returns nil when there is nothing to send, so an Access-Accept for a
// deployment that has configured no network authorisation is byte-for-byte what
// it was before this existed.
func (a Authorization) Attributes() []Attribute {
	if a.Empty() {
		return nil
	}
	var out []Attribute

	if a.FilterID != "" {
		out = append(out, Attribute{Type: AttrFilterID, Value: []byte(a.FilterID)})
	}

	// Out-of-range is dropped rather than clamped or truncated. A VLAN of 0 or
	// 9999 is a configuration mistake, and putting somebody on VLAN 1 because
	// their intended one was invalid is worse than saying nothing: the switch
	// then applies its own default, which the operator can see and diagnose.
	if a.VLANID < 1 || a.VLANID > 4094 {
		return out
	}

	// All three, together. A Tunnel-Private-Group-ID without the type and medium
	// is not a VLAN assignment; several switch firmwares ignore the lot.
	out = append(out,
		Attribute{Type: AttrTunnelType, Value: taggedInteger(tunnelTypeVLAN)},
		Attribute{Type: AttrTunnelMediumType, Value: taggedInteger(tunnelMedium802)},
		// The VLANID as a STRING (RFC 3580 §3.31), preceded by the tag octet.
		Attribute{Type: AttrTunnelPrivateGroupID,
			Value: append([]byte{unusedTag}, []byte(strconv.Itoa(a.VLANID))...)},
	)
	return out
}

// taggedInteger renders RFC 2868's Tag plus a 3-octet value.
//
// Three octets, not four: the tag occupies the first of what would otherwise be
// a 4-octet integer, so the total attribute Length is 6 exactly as for an
// untagged integer. Writing four here produces a Length of 7 and a reply many
// devices discard without saying why.
func taggedInteger(v uint32) []byte {
	return []byte{unusedTag, byte(v >> 16), byte(v >> 8), byte(v)}
}
