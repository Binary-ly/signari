package radius

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// fixedAuthz answers the same grant for everybody, and remembers who it was
// asked about.
type fixedAuthz struct {
	grant Authorization
	err   error
	asked []string
}

func (a *fixedAuthz) Authorize(_ context.Context, username string) (Authorization, error) {
	a.asked = append(a.asked, username)
	return a.grant, a.err
}

func attrValue(p *Packet, typ byte) []byte {
	v, _ := p.Attr(typ)
	return v
}

// A certificate gets what a password gets (7.06). The Accept for EAP-TLS carried
// keys and nothing else, so moving a building onto certificates moved everybody
// off their VLAN.
func TestAnEAPAcceptCarriesWhatTheGroupIsGiven(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})
	authz := &fixedAuthz{grant: Authorization{VLANID: 42, FilterID: "staff", SessionTimeout: 28800, Class: "staff",
		Vendor: []VendorAttribute{{Vendor: 9, Type: 1, Value: "shell:priv-lvl=15"}}}}
	srv.SetAuthorizer(authz)

	sup := &supplicant{t: t, server: srv, conn: newFakePacketConn(),
		secret: []byte("a-secret-of-sufficient-length"),
		cert:   pki.issue(t, "alice@corp.test", true, 0), pool: pki.pool, identity: "anonymous"}
	code, reply, err := sup.run()
	if err != nil {
		t.Fatalf("the conversation failed: %v", err)
	}
	if code != CodeAccessAccept {
		t.Fatalf("got code %d, want Access-Accept", code)
	}
	// Who the certificate says, never the identity the supplicant announced.
	if len(authz.asked) != 1 || authz.asked[0] != "alice@corp.test" {
		t.Errorf("the authorizer was asked about %q", authz.asked)
	}
	if got := attrValue(reply, AttrTunnelPrivateGroupID); !bytes.Equal(got, append([]byte{unusedTag}, "42"...)) {
		t.Errorf("Tunnel-Private-Group-ID is %q", got)
	}
	for _, typ := range []byte{AttrTunnelType, AttrTunnelMediumType} {
		if _, ok := reply.Attr(typ); !ok {
			t.Errorf("attribute %d is missing from the Accept", typ)
		}
	}
	if got := attrValue(reply, AttrFilterID); string(got) != "staff" {
		t.Errorf("Filter-Id is %q", got)
	}
	if got := attrValue(reply, AttrSessionTimeout); !bytes.Equal(got, []byte{0, 0, 0x70, 0x80}) {
		t.Errorf("Session-Timeout is %x, want 28800 in four octets", got)
	}
	if got := attrValue(reply, AttrClass); string(got) != "staff" {
		t.Errorf("Class is %q", got)
	}
	// The group's, beside the two keys, without which the laptop passes nothing.
	if n := reply.Count(AttrVendorSpecific); n != 3 {
		t.Errorf("%d vendor-specific attributes, want 3", n)
	}
}

// Advisory, as for a password: somebody authenticated is not refused because an
// optional mapping could not be read.
func TestAnEAPAcceptOutlivesAFailedLookup(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})
	srv.SetAuthorizer(&fixedAuthz{err: errors.New("the database is away")})
	sup := &supplicant{t: t, server: srv, conn: newFakePacketConn(),
		secret: []byte("a-secret-of-sufficient-length"),
		cert:   pki.issue(t, "alice@corp.test", true, 0), pool: pki.pool, identity: "anonymous"}
	code, _, err := sup.run()
	if err != nil || code != CodeAccessAccept {
		t.Errorf("answered %d, %v; want Access-Accept", code, err)
	}
}

func TestAVendorAttributeIsWhatItsVendorExpects(t *testing.T) {
	attr, ok := VendorAttribute{Vendor: 9, Type: 1, Value: "shell:priv-lvl=15"}.Encode()
	if !ok || attr.Type != AttrVendorSpecific {
		t.Fatalf("encoded %+v, %v", attr, ok)
	}
	want := append([]byte{0, 0, 0, 9, 1, 19}, "shell:priv-lvl=15"...)
	if !bytes.Equal(attr.Value, want) {
		t.Errorf("encoded % x, want % x", attr.Value, want)
	}
	if len(attr.Value) > 253 {
		t.Errorf("%d octets do not fit an attribute", len(attr.Value))
	}
	if full, ok := (VendorAttribute{Vendor: 1, Type: 1, Value: strings.Repeat("x", MaxVendorValue)}).Encode(); !ok || len(full.Value) != 253 {
		t.Errorf("the longest value made %d octets", len(full.Value))
	}
	for name, v := range map[string]VendorAttribute{
		"no vendor":     {Type: 1, Value: "x"},
		"no type":       {Vendor: 9, Value: "x"},
		"a type over":   {Vendor: 9, Type: 256, Value: "x"},
		"a vendor over": {Vendor: 1 << 32, Type: 1, Value: "x"},
		"no value":      {Vendor: 9, Type: 1},
		"a value over":  {Vendor: 9, Type: 1, Value: strings.Repeat("x", MaxVendorValue+1)},
	} {
		if _, ok := v.Encode(); ok {
			t.Errorf("%s encoded", name)
		}
	}
}

// One that cannot be sent is left out, as an out-of-range VLAN is, and takes
// nothing else with it.
func TestABadVendorAttributeIsDroppedAlone(t *testing.T) {
	got := Authorization{Class: "c", Vendor: []VendorAttribute{{Vendor: 9, Type: 1},
		{Vendor: 9, Type: 2, Value: "good"}}}.Attributes()
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestOnlyATimeoutIsSomethingToSay(t *testing.T) {
	if (Authorization{SessionTimeout: 60}).Empty() {
		t.Error("a Session-Timeout alone was nothing")
	}
	if (Authorization{Vendor: []VendorAttribute{{Vendor: 9, Type: 1, Value: "x"}}}).Empty() {
		t.Error("a vendor attribute alone was nothing")
	}
	if !(Authorization{}).Empty() {
		t.Error("nothing was something")
	}
}
