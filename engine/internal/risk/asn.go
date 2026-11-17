package risk

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// ASNResolver names the autonomous system an address belongs to: the network
// operator announcing it. 0 means it could not say, and no address belongs to AS0.
type ASNResolver interface {
	ASN(ip string) uint32
}

// NewASNResolver builds the operator lookup a policy's from_asns and not_from_asns
// rules read.
//
// SIGNARI_GEOIP_ASN_DB names an IP-to-ASN database in MaxMind's format: MaxMind's
// GeoLite2-ASN, its GeoIP2-ISP, or DB-IP's IP-to-ASN Lite, which says it is laid
// out like GeoLite2-ASN. Like SIGNARI_GEOIP_DB it is not bundled and not
// downloaded: the operator points at a file they control. SIGNARI_GEOIP_ASN_STATIC
// maps ranges by hand, "203.0.113.0/24=64500;2001:db8::/32=64501", for a deployment
// that knows its own networks and for tests.
func NewASNResolver() ASNResolver {
	if spec := os.Getenv("SIGNARI_GEOIP_ASN_STATIC"); spec != "" {
		r, err := newStaticASNResolver(spec)
		if err != nil {
			return &missingASNResolver{why: "SIGNARI_GEOIP_ASN_STATIC could not be read (" + err.Error() +
				"); from_asns refuses everybody it covers and not_from_asns refuses nobody"}
		}
		return r
	}
	path := os.Getenv("SIGNARI_GEOIP_ASN_DB")
	if path == "" {
		return noASN{}
	}
	return openASNDB(path)
}

func openASNDB(path string) ASNResolver {
	if _, err := os.Stat(path); err != nil {
		return &missingASNResolver{why: "SIGNARI_GEOIP_ASN_DB is set to " + path +
			" but the file could not be read; from_asns refuses everybody it covers and not_from_asns refuses nobody"}
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return &missingASNResolver{why: "SIGNARI_GEOIP_ASN_DB is set to " + path + " but it could not be opened (" +
			err.Error() + "); from_asns refuses everybody it covers and not_from_asns refuses nobody"}
	}
	// A city database given here by mistake opens and places nobody: every lookup
	// decodes to AS0. Refused by its own description, which names what it holds.
	if t := db.Metadata.DatabaseType; !strings.Contains(t, "ASN") && !strings.Contains(t, "ISP") {
		_ = db.Close()
		return &missingASNResolver{why: "SIGNARI_GEOIP_ASN_DB is set to " + path + ", a " + t +
			" database, which holds no autonomous system numbers; give an ASN or ISP database"}
	}
	return &mmdbASN{db: db}
}

// noASN is the default: nothing places an address on a network.
type noASN struct{}

func (noASN) ASN(string) uint32 { return 0 }

// mmdbASN reads one field, the number. The organisation's name is in the record
// too and is not decoded: nothing here decides on a name.
type mmdbASN struct{ db *maxminddb.Reader }

// asnRecord is the field GeoLite2-ASN, GeoIP2-ISP and DB-IP's IP-to-ASN Lite all
// carry; the name was read from DB-IP's file, not assumed.
type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
}

func (m *mmdbASN) ASN(ipStr string) uint32 {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return 0
	}
	res := m.db.Lookup(addr.Unmap())
	if !res.Found() {
		return 0
	}
	var rec asnRecord
	if err := res.Decode(&rec); err != nil {
		return 0
	}
	return rec.Number
}

// Close releases the database. Used by tests.
func (m *mmdbASN) Close() error { return m.db.Close() }

// missingASNResolver places nobody and says why, for the startup log and doctor.
type missingASNResolver struct{ why string }

func (*missingASNResolver) ASN(string) uint32 { return 0 }

// Why explains the resolver's state.
func (m *missingASNResolver) Why() string { return m.why }

// ExplainASN returns an ASN resolver's complaint, if it has one.
func ExplainASN(r ASNResolver) string {
	if e, ok := r.(Explainer); ok {
		return e.Why()
	}
	return ""
}

// ASNConfigured reports whether anything can place an address on a network.
func ASNConfigured(r ASNResolver) bool {
	switch r.(type) {
	case noASN, *missingASNResolver:
		return false
	}
	return true
}

type staticASN struct {
	net *net.IPNet
	asn uint32
}

type staticASNResolver struct{ entries []staticASN }

func newStaticASNResolver(spec string) (*staticASNResolver, error) {
	r := &staticASNResolver{}
	for _, part := range strings.Split(spec, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		cidr, num, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not CIDR=ASN", part)
		}
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("%q: %w", cidr, err)
		}
		asn, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(num), "AS"), 10, 32)
		if err != nil || asn == 0 {
			return nil, fmt.Errorf("%q is not an autonomous system number above 0", num)
		}
		r.entries = append(r.entries, staticASN{net: n, asn: uint32(asn)})
	}
	if len(r.entries) == 0 {
		return nil, fmt.Errorf("no entries")
	}
	return r, nil
}

// ASN answers the FIRST matching range, in the order the operator wrote them, as
// the static position map does.
func (r *staticASNResolver) ASN(ipStr string) uint32 {
	ip, ok := ParseIP(strings.TrimSpace(ipStr))
	if !ok {
		return 0
	}
	for _, e := range r.entries {
		if e.net.Contains(ip) {
			return e.asn
		}
	}
	return 0
}
