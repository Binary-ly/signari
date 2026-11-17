package risk

import (
	"strings"
	"testing"
)

// The network an address is on, from a database laid out as the real ones are
// (testdata/asn-test.mmdb), so the field the reader decodes is the field they carry.
func TestTheASNDatabaseNamesTheNetwork(t *testing.T) {
	t.Setenv("SIGNARI_GEOIP_ASN_STATIC", "")
	t.Setenv("SIGNARI_GEOIP_ASN_DB", "testdata/asn-test.mmdb")
	r := NewASNResolver()
	if why := ExplainASN(r); why != "" || !ASNConfigured(r) {
		t.Fatalf("the fixture was not opened: %q", why)
	}
	for ip, want := range map[string]uint32{
		"203.0.113.9":        64500,
		"198.51.100.200":     64666,
		"2001:db8::1":        64501,
		"::ffff:203.0.113.9": 64500,
		"192.0.2.1":          0, // in no range the database holds
		"not an address":     0,
		"":                   0,
	} {
		if got := r.ASN(ip); got != want {
			t.Errorf("%q is on AS%d, want AS%d", ip, got, want)
		}
	}
}

// A database that holds no networks is refused by what it says it is, rather than
// opened to place nobody; a missing file and a broken map are each said, and none of
// them stops anything: an address is simply not placed.
func TestAnASNSourceThatCannotAnswerSaysWhy(t *testing.T) {
	for _, c := range []struct{ name, db, static, want string }{
		{"a city database", "testdata/GeoIP2-City-Test.mmdb", "", "holds no autonomous system numbers"},
		{"no such file", "testdata/nowhere.mmdb", "", "could not be read"},
		{"a map that is not one", "", "203.0.113.0/24=AS0", "above 0"},
		{"a map with no ASN", "", "203.0.113.0/24", "CIDR=ASN"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SIGNARI_GEOIP_ASN_DB", c.db)
			t.Setenv("SIGNARI_GEOIP_ASN_STATIC", c.static)
			r := NewASNResolver()
			if ASNConfigured(r) || !strings.Contains(ExplainASN(r), c.want) {
				t.Errorf("configured %v, explained %q, want it unconfigured and naming %q",
					ASNConfigured(r), ExplainASN(r), c.want)
			}
			if got := r.ASN("203.0.113.9"); got != 0 {
				t.Errorf("an address placed on AS%d by a source that cannot answer", got)
			}
		})
	}
	t.Setenv("SIGNARI_GEOIP_ASN_DB", "")
	t.Setenv("SIGNARI_GEOIP_ASN_STATIC", "")
	if r := NewASNResolver(); ASNConfigured(r) || ExplainASN(r) != "" {
		t.Error("with nothing named the lookup should be off and quiet")
	}
}

// A map by hand, first match in the order written, as the position map is.
func TestTheStaticASNMapTakesTheFirstMatch(t *testing.T) {
	t.Setenv("SIGNARI_GEOIP_ASN_DB", "")
	t.Setenv("SIGNARI_GEOIP_ASN_STATIC", "203.0.113.0/25=64500; 203.0.113.0/24=AS64501; 2001:db8::/32=64502")
	r := NewASNResolver()
	for ip, want := range map[string]uint32{"203.0.113.1": 64500, "203.0.113.200": 64501, "2001:db8::9": 64502, "10.0.0.1": 0} {
		if got := r.ASN(ip); got != want {
			t.Errorf("%s is on AS%d, want AS%d", ip, got, want)
		}
	}
}
