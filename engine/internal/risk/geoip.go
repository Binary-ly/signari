package risk

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Resolver turns an address into a coarse position.
type Resolver interface {
	Resolve(ip string) Location
}

// Explainer is implemented by a resolver that has something to say about why it
// cannot do its job.
//
// Separate from Resolver so the ordinary ones stay a single method. Callers ask
// with a type assertion at startup; see Explain.
type Explainer interface {
	Why() string
}

// Explain returns a resolver's complaint, if it has one.
//
// This exists because the complaint had nowhere to go. SIGNARI_GEOIP_DB could
// be set to a path that produced no reader, every impossible-travel check would
// then report "not checked", and nothing anywhere said so -- the operator had
// configured a security control and received silence. The message was written
// for a startup log and never reached one.
func Explain(r Resolver) string {
	if e, ok := r.(Explainer); ok {
		return e.Why()
	}
	return ""
}

// nullResolver knows nothing, and says so.
//
// The default. Without a GeoIP database every position is Unknown, so the travel
// check reports "not checked" rather than silently passing -- which is the
// distinction the whole design turns on.
type nullResolver struct{}

func (nullResolver) Resolve(string) Location { return Location{Known: false} }

// NewResolver builds the position lookup.
//
// SIGNARI_GEOIP_DB names a MaxMind-format database. Absent, the returned
// resolver knows nothing and every check reports that it did not run.
//
// The database is NOT bundled and NOT downloaded. It is licensed, it changes
// weekly, and an identity provider that fetches a binary blob from the internet
// on startup has added a supply chain to the authentication path. An operator
// who wants this points at a file they control.
func NewResolver() Resolver {
	// A static map first. Many deployments know exactly where their networks
	// are -- an office range, a VPN concentrator, a data centre -- and for those
	// a licensed database buys nothing. It is also the only form of this that
	// can be tested without shipping somebody else's data.
	//
	//   SIGNARI_GEOIP_STATIC="10.0.0.0/8=GB,51.51,-0.13;198.51.100.0/24=BR,-23.55,-46.63"
	if spec := os.Getenv("SIGNARI_GEOIP_STATIC"); spec != "" {
		if r, err := newStaticResolver(spec); err == nil {
			return r
		}
	}

	path := os.Getenv("SIGNARI_GEOIP_DB")
	if path == "" {
		return nullResolver{}
	}
	if _, err := os.Stat(path); err != nil {
		// Named but unreadable. Returning the null resolver keeps sign-in working
		// -- an unreadable optional database must not stop anybody logging in --
		// and the check will report that it did not run, which is true.
		return &missingResolver{path: path}
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		// Present but not a usable database: truncated, wrong format, or a
		// different MaxMind product than expected. Same rule as above -- an
		// optional file that is broken must not stop anybody signing in, and the
		// operator is told the difference at startup.
		return &missingResolver{path: path, reason: err.Error()}
	}
	return &mmdbResolver{db: db, path: path}
}

// mmdbResolver reads a MaxMind-format database.
//
// The reader is opened ONCE, at construction. Opening per lookup would put a
// file open on the sign-in path, and the library's Reader is safe for concurrent
// use, so there is nothing to gain by reopening it.
//
// Only three fields are decoded -- country, latitude, longitude. A GeoIP2-City
// record carries a great deal more (postcode, subdivisions, accuracy radius,
// city names in a dozen languages), and none of it is wanted here: the travel
// check needs a position, and every extra field decoded is a field that ends up
// somewhere it was not meant to go.
type mmdbResolver struct {
	db   *maxminddb.Reader
	path string
}

// cityRecord is the minimum subset of the GeoIP2/GeoLite2 City schema.
type cityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

func (m *mmdbResolver) Resolve(ipStr string) Location {
	ip, ok := ParseIP(ipStr)
	if !ok {
		return Location{Known: false}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Location{Known: false}
	}
	// Unmapped explicitly, and the honest note is that this is belt to the
	// library's braces rather than a fix for a live bug.
	//
	// An earlier comment here claimed an IPv4 address arriving as ::ffff:a.b.c.d
	// would miss an IPv4 network in the database. Checked, and that is not what
	// happens: net.ParseIP returns SIXTEEN bytes for a dotted-quad too, so both
	// spellings reach this point identically, and the reader resolves either form.
	// Removing the Unmap changes no test.
	//
	// It stays because the intent should not depend on a library's normalisation
	// staying the same, and it costs nothing. The claim that it fixes something
	// does not stay, because a reason that does not hold is worth correcting even
	// when the code it justifies is fine.
	res := m.db.Lookup(addr.Unmap())
	if !res.Found() {
		return Location{Known: false}
	}
	var rec cityRecord
	if err := res.Decode(&rec); err != nil {
		// A record that will not decode is not a reason to fail a sign-in.
		return Location{Known: false}
	}
	// A row with no coordinates is common -- anonymous proxies and satellite
	// ranges resolve to a country and nothing else. Reporting 0,0 for those would
	// place them in the Gulf of Guinea and make every one look like impossible
	// travel, which is the same trap the static resolver refuses to fall into.
	if rec.Location.Latitude == 0 && rec.Location.Longitude == 0 {
		return Location{Known: false}
	}
	return Location{
		Country:   rec.Country.ISOCode,
		Latitude:  rec.Location.Latitude,
		Longitude: rec.Location.Longitude,
		Known:     true,
	}
}

// Close releases the database. Used by tests; the process-lifetime resolver has
// no need of it.
func (m *mmdbResolver) Close() error { return m.db.Close() }

// missingResolver reports the same "unknown" as the null one, and remembers why,
// so an operator can be told the difference between "not configured" and
// "configured and not working".
type missingResolver struct {
	path   string
	reason string
	once   sync.Once
}

func (m *missingResolver) Resolve(string) Location { return Location{Known: false} }

// Why explains the resolver's state for a startup log.
func (m *missingResolver) Why() string {
	if m.reason != "" {
		return "SIGNARI_GEOIP_DB is set to " + m.path + " but it could not be opened (" +
			m.reason + "); impossible-travel checks will report that they did not run"
	}
	return "SIGNARI_GEOIP_DB is set to " + m.path + " but the file could not be read; " +
		"impossible-travel checks will report that they did not run"
}

// ParseIP is a small guard so a caller cannot pass a hostname by accident.
func ParseIP(s string) (net.IP, bool) {
	ip := net.ParseIP(s)
	return ip, ip != nil
}

// staticResolver maps CIDR ranges to fixed positions.
type staticEntry struct {
	net     *net.IPNet
	country string
	lat     float64
	lon     float64
}

type staticResolver struct{ entries []staticEntry }

func newStaticResolver(spec string) (*staticResolver, error) {
	r := &staticResolver{}
	for _, part := range strings.Split(spec, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		cidr, rest, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not CIDR=country,lat,lon", part)
		}
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("%q: %w", cidr, err)
		}
		fields := strings.Split(rest, ",")
		if len(fields) != 3 {
			return nil, fmt.Errorf("%q needs country,lat,lon", rest)
		}
		lat, err1 := strconv.ParseFloat(strings.TrimSpace(fields[1]), 64)
		lon, err2 := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%q has unparseable coordinates", rest)
		}
		r.entries = append(r.entries, staticEntry{
			net: n, country: strings.TrimSpace(fields[0]), lat: lat, lon: lon,
		})
	}
	if len(r.entries) == 0 {
		return nil, fmt.Errorf("no entries")
	}
	return r, nil
}

// Resolve returns the FIRST matching range.
//
// First rather than most-specific, so the order an operator wrote is the order
// that applies. A most-specific rule would be more clever and would mean the
// behaviour depends on a comparison they cannot see in their own configuration.
func (r *staticResolver) Resolve(ipStr string) Location {
	ip, ok := ParseIP(ipStr)
	if !ok {
		return Location{Known: false}
	}
	for _, e := range r.entries {
		if e.net.Contains(ip) {
			return Location{
				Country: e.country, Latitude: e.lat, Longitude: e.lon, Known: true,
			}
		}
	}
	// Outside every configured range. Unknown, NOT a default position: putting
	// unrecognised addresses at a fixed point would make every one of them look
	// like impossible travel from the office.
	return Location{Known: false}
}
