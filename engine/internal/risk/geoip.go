package risk

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
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
	// A real MaxMind reader goes here. Deliberately not implemented against a
	// database this repository cannot test with: a lookup written blind is a
	// lookup nobody has ever seen return the right answer.
	return &missingResolver{path: path}
}

// missingResolver reports the same "unknown" as the null one, and remembers why,
// so an operator can be told the difference between "not configured" and
// "configured and not working".
type missingResolver struct {
	path string
	once sync.Once
}

func (m *missingResolver) Resolve(string) Location { return Location{Known: false} }

// Why explains the resolver's state for a startup log.
func (m *missingResolver) Why() string {
	return "SIGNARI_GEOIP_DB is set to " + m.path + " but no reader is built in yet; " +
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
