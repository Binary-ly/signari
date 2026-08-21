package risk

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The MaxMind reader, against MaxMind's own test database.
//
// The reader was not implemented for a stated reason: "a lookup written blind is
// a lookup nobody has ever seen return the right answer." That reason was sound
// and is no longer true — MaxMind publishes `test-data/*.mmdb` under Apache-2.0
// precisely so a reader can be exercised without licensing their production data.
// `testdata/GeoIP2-City-Test.mmdb` is one of those files.
//
// Until this existed, `NewResolver` returned `missingResolver` for every
// SIGNARI_GEOIP_DB path, so the only working position source was the static CIDR
// map and impossible-travel could not fire for anyone using a database.

func testDB(t *testing.T) string {
	t.Helper()
	p := filepath.Join("testdata", "GeoIP2-City-Test.mmdb")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("test database missing: %v", err)
	}
	return p
}

func TestTheReaderReturnsRealPositions(t *testing.T) {
	t.Setenv("SIGNARI_GEOIP_STATIC", "")
	t.Setenv("SIGNARI_GEOIP_DB", testDB(t))
	r := NewResolver()

	if why := Explain(r); why != "" {
		t.Fatalf("a readable database still reported a problem: %s", why)
	}

	for _, tc := range []struct {
		ip      string
		country string
		lat     float64
		lon     float64
	}{
		{"81.2.69.142", "GB", 51.5142, -0.0931},
		{"89.160.20.112", "SE", 58.4167, 15.6167},
		{"216.160.83.56", "US", 47.2513, -122.3149},
	} {
		got := r.Resolve(tc.ip)
		if !got.Known {
			t.Errorf("%s resolved to unknown; the database has a record for it", tc.ip)
			continue
		}
		if got.Country != tc.country {
			t.Errorf("%s country = %q, want %q", tc.ip, got.Country, tc.country)
		}
		// Coordinates are compared loosely: the database stores them to four
		// decimal places and the check only needs a position good to a city.
		if d := got.Latitude - tc.lat; d > 0.01 || d < -0.01 {
			t.Errorf("%s latitude = %v, want ~%v", tc.ip, got.Latitude, tc.lat)
		}
		if d := got.Longitude - tc.lon; d > 0.01 || d < -0.01 {
			t.Errorf("%s longitude = %v, want ~%v", tc.ip, got.Longitude, tc.lon)
		}
	}
}

// The property the whole feature exists for, end to end: two real addresses from
// the database, an hour apart, must be reported as impossible.
//
// London to Tacoma is about 7,700 km. An hour is not enough, and no aircraft
// closes it — so this is the check doing its job on data it actually looked up,
// rather than on coordinates a test invented.
func TestImpossibleTravelFiresOnRealLookups(t *testing.T) {
	t.Setenv("SIGNARI_GEOIP_STATIC", "")
	t.Setenv("SIGNARI_GEOIP_DB", testDB(t))
	r := NewResolver()

	london := r.Resolve("81.2.69.142")
	tacoma := r.Resolve("216.160.83.56")
	if !london.Known || !tacoma.Known {
		t.Fatal("both addresses must resolve for this test to mean anything")
	}
	london.At = time.Now().Add(-1 * time.Hour)
	tacoma.At = time.Now()

	v := CheckTravel(london, tacoma)
	if !v.Checked {
		t.Fatalf("the check did not run: %s", v.Reason)
	}
	if !v.Impossible {
		t.Fatalf("London to Tacoma in an hour was judged possible "+
			"(%.0f km at %.0f km/h)", v.DistanceKm, v.SpeedKmh)
	}
	if v.DistanceKm < 7000 || v.DistanceKm > 8500 {
		t.Errorf("distance = %.0f km; London-Tacoma is roughly 7,700", v.DistanceKm)
	}

	// And the negative control: the same two points a fortnight apart is just
	// somebody who travelled. A detector that fires on that gets switched off.
	london.At = time.Now().Add(-14 * 24 * time.Hour)
	if v := CheckTravel(london, tacoma); v.Impossible {
		t.Errorf("a fortnight between London and Tacoma was called impossible "+
			"(%.0f km/h)", v.SpeedKmh)
	}
}

// An address the database does not carry must be unknown, not a default point.
// Reporting 0,0 would place it in the Gulf of Guinea and make every unrecognised
// address look like impossible travel from anywhere.
func TestAnAddressNotInTheDatabaseIsUnknown(t *testing.T) {
	t.Setenv("SIGNARI_GEOIP_STATIC", "")
	t.Setenv("SIGNARI_GEOIP_DB", testDB(t))
	r := NewResolver()

	for _, ip := range []string{"192.0.2.1", "203.0.113.9", "not-an-ip", ""} {
		if got := r.Resolve(ip); got.Known {
			t.Errorf("%q resolved to %v; it should be unknown", ip, got)
		}
	}
}

// Both spellings of the same address must give the same answer.
//
// Stated carefully, because a first version of this test was written to prove the
// Unmap call was load-bearing and it is not: removing the Unmap leaves this test
// green. net.ParseIP returns sixteen bytes for a dotted-quad as well, so both
// inputs arrive here in 4-in-6 form, and the reader resolves either.
//
// The property is still worth pinning — an office behind a dual-stack proxy must
// not read as unknown — but it is pinned as a property of the resolver, not as
// evidence for one line inside it.
func TestIPv4MappedAddressesResolve(t *testing.T) {
	t.Setenv("SIGNARI_GEOIP_STATIC", "")
	t.Setenv("SIGNARI_GEOIP_DB", testDB(t))
	r := NewResolver()

	plain := r.Resolve("81.2.69.142")
	mapped := r.Resolve("::ffff:81.2.69.142")
	if !plain.Known {
		t.Fatal("the plain form must resolve for this test to mean anything")
	}
	if !mapped.Known {
		t.Fatal("the IPv6-mapped form did not resolve; Unmap is not being applied")
	}
	if mapped.Country != plain.Country || mapped.Latitude != plain.Latitude {
		t.Errorf("mapped %v != plain %v", mapped, plain)
	}
}

// A file that exists but is not a database must not stop anybody signing in, and
// the operator must be told the difference between "not configured" and
// "configured and broken".
func TestABrokenDatabaseDegradesWithAnExplanation(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken.mmdb")
	if err := os.WriteFile(broken, []byte("this is not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNARI_GEOIP_STATIC", "")
	t.Setenv("SIGNARI_GEOIP_DB", broken)
	r := NewResolver()

	if got := r.Resolve("81.2.69.142"); got.Known {
		t.Error("a broken database returned a position")
	}
	why := Explain(r)
	if why == "" {
		t.Fatal("a broken database explained nothing; the operator configured a " +
			"security control and would hear silence")
	}
	if !contains(why, broken) {
		t.Errorf("the explanation does not name the file: %s", why)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
