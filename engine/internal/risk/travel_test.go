package risk

import (
	"math"
	"strings"
	"testing"
	"time"
)

// Real coordinates, so the distances are checkable against an atlas.
var (
	london    = Location{Country: "GB", Latitude: 51.51, Longitude: -0.13, Known: true}
	paris     = Location{Country: "FR", Latitude: 48.86, Longitude: 2.35, Known: true}
	newYork   = Location{Country: "US", Latitude: 40.71, Longitude: -74.01, Known: true}
	saoPaulo  = Location{Country: "BR", Latitude: -23.55, Longitude: -46.63, Known: true}
	sydney    = Location{Country: "AU", Latitude: -33.87, Longitude: 151.21, Known: true}
	stockholm = Location{Country: "SE", Latitude: 59.33, Longitude: 18.07, Known: true}
)

func at(l Location, t time.Time) Location { l.At = t; return l }

func TestHaversineAgainstKnownDistances(t *testing.T) {
	cases := []struct {
		name   string
		a, b   Location
		wantKm float64
	}{
		{"London to Paris", london, paris, 344},
		{"London to New York", london, newYork, 5570},
		{"London to Sydney", london, sydney, 16993},
		{"London to São Paulo", london, saoPaulo, 9473},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := haversineKm(c.a.Latitude, c.a.Longitude, c.b.Latitude, c.b.Longitude)
			// Within 1%: the coordinates are city centres rounded to two places.
			if math.Abs(got-c.wantKm)/c.wantKm > 0.01 {
				t.Errorf("distance = %.0f km, want about %.0f km", got, c.wantKm)
			}
		})
	}
}

// TestHaversineNotFlatEarth.
//
// A flat approximation is wrong by roughly the cosine of the latitude -- fine
// near the equator, badly wrong in northern Europe, which is where a great many
// of these users are. Stockholm to a point ten degrees of longitude east is
// about half what the naive calculation gives.
func TestHaversineNotFlatEarth(t *testing.T) {
	east := Location{Latitude: 59.33, Longitude: 28.07, Known: true}
	got := haversineKm(stockholm.Latitude, stockholm.Longitude, east.Latitude, east.Longitude)

	naive := 10 * 111.0 // degrees of longitude times km-per-degree at the equator
	if got > naive*0.75 {
		t.Errorf("distance = %.0f km; a flat approximation would give %.0f, and at "+
			"latitude 59 the real answer is about half that", got, naive)
	}
}

func TestImpossibleTravelIsDetected(t *testing.T) {
	now := time.Now()
	v := CheckTravel(
		at(london, now.Add(-11*time.Minute)),
		at(saoPaulo, now),
	)
	if !v.Checked {
		t.Fatalf("the check did not run: %s", v.Reason)
	}
	if !v.Impossible {
		t.Fatalf("London to São Paulo in 11 minutes was called plausible: %s", v.Reason)
	}
	if !strings.Contains(v.Reason, "km/h") {
		t.Errorf("the reason should give the implied speed; got %q", v.Reason)
	}
}

// TestALongHaulFlightIsNotFlagged.
//
// The threshold is set at aircraft cruise speed deliberately. Flagging every
// long-haul flight produces an alert per business traveller per trip, and a
// detector that fires on ordinary behaviour is disabled within a week.
func TestALongHaulFlightIsNotFlagged(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		from, to Location
		hours    float64
	}{
		{"London to New York, 8 hours", london, newYork, 8},
		{"London to Sydney, 22 hours", london, sydney, 22},
		{"London to Paris on the train, 2.5 hours", london, paris, 2.5},
		{"London to São Paulo, 12 hours", london, saoPaulo, 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := CheckTravel(
				at(c.from, now.Add(-time.Duration(c.hours*float64(time.Hour)))),
				at(c.to, now),
			)
			if v.Impossible {
				t.Errorf("a real journey was flagged as impossible: %s", v.Reason)
			}
		})
	}
}

// TestUnknownPositionDoesNotAccuse.
//
// "We did not check" and "we checked and it was fine" must never be the same
// answer -- one of them is a gap somebody should close, and treating a missing
// GeoIP database as a clean bill of health hides it forever.
func TestUnknownPositionDoesNotAccuse(t *testing.T) {
	now := time.Now()
	unknown := Location{Known: false, At: now}

	for _, c := range []struct {
		name string
		a, b Location
	}{
		{"previous unknown", unknown, at(london, now)},
		{"current unknown", at(london, now.Add(-time.Hour)), unknown},
		{"both unknown", unknown, unknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := CheckTravel(c.a, c.b)
			if v.Impossible {
				t.Error("accused somebody on the basis of a position we do not have")
			}
			if v.Checked {
				t.Error("reported that a check ran when there was nothing to compare")
			}
			if v.Reason == "" {
				t.Error("no reason given for not checking")
			}
		})
	}
}

// TestZeroZeroIsNotTreatedAsAPosition.
//
// (0,0) is a real place in the Atlantic. A nil-handling bug that leaves
// coordinates at their zero value will happily put somebody there and then flag
// their next sign-in as impossible travel from the Gulf of Guinea.
func TestZeroZeroIsNotTreatedAsAPosition(t *testing.T) {
	now := time.Now()
	nullIsland := Location{Latitude: 0, Longitude: 0, Known: false, At: now.Add(-time.Hour)}
	v := CheckTravel(nullIsland, at(london, now))
	if v.Checked {
		t.Error("an unset coordinate pair was treated as a position in the Atlantic")
	}
}

// TestTooCloseTogetherIsNotChecked.
//
// Two sign-ins seconds apart from the same building can compute an absurd speed
// out of a kilometre of coordinate rounding. Below the floor the answer is "not
// checked", not a confident wrong one.
func TestTooCloseTogetherIsNotChecked(t *testing.T) {
	now := time.Now()
	v := CheckTravel(at(london, now.Add(-5*time.Second)), at(paris, now))
	if v.Checked {
		t.Errorf("checked two sign-ins 5 seconds apart: %s", v.Reason)
	}
	if v.Impossible {
		t.Error("flagged them as impossible")
	}
}

// TestOutOfOrderIsNotChecked. Comparing them anyway computes a negative speed
// and calls it plausible.
func TestOutOfOrderIsNotChecked(t *testing.T) {
	now := time.Now()
	v := CheckTravel(at(london, now), at(saoPaulo, now.Add(-time.Hour)))
	if v.Checked {
		t.Error("compared two sign-ins in the wrong order")
	}
	if v.Impossible {
		t.Error("a negative interval produced an accusation")
	}
}

// TestSameCityIsFine -- the most common case by far.
func TestSameCityIsFine(t *testing.T) {
	now := time.Now()
	v := CheckTravel(at(london, now.Add(-2*time.Minute)), at(london, now))
	if !v.Checked {
		t.Fatalf("did not check: %s", v.Reason)
	}
	if v.Impossible {
		t.Errorf("two sign-ins from the same city were flagged: %s", v.Reason)
	}
}

func TestRoundCoarse(t *testing.T) {
	// About a kilometre. Enough for a speed over hundreds of kilometres, useless
	// for finding a house.
	cases := map[float64]float64{
		51.5074456: 51.51,
		-0.1277653: -0.13,
		-23.550520: -23.55,
		0.0:        0.0,
	}
	for in, want := range cases {
		if got := RoundCoarse(in); math.Abs(got-want) > 1e-9 {
			t.Errorf("RoundCoarse(%v) = %v, want %v", in, got, want)
		}
	}
}

// TestThresholdBoundary pins the line, since moving it changes who gets flagged.
func TestThresholdBoundary(t *testing.T) {
	now := time.Now()
	// A journey at exactly the threshold speed is plausible; faster is not.
	const hours = 2.0
	km := MaxPlausibleSpeedKmh * hours

	// Two points on the equator, where a degree of longitude is ~111.32 km.
	from := Location{Latitude: 0, Longitude: 0, Known: true, At: now.Add(-2 * time.Hour)}
	atThreshold := Location{Latitude: 0, Longitude: km / 111.32, Known: true, At: now}
	if v := CheckTravel(from, atThreshold); v.Impossible {
		t.Errorf("a journey at exactly the threshold was flagged: %s", v.Reason)
	}

	tooFar := Location{Latitude: 0, Longitude: (km * 1.2) / 111.32, Known: true, At: now}
	if v := CheckTravel(from, tooFar); !v.Impossible {
		t.Errorf("a journey 20%% over the threshold was not flagged: %s", v.Reason)
	}
}

func TestStaticResolver(t *testing.T) {
	r, err := newStaticResolver(
		"10.0.0.0/8=GB,51.51,-0.13; 198.51.100.0/24=BR,-23.55,-46.63")
	if err != nil {
		t.Fatal(err)
	}
	if loc := r.Resolve("10.1.2.3"); !loc.Known || loc.Country != "GB" {
		t.Errorf("10.1.2.3 resolved to %+v", loc)
	}
	if loc := r.Resolve("198.51.100.7"); !loc.Known || loc.Country != "BR" {
		t.Errorf("198.51.100.7 resolved to %+v", loc)
	}
	// Outside every range: unknown, NOT a default position. Putting unrecognised
	// addresses at a fixed point makes every one of them look like impossible
	// travel from the office.
	if loc := r.Resolve("203.0.113.9"); loc.Known {
		t.Errorf("an address outside every range got a position: %+v", loc)
	}
	if loc := r.Resolve("not-an-ip"); loc.Known {
		t.Error("a hostname was resolved to a position")
	}
}

func TestStaticResolverRejectsNonsense(t *testing.T) {
	for _, spec := range []string{"nonsense", "10.0.0.0/8", "10.0.0.0/8=GB,notalat,0", "999.0.0.0/8=GB,1,2"} {
		if _, err := newStaticResolver(spec); err == nil {
			t.Errorf("accepted %q", spec)
		}
	}
}
