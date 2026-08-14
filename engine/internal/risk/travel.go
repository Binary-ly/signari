// Package risk detects signals that an authentication is not what it appears.
//
// # Impossible travel
//
// Somebody authenticates from London, and eleven minutes later from São Paulo.
// Nobody did that. Either the credential is shared, or one of the two sessions
// is not the person it claims to be.
//
// It is a genuinely useful signal and a genuinely noisy one, and most of the
// design here is about the noise. A detector that cries wolf is turned off, and
// a detector that is turned off catches nothing.
package risk

import (
	"fmt"
	"math"
	"time"
)

// Location is a coarse position.
//
// Latitude and longitude are rounded to about a kilometre before they are ever
// stored. That is enough to compute a plausible speed over hundreds of
// kilometres and useless for finding where somebody lives.
type Location struct {
	Country   string
	Region    string
	Latitude  float64
	Longitude float64
	// Known is false when no position could be determined -- no GeoIP database
	// configured, or an address that is not in it. Distinguished from a position
	// at (0,0), which is a real place in the Atlantic that a nil-handling bug
	// will happily put somebody.
	Known bool
	At    time.Time
}

// Verdict is the outcome of a travel check.
type Verdict struct {
	// Impossible is true only when the check RAN and failed.
	Impossible bool
	// Checked is false when there was nothing to compare against. "We did not
	// check" and "we checked and it was fine" must never be the same answer:
	// one of them is a gap somebody should close.
	Checked bool
	// Reason explains the verdict, including why it did not run.
	Reason string

	DistanceKm float64
	Elapsed    time.Duration
	SpeedKmh   float64
}

// MaxPlausibleSpeedKmh is the threshold.
//
// 900 km/h is roughly a commercial jet's cruise. It is set at the aircraft speed
// rather than something lower because the alternative -- flagging every
// long-haul flight -- produces an alert per business traveller per trip, and a
// detector that fires on ordinary behaviour gets disabled within a week.
//
// Anything above this is not slow travel; it is two places at once.
const MaxPlausibleSpeedKmh = 900

// MinElapsed is the shortest gap the check will reason about.
//
// Under a minute, small clock differences and rounding dominate: two
// authentications 5 seconds apart from the same building can compute an absurd
// speed from a kilometre of rounding error. Below this the answer is "not
// checked" rather than a confident wrong one.
const MinElapsed = 60 * time.Second

// CheckTravel compares two authentications.
func CheckTravel(previous, current Location) Verdict {
	if !previous.Known || !current.Known {
		return Verdict{
			Checked: false,
			Reason: "no position for one of the two sign-ins, so travel was not " +
				"checked (is a GeoIP database configured?)",
		}
	}
	if previous.At.IsZero() || current.At.IsZero() {
		return Verdict{Checked: false, Reason: "one of the sign-ins has no timestamp"}
	}

	elapsed := current.At.Sub(previous.At)
	if elapsed < 0 {
		// Out of order. Comparing them anyway would compute a negative speed and
		// call it fine.
		return Verdict{Checked: false, Reason: "the sign-ins are out of order"}
	}
	if elapsed < MinElapsed {
		return Verdict{
			Checked: false, Elapsed: elapsed,
			Reason: fmt.Sprintf("only %s apart; too close together for the distance "+
				"to mean anything", elapsed.Round(time.Second)),
		}
	}

	km := haversineKm(previous.Latitude, previous.Longitude, current.Latitude, current.Longitude)
	speed := km / elapsed.Hours()

	v := Verdict{
		Checked: true, DistanceKm: km, Elapsed: elapsed, SpeedKmh: speed,
	}
	if speed > MaxPlausibleSpeedKmh {
		v.Impossible = true
		v.Reason = fmt.Sprintf("%.0f km in %s implies %.0f km/h, which is not travel",
			km, elapsed.Round(time.Minute), speed)
		return v
	}
	v.Reason = fmt.Sprintf("%.0f km in %s (%.0f km/h) is plausible",
		km, elapsed.Round(time.Minute), speed)
	return v
}

// haversineKm is the great-circle distance between two points.
//
// Great-circle rather than a flat approximation, because the flat one is wrong
// by a factor of the cosine of the latitude -- fine near the equator, badly
// wrong in northern Europe, which is where a great many of these users are.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0

	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat := rad(lat2 - lat1)
	dLon := rad(lon2 - lon1)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusKm * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

// RoundCoarse rounds a coordinate before it is stored.
//
// Two decimal places, about a kilometre. Applied at the WRITE, not at read time:
// a precise value that is only rounded when displayed is still a precise value
// in the database, and the database is what leaks.
func RoundCoarse(v float64) float64 {
	return math.Round(v*100) / 100
}
