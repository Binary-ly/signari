package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/risk"
)

// RecordAuthLocation stores where an authentication came from.
//
// Coordinates are rounded HERE, at the write. A precise value rounded only when
// displayed is still a precise value in the database, and the database is what
// leaks.
func RecordAuthLocation(ctx context.Context, db *pgxpool.Pool, userID, orgID string, loc risk.Location) error {
	if !loc.Known {
		// Recorded anyway, with source 'unknown'. The absence of a position is
		// itself worth keeping: it is what distinguishes "this user has never been
		// located" from "we have no history for them", and the second is what a
		// first sign-in looks like.
		_, err := db.Exec(ctx, `
			INSERT INTO core.auth_locations (user_id, org_id, source)
			VALUES ($1::uuid, $2::uuid, 'unknown')`, userID, orgID)
		return err
	}
	_, err := db.Exec(ctx, `
		INSERT INTO core.auth_locations
			(user_id, org_id, country, region, latitude, longitude, source)
		VALUES ($1::uuid, $2::uuid, NULLIF($3,''), NULLIF($4,''), $5, $6, 'geoip')`,
		userID, orgID, loc.Country, loc.Region,
		risk.RoundCoarse(loc.Latitude), risk.RoundCoarse(loc.Longitude))
	return err
}

// PreviousAuthLocation returns the most recent KNOWN position for a user.
//
// Skips the unknown rows deliberately: comparing against "we did not know where
// they were last time" answers nothing, and the last position we actually have
// is the only useful comparison.
func PreviousAuthLocation(ctx context.Context, db *pgxpool.Pool, userID string) (risk.Location, error) {
	var loc risk.Location
	var country, region *string
	var lat, lon *float64
	var at time.Time

	err := db.QueryRow(ctx, `
		SELECT country, region, latitude, longitude, occurred_at
		FROM core.auth_locations
		WHERE user_id = $1::uuid AND source = 'geoip' AND latitude IS NOT NULL
		ORDER BY occurred_at DESC
		LIMIT 1`, userID).Scan(&country, &region, &lat, &lon, &at)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return risk.Location{Known: false}, nil
		}
		return risk.Location{Known: false}, err
	}
	if lat == nil || lon == nil {
		return risk.Location{Known: false}, nil
	}
	loc.Latitude, loc.Longitude, loc.At, loc.Known = *lat, *lon, at, true
	if country != nil {
		loc.Country = *country
	}
	if region != nil {
		loc.Region = *region
	}
	return loc, nil
}
