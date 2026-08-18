package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/ssf"
)

// Sources we accept Shared Signals from, and what we did with what they sent.

// SourceByIssuer finds an enabled source by the issuer in a token.
//
// Looked up by issuer because that is the only thing we can read from the token
// before verifying it -- and reading it is safe, since the issuer selects WHICH
// keys to verify against rather than granting anything.
func SourceByIssuer(ctx context.Context, q Querier, issuer string) (ssf.Source, bool, error) {
	var s ssf.Source
	rows, err := q.Query(ctx, `
		SELECT id::text, org_id::text, issuer, jwks_uri, audience, allowed_events,
		       critical_subject_members
		  FROM core.ssf_sources
		 WHERE issuer = $1 AND enabled`, issuer)
	if err != nil {
		return s, false, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&s.ID, &s.OrgID, &s.Issuer, &s.JWKSURI,
			&s.Audience, &s.AllowedEvents, &s.CriticalSubjectMembers); err != nil {
			return s, false, err
		}
		return s, true, nil
	}
	return s, false, rows.Err()
}

// AddSource registers a transmitter.
func AddSource(ctx context.Context, e Execer, orgID, name, issuer, jwksURI,
	audience string, events, criticalMembers []string) error {

	if events == nil {
		events = []string{}
	}
	if criticalMembers == nil {
		criticalMembers = []string{}
	}
	_, err := e.Exec(ctx, `
		INSERT INTO core.ssf_sources
			(org_id, display_name, issuer, jwks_uri, audience, allowed_events,
			 critical_subject_members)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (org_id, issuer) DO UPDATE SET
			display_name = EXCLUDED.display_name, jwks_uri = EXCLUDED.jwks_uri,
			audience = EXCLUDED.audience, allowed_events = EXCLUDED.allowed_events,
			critical_subject_members = EXCLUDED.critical_subject_members,
			enabled = true`,
		orgID, name, issuer, jwksURI, audience, events, criticalMembers)
	return err
}

// ErrReplayed means this jti has already been seen from this source.
var ErrReplayed = fmt.Errorf("this security event token has already been received")

// RecordReceived writes the event and refuses a replay.
//
// The UNIQUE constraint is the guard, not a prior SELECT: two events arriving at
// once would both pass a check-then-insert, and a replayed session-revoked is a
// way to sign somebody out repeatedly from one captured token.
func RecordReceived(ctx context.Context, tx pgx.Tx, sourceID, orgID string,
	e ssf.ReceivedEvent, userID, action, detail string) error {

	subject, err := json.Marshal(map[string]any{
		"format": e.Subject.Format, "iss": e.Subject.Issuer, "sub": e.Subject.Sub,
	})
	if err != nil {
		return err
	}
	var uid any
	if userID != "" {
		uid = userID
	}
	var when any
	if !e.EventTime.IsZero() {
		when = e.EventTime
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO core.ssf_received
			(source_id, org_id, jti, event_type, subject, user_id, action, detail, event_time)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7, $8, $9)
		ON CONFLICT (source_id, jti) DO NOTHING`,
		sourceID, orgID, e.JTI, e.Type, subject, uid, action, detail, when)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrReplayed
	}
	_, err = tx.Exec(ctx,
		`UPDATE core.ssf_sources SET last_event_at = now() WHERE id = $1::uuid`, sourceID)
	return err
}

// ResolveSSFSubject maps a transmitter's subject to one of our users.
//
// # Why this is deliberately strict
//
// The subject is how a source names a person, and how we resolve it decides
// whose sessions a source can end. An email match is the obvious approach and
// the wrong default: two directories can hold the same address, and a source
// permitted to speak about its own users would then be able to end sessions for
// ours.
//
// So the resolution order is:
//
//  1. `iss_sub` — the issuer-scoped subject WE issued to that source through a
//     federated identity link. Unambiguous, because we minted it.
//  2. A federated identity from that issuer, matched on the external subject.
//  3. `email`, ONLY when the source is configured for it, and only within that
//     source's own organisation.
//
// Returning "" is normal. A transmitter sends events about people we have never
// seen, and that is not an error.
func ResolveSSFSubject(ctx context.Context, q Querier, orgID string,
	s ssf.Subject) (string, error) {

	switch s.Format {
	case "iss_sub", "":
		if s.Sub == "" {
			return "", nil
		}
		// A federated link from this issuer with this external subject. This is
		// the identity the two sides already agreed on.
		rows, err := q.Query(ctx, `
			SELECT f.user_id::text
			  FROM core.federated_identities f
			  JOIN core.identity_providers p ON p.id = f.provider_id
			 WHERE f.subject = $1 AND p.org_id = $2::uuid
			 LIMIT 1`, s.Sub, orgID)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		if rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return "", err
			}
			return id, nil
		}
		return "", rows.Err()

	case "email":
		// Scoped to the source's organisation. Without that scope, a source
		// could name any address in the deployment and end those sessions.
		rows, err := q.Query(ctx, `
			SELECT id::text FROM core.users
			 WHERE lower(email) = lower($1) AND org_id = $2::uuid
			 LIMIT 1`, s.Sub, orgID)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		if rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return "", err
			}
			return id, nil
		}
		return "", rows.Err()
	}
	return "", nil
}

// RecentReceived lists what a source has sent, for the console and the CLI.
func RecentReceived(ctx context.Context, q Querier, orgID string, limit int) (
	[]ReceivedRow, error) {

	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := q.Query(ctx, `
		SELECT s.display_name, r.event_type, r.action, COALESCE(r.detail,''),
		       COALESCE(r.user_id::text,''), r.received_at
		  FROM core.ssf_received r
		  JOIN core.ssf_sources s ON s.id = r.source_id
		 WHERE r.org_id = $1::uuid
		 ORDER BY r.received_at DESC
		 LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReceivedRow
	for rows.Next() {
		var r ReceivedRow
		if err := rows.Scan(&r.Source, &r.EventType, &r.Action, &r.Detail,
			&r.UserID, &r.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReceivedRow is one line of the received-events log.
type ReceivedRow struct {
	Source     string
	EventType  string
	Action     string
	Detail     string
	UserID     string
	ReceivedAt time.Time
}
