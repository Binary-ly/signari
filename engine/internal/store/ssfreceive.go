package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/ssf"
)

// Sources we accept Shared Signals from, and what we did with what they sent.

// ErrAmbiguousSource means a token's audiences name sources in more than one
// organisation for its issuer, so nothing can say whose event it is.
var ErrAmbiguousSource = errors.New("the token's audiences name more than one " +
	"organisation's source for its issuer")

// SourceFor finds the enabled source a token is for, by its issuer and its
// audiences, read unverified.
//
// Both, because two organisations can trust one transmitter, and the audience
// is what the transmitter writes to say which of them an event is for. The
// issuer alone picked whichever tenant's row came back first, and that
// tenant's directory resolved the subject. Reading the pair before verifying
// is safe: it selects WHICH keys to verify against rather than granting
// anything, and Verify checks both again.
//
// The pair is unique across organisations (migration 0138), so one audience
// finds at most one source. A token naming several audiences could still name
// two organisations' sources, and that is refused rather than resolved. Only
// instanceID's sources are looked at (6.12).
func SourceFor(ctx context.Context, q Querier, issuer string, audiences []string, instanceID string) (ssf.Source, bool, error) {
	var s ssf.Source
	lowered := make([]string, 0, len(audiences))
	for _, a := range audiences {
		lowered = append(lowered, strings.ToLower(a))
	}
	rows, err := q.Query(ctx, `
		SELECT id::text, org_id::text, issuer, jwks_uri, audience, allowed_events,
		       critical_subject_members
		  FROM core.ssf_sources
		 WHERE issuer = $1 AND lower(audience) = ANY($2::text[]) AND enabled
		   AND `+InInstance("org_id", "$3")+`
		 LIMIT 2`, issuer, lowered, instanceID)
	if err != nil {
		return s, false, err
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		if found++; found > 1 {
			return ssf.Source{}, false, ErrAmbiguousSource
		}
		if err := rows.Scan(&s.ID, &s.OrgID, &s.Issuer, &s.JWKSURI,
			&s.Audience, &s.AllowedEvents, &s.CriticalSubjectMembers); err != nil {
			return ssf.Source{}, false, err
		}
	}
	if err := rows.Err(); err != nil {
		return ssf.Source{}, false, err
	}
	return s, found == 1, nil
}

// AudienceIsReceived reports whether any enabled source accepts tokens
// addressed to one of these audiences, whatever their issuer.
//
// Only for choosing the registered error code when SourceFor finds nothing: a
// token addressed to a recipient here carries an issuer that recipient does not
// accept (`invalid_issuer`), and one addressed elsewhere is not for us at all
// (`invalid_audience`). It selects no source. "Here" is instanceID (6.12).
func AudienceIsReceived(ctx context.Context, q rowQuerier, audiences []string, instanceID string) (bool, error) {
	lowered := make([]string, 0, len(audiences))
	for _, a := range audiences {
		lowered = append(lowered, strings.ToLower(a))
	}
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.ssf_sources
		                WHERE lower(audience) = ANY($1::text[]) AND enabled
		                  AND `+InInstance("org_id", "$2")+`)`,
		lowered, instanceID).Scan(&ok)
	return ok, err
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
	if err != nil && strings.Contains(err.Error(), "ssf_sources_issuer_audience_key") {
		return fmt.Errorf("%w: another organisation already accepts events from %s addressed "+
			"to %s; the receiver chooses a source by that pair, so it would not know whose "+
			"they are. Use the audience the transmitter writes for this organisation",
			ErrSourceAudienceTaken, issuer, audience)
	}
	return err
}

// SetSSFSourceEnabled stops or resumes accepting a transmitter's events, as a
// pruned configuration file asks (6.25): switched off rather than deleted,
// since deleting it takes the record of what it sent.
func SetSSFSourceEnabled(ctx context.Context, e Execer, orgID, issuer string, enabled bool) error {
	_, err := e.Exec(ctx, `UPDATE core.ssf_sources SET enabled = $3 WHERE org_id = $1::uuid AND issuer = $2`,
		orgID, issuer, enabled)
	return err
}

// ErrSourceAudienceTaken is an issuer and audience another organisation's
// source already has.
var ErrSourceAudienceTaken = errors.New("that issuer and audience belong to another organisation's source")

// Source is one transmitter an organisation accepts events from.
type Source struct {
	ID, Name, Issuer, JWKSURI, Audience string
	Events, CriticalMembers             []string
	Enabled                             bool
}

// Sources lists an organisation's transmitters by name.
func Sources(ctx context.Context, q Querier, orgID string) ([]Source, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, display_name, issuer, jwks_uri, audience, allowed_events, critical_subject_members, enabled
		  FROM core.ssf_sources WHERE org_id = $1::uuid ORDER BY display_name, issuer`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.ID, &s.Name, &s.Issuer, &s.JWKSURI, &s.Audience, &s.Events, &s.CriticalMembers,
			&s.Enabled); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
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
