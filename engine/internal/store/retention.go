package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Retention is how long rows nothing reads any more are kept (3.17). Each of
// these tables only grew: an ended session, a delivered notice, a received
// event, a superseded password hash stayed for ever, and a deployment's
// database grew with every sign-in it had ever served.
type Retention struct {
	// Sessions is how long an ended session is kept. Deleting it deletes its
	// applications list and its refresh families with it, all of them ended
	// with the session.
	Sessions time.Duration
	// Families is how long a refresh-token family is kept once it was revoked
	// or its newest token expired, its tokens with it. A token of a live
	// family is never deleted here, rotated ones included, since presenting a
	// rotated token is how a stolen one is caught.
	Families time.Duration
	// Delivered is how long a delivered outbox row or event delivery is kept;
	// an undelivered event delivery is dropped at the same age.
	Delivered time.Duration
	// Received is how long a received security event is kept.
	Received time.Duration
	// Locations is how long a sign-in location is kept, except each person's
	// newest one, which the next sign-in is compared with.
	Locations time.Duration
	// Nonces is how long a credential nonce is kept past its expiry.
	Nonces time.Duration
	// PasswordHistory is how many retired password hashes are kept per person:
	// the depth the reuse check reads. Zero keeps every one, so a policy that
	// is unset destroys nothing a later one would need.
	PasswordHistory int
}

// DefaultRetention is what a deployment that sets nothing keeps.
func DefaultRetention() Retention {
	return Retention{
		Sessions:  30 * 24 * time.Hour,
		Families:  30 * 24 * time.Hour,
		Delivered: 7 * 24 * time.Hour,
		Received:  90 * 24 * time.Hour,
		Locations: 90 * 24 * time.Hour,
		Nonces:    24 * time.Hour,
	}
}

// RetentionTables are the tables PurgeRetained deletes from, in its order;
// the metrics label set.
var RetentionTables = []string{
	"sessions", "refresh_token_families", "outbox", "event_deliveries",
	"ssf_received", "auth_locations", "credential_nonces", "password_history",
}

// PurgeRetained deletes up to batch rows per table that the retention says
// nothing needs, and says how many from each. Batched like the session sweep,
// so a first pass over years of rows is many short transactions rather than
// one long one.
func PurgeRetained(ctx context.Context, tx pgx.Tx, r Retention, batch int) (map[string]int, error) {
	interval := func(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }
	jobs := []struct {
		table, sql string
		args       []any
	}{
		{"sessions", `
			DELETE FROM core.sessions WHERE sid IN (
				SELECT sid FROM core.sessions
				WHERE revoked_at < now() - $1::interval LIMIT $2)`,
			[]any{interval(r.Sessions), batch}},
		{"refresh_token_families", `
			DELETE FROM core.refresh_token_families WHERE id IN (
				SELECT f.id FROM core.refresh_token_families f
				WHERE f.revoked_at < now() - $1::interval
				   OR (f.revoked_at IS NULL AND NOT EXISTS (
				        SELECT 1 FROM core.refresh_tokens t
				        WHERE t.family_id = f.id AND t.expires_at > now() - $1::interval)
				       AND f.created_at < now() - $1::interval)
				LIMIT $2)`,
			[]any{interval(r.Families), batch}},
		{"outbox", `
			DELETE FROM core.outbox WHERE id IN (
				SELECT id FROM core.outbox WHERE delivered_at < now() - $1::interval LIMIT $2)`,
			[]any{interval(r.Delivered), batch}},
		{"event_deliveries", `
			DELETE FROM core.event_deliveries WHERE id IN (
				SELECT id FROM core.event_deliveries
				WHERE COALESCE(delivered_at, created_at) < now() - $1::interval LIMIT $2)`,
			[]any{interval(r.Delivered), batch}},
		{"ssf_received", `
			DELETE FROM core.ssf_received WHERE id IN (
				SELECT id FROM core.ssf_received WHERE received_at < now() - $1::interval LIMIT $2)`,
			[]any{interval(r.Received), batch}},
		{"auth_locations", `
			DELETE FROM core.auth_locations WHERE id IN (
				SELECT l.id FROM core.auth_locations l
				WHERE l.occurred_at < now() - $1::interval
				  AND l.id <> COALESCE((
				      SELECT n.id FROM core.auth_locations n
				      WHERE n.user_id = l.user_id AND n.source = 'geoip' AND n.latitude IS NOT NULL
				      ORDER BY n.occurred_at DESC LIMIT 1), -1)
				LIMIT $2)`,
			[]any{interval(r.Locations), batch}},
		{"credential_nonces", `
			DELETE FROM core.credential_nonces WHERE nonce_hash IN (
				SELECT nonce_hash FROM core.credential_nonces
				WHERE expires_at < now() - $1::interval LIMIT $2)`,
			[]any{interval(r.Nonces), batch}},
	}
	if r.PasswordHistory > 0 {
		jobs = append(jobs, struct {
			table, sql string
			args       []any
		}{"password_history", `
			DELETE FROM core.password_history WHERE id IN (
				SELECT id FROM (
					SELECT id, row_number() OVER (PARTITION BY user_id ORDER BY retired_at DESC) AS rank
					FROM core.password_history) h
				WHERE rank > $1 LIMIT $2)`,
			[]any{r.PasswordHistory, batch}})
	}

	out := map[string]int{}
	for _, j := range jobs {
		tag, err := tx.Exec(ctx, j.sql, j.args...)
		if err != nil {
			return out, fmt.Errorf("retention of %s: %w", j.table, err)
		}
		out[j.table] = int(tag.RowsAffected())
	}
	return out, nil
}
