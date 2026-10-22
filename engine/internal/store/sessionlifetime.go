package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// How long a session lasts, per organisation, and how long unused (5.09).
//
// Migration 0180 gives every session two deadlines: absolute_not_after, fixed
// at sign-in, and not_after, which every liveness check reads and which use
// moves, never past the first (a CHECK holds it there). touchSet is that move,
// shared by the two places use is seen -- the browser presenting its cookie
// (ResolveSessionCookie) and an application refreshing a token (TouchSession)
// -- so they cannot disagree about what using a session does.

const (
	// DefaultSessionLifetime is what an organisation has until it is changed:
	// the twelve hours that used to be a constant.
	DefaultSessionLifetime = 12 * time.Hour
	MinSessionLifetime     = 5 * time.Minute
	MaxSessionLifetime     = 30 * 24 * time.Hour
	// MinSessionIdle is five times the granularity a touch is written at, so a
	// session in use always has minutes in hand rather than seconds.
	MinSessionIdle = 5 * time.Minute
)

// ErrSessionLifetime is a lifetime or idle limit outside the bounds.
var ErrSessionLifetime = fmt.Errorf("a session lifetime must be whole seconds from %s to %s, and an "+
	"idle limit from %s to the lifetime, or 0 for none", MinSessionLifetime, MaxSessionLifetime, MinSessionIdle)

// touchSet moves a session's deadline for a use now: to the sooner of its
// absolute deadline and now plus the organisation's idle limit, or, with no
// limit, to the absolute deadline. t is the session and o its organisation.
const touchSet = `last_seen_at = now(),
	not_after = CASE WHEN o.session_idle_s IS NULL THEN t.absolute_not_after
	                 ELSE least(t.absolute_not_after, now() + make_interval(secs => o.session_idle_s)) END`

// touchDue is when a use is written: a live session last written more than a
// minute ago. A session in use costs one write a minute, not one a request.
const touchDue = `t.revoked_at IS NULL AND t.not_after > now() AND t.last_seen_at < now() - interval '1 minute'`

// TouchSession records a use of sid that did not come through its cookie: an
// application refreshing a token it holds under the session.
func TouchSession(ctx context.Context, e Execer, sid string) error {
	_, err := e.Exec(ctx, `UPDATE core.sessions t SET `+touchSet+`
		  FROM core.organizations o WHERE t.sid = $1 AND o.id = t.org_id AND `+touchDue, sid)
	return err
}

// SessionLifetimes are an organisation's limits. Idle 0 is none; Offline 0
// ends a grant of offline_access with its session (5.10).
type SessionLifetimes struct {
	Lifetime time.Duration
	Idle     time.Duration
	Offline  time.Duration
	// Persistent is whether the sign-in page offers "stay signed in on this
	// device", a session cookie that outlasts the browser (5.11).
	Persistent bool
}

// SetPersistentSessions sets whether an organisation offers "stay signed in on
// this device", and returns what it replaced. Turning it off does not end the
// cookies already given; each still ends with its session.
func SetPersistentSessions(ctx context.Context, tx pgx.Tx, orgID string, on bool) (bool, error) {
	var was bool
	err := tx.QueryRow(ctx, `SELECT persistent_sessions FROM core.organizations WHERE id = $1::uuid FOR UPDATE`,
		orgID).Scan(&was)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrOrganizationNotFound
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET persistent_sessions = $2 WHERE id = $1::uuid`,
		orgID, on); err != nil {
		return false, err
	}
	return was, nil
}

const (
	// DefaultOfflineLifetime is how long a grant of offline_access lasts until
	// an organisation says otherwise.
	DefaultOfflineLifetime = 30 * 24 * time.Hour
	MinOfflineLifetime     = time.Hour
	MaxOfflineLifetime     = 365 * 24 * time.Hour
)

// ErrOfflineLifetime is an offline lifetime outside the bounds.
var ErrOfflineLifetime = fmt.Errorf("an offline lifetime must be whole seconds from %s to %s, or 0 to "+
	"end each grant with its session", MinOfflineLifetime, MaxOfflineLifetime)

// SetOfflineLifetime sets how long an organisation's grants of offline_access
// last from when each was given, and returns the lifetime it replaced and how
// many live grants now end sooner. Like a session's lifetime, a shorter one
// applies to live grants at once and a longer one lengthens none; 0 makes every
// live grant end with its session, which for most has already ended.
func SetOfflineLifetime(ctx context.Context, tx pgx.Tx, orgID string, d time.Duration) (
	previous time.Duration, sooner int, err error) {

	if d != 0 && (d < MinOfflineLifetime || d > MaxOfflineLifetime || d%time.Second != 0) {
		return 0, 0, ErrOfflineLifetime
	}
	var was int
	err = tx.QueryRow(ctx, `SELECT offline_lifetime_s FROM core.organizations WHERE id = $1::uuid FOR UPDATE`,
		orgID).Scan(&was)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, ErrOrganizationNotFound
	}
	if err != nil {
		return 0, 0, err
	}
	secs := int(d.Seconds())
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET offline_lifetime_s = $2 WHERE id = $1::uuid`,
		orgID, secs); err != nil {
		return 0, 0, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families
		   SET offline_not_after = CASE WHEN $2::int = 0 THEN NULL
		                                ELSE least(offline_not_after, created_at + make_interval(secs => $2::int)) END
		 WHERE org_id = $1::uuid AND revoked_at IS NULL AND offline_not_after > now()
		   AND ($2::int = 0 OR offline_not_after > created_at + make_interval(secs => $2::int))`, orgID, secs)
	if err != nil {
		return 0, 0, fmt.Errorf("applying the offline lifetime to live grants: %w", err)
	}
	return time.Duration(was) * time.Second, int(tag.RowsAffected()), nil
}

// SessionLifetimesOf reads an organisation's.
func SessionLifetimesOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (SessionLifetimes, error) {
	var lifetime, offline int
	var idle *int
	var persistent bool
	err := q.QueryRow(ctx, `SELECT session_lifetime_s, session_idle_s, offline_lifetime_s, persistent_sessions
		FROM core.organizations WHERE id = $1::uuid`, orgID).Scan(&lifetime, &idle, &offline, &persistent)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionLifetimes{}, ErrOrganizationNotFound
	}
	if err != nil {
		return SessionLifetimes{}, err
	}
	out := SessionLifetimes{Lifetime: time.Duration(lifetime) * time.Second,
		Offline: time.Duration(offline) * time.Second, Persistent: persistent}
	if idle != nil {
		out.Idle = time.Duration(*idle) * time.Second
	}
	return out, nil
}

// SetSessionLifetimes sets an organisation's limits and returns what they
// replaced and how many live sessions now end sooner, ended counting those
// already past their new deadline.
//
// Live sessions take the new limits at once, measured from their own sign-in
// and last use, because a limit tightened for a reason is wanted now and not
// twelve hours from now. A longer lifetime never lengthens a session already
// signed in: each keeps the lifetime it was signed in with as its ceiling. A
// longer idle limit, or none, does lengthen a live session's idle deadline,
// within that ceiling. Sessions already past their new deadline are refused
// from this commit; the janitor's sweep ends them and tells their applications.
func SetSessionLifetimes(ctx context.Context, tx pgx.Tx, orgID string, lifetime, idle time.Duration) (
	previous SessionLifetimes, sooner, ended int, err error) {

	if lifetime < MinSessionLifetime || lifetime > MaxSessionLifetime || lifetime%time.Second != 0 ||
		idle < 0 || (idle != 0 && (idle < MinSessionIdle || idle > lifetime || idle%time.Second != 0)) {
		return SessionLifetimes{}, 0, 0, ErrSessionLifetime
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM core.organizations WHERE id = $1::uuid FOR UPDATE`, orgID); err != nil {
		return SessionLifetimes{}, 0, 0, err
	}
	previous, err = SessionLifetimesOf(ctx, tx, orgID)
	if err != nil {
		return SessionLifetimes{}, 0, 0, err
	}
	var idleS *int
	if idle != 0 {
		s := int(idle.Seconds())
		idleS = &s
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET session_lifetime_s = $2, session_idle_s = $3
		WHERE id = $1::uuid`, orgID, int(lifetime.Seconds()), idleS); err != nil {
		return SessionLifetimes{}, 0, 0, err
	}
	err = tx.QueryRow(ctx, `
		WITH before AS (
			SELECT sid, not_after FROM core.sessions
			 WHERE org_id = $1::uuid AND revoked_at IS NULL AND not_after > now() FOR UPDATE),
		after AS (
			UPDATE core.sessions t
			   SET absolute_not_after = least(t.absolute_not_after, t.auth_time + make_interval(secs => $2)),
			       not_after = least(t.absolute_not_after, t.auth_time + make_interval(secs => $2),
			                         CASE WHEN $3::int IS NULL THEN t.absolute_not_after
			                              ELSE t.last_seen_at + make_interval(secs => $3::int) END)
			  FROM before b WHERE t.sid = b.sid
			RETURNING t.not_after AS now_after, b.not_after AS was)
		SELECT count(*) FILTER (WHERE now_after < was), count(*) FILTER (WHERE now_after <= now())
		  FROM after`, orgID, int(lifetime.Seconds()), idleS).Scan(&sooner, &ended)
	if err != nil {
		return SessionLifetimes{}, 0, 0, fmt.Errorf("applying the limits to live sessions: %w", err)
	}
	return previous, sooner, ended, nil
}
