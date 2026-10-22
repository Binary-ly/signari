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

// SessionLifetimes are an organisation's two limits. Idle 0 is none.
type SessionLifetimes struct {
	Lifetime time.Duration
	Idle     time.Duration
}

// SessionLifetimesOf reads an organisation's.
func SessionLifetimesOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (SessionLifetimes, error) {
	var lifetime int
	var idle *int
	err := q.QueryRow(ctx, `SELECT session_lifetime_s, session_idle_s FROM core.organizations
		WHERE id = $1::uuid`, orgID).Scan(&lifetime, &idle)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionLifetimes{}, ErrOrganizationNotFound
	}
	if err != nil {
		return SessionLifetimes{}, err
	}
	out := SessionLifetimes{Lifetime: time.Duration(lifetime) * time.Second}
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
