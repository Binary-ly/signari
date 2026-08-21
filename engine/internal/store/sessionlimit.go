package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrSessionLimitReached means the person already holds as many sessions as the
// organisation permits, and the configured behaviour is to refuse rather than to
// make room.
var ErrSessionLimitReached = errors.New("this account already has the maximum number of active sessions")

// SessionLimit is one organisation's policy.
type SessionLimit struct {
	// Max is how many live sessions one person may hold. Zero means unlimited,
	// which is the default and the state of every deployment that has not
	// deliberately changed it.
	Max int
	// Behaviour is "deny" or "evict_oldest".
	Behaviour string
}

const (
	LimitDeny        = "deny"
	LimitEvictOldest = "evict_oldest"
)

// EnforceSessionLimit applies the organisation's concurrent-session policy to a
// person about to receive a new session.
//
// Called INSIDE the sign-in transaction and before the session row is written,
// so that the count it reads is the count the insert will add to. Doing this
// after the insert would need the new session excluded from its own limit, which
// is the kind of off-by-one that only shows up at the boundary.
//
// Returns the sids it ended, so the caller can record them. A person under the
// limit gets no query beyond the first.
func EnforceSessionLimit(ctx context.Context, tx pgx.Tx, orgID, userID string) ([]string, error) {
	var lim SessionLimit
	err := tx.QueryRow(ctx, `
		SELECT max_concurrent_sessions, session_limit_behaviour
		FROM core.organizations WHERE id = $1::uuid`, orgID).
		Scan(&lim.Max, &lim.Behaviour)
	if err != nil {
		return nil, fmt.Errorf("reading the session limit: %w", err)
	}
	if lim.Max <= 0 {
		return nil, nil // unlimited: the default, and the common case
	}

	// Live sessions only. An expired or revoked session is not one the person
	// can use, so counting it would refuse a sign-in on the strength of sessions
	// that no longer exist -- and since `not_after` passes without anything
	// running, that would silently tighten over time.
	rows, err := tx.Query(ctx, `
		SELECT sid FROM core.sessions
		WHERE user_id = $1::uuid AND revoked_at IS NULL AND not_after > now()
		ORDER BY auth_time ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("counting live sessions: %w", err)
	}
	var live []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			rows.Close()
			return nil, err
		}
		live = append(live, sid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The new session is not written yet, so room exists while live < Max.
	if len(live) < lim.Max {
		return nil, nil
	}

	if lim.Behaviour == LimitDeny {
		return nil, ErrSessionLimitReached
	}

	// evict_oldest: end as many of the oldest as it takes to leave one space.
	// More than one can be needed if the limit was lowered while sessions were
	// open, which is exactly when an operator most wants it applied.
	need := len(live) - lim.Max + 1
	var ended []string
	for i := 0; i < need && i < len(live); i++ {
		// Through TerminateSessions rather than an UPDATE: it is what emits the
		// back-channel logout notice with `sid` and no `sub`, so relying parties
		// end that one session rather than all of the person's. An eviction that
		// skipped it would leave every RP believing the session was still live.
		if _, err := TerminateSessions(ctx, tx, live[i], "", ReasonSessionLimit); err != nil {
			return ended, fmt.Errorf("evicting session %s: %w", live[i], err)
		}
		ended = append(ended, live[i])
	}
	return ended, nil
}
