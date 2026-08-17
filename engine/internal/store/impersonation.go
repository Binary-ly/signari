package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Support access: an administrator acting as a user.
//
// The rules enforced here are the ones that separate a support feature from a
// back door, and each is refused rather than logged:
//
//   - It is never silent. The session carries the administrator's identity into
//     every token minted from it, as the RFC 8693 `act` claim.
//   - It ends by itself. Support access nobody remembered to close is a live
//     administrative session wearing somebody else's name.
//   - It cannot chain. An impersonated session cannot start another one, or the
//     actor recorded is the person being impersonated.
//   - It needs a reason, and the reason is stored.

// ErrImpersonationRefused is returned when the rules refuse it.
var ErrImpersonationRefused = fmt.Errorf("impersonation refused")

// Impersonation is one episode of support access.
type Impersonation struct {
	ID        string
	OrgID     string
	ActorID   string
	SubjectID string
	Reason    string
	SID       string
	StartedAt time.Time
	ExpiresAt time.Time
}

// MaxImpersonation bounds how long support access can last.
//
// Short on purpose. An administrator who needs longer can start again, and the
// second reason is a second audit row -- which is the record an investigation
// actually wants.
const MaxImpersonation = 30 * time.Minute

// BeginImpersonation records the episode and returns it.
//
// The session is created by the caller and attached with AttachImpersonation,
// because the session and the record must land in the same transaction: an
// episode with no session is a puzzle, and a session with no episode is an
// administrator wearing somebody's name with nothing saying so.
func BeginImpersonation(ctx context.Context, tx pgx.Tx, orgID, actorID, subjectID,
	reason, correlationID string, ttl time.Duration) (Impersonation, error) {

	var im Impersonation
	if actorID == subjectID {
		// Not a quirk. Impersonating yourself launders an action into one that
		// cannot be attributed to the person who took it.
		return im, fmt.Errorf("%w: an administrator cannot impersonate themselves",
			ErrImpersonationRefused)
	}
	if len(trimSpace(reason)) < 8 {
		return im, fmt.Errorf("%w: a reason is required, and \"%s\" is not one",
			ErrImpersonationRefused, reason)
	}
	if ttl <= 0 || ttl > MaxImpersonation {
		ttl = MaxImpersonation
	}

	// The subject must be in the same organisation. Crossing that boundary is
	// not support access, it is a tenant breach with a support feature's name on
	// it -- and RLS would not catch it, because the ENGINE is exempt from RLS by
	// design and this runs as the engine.
	var subjectOrg string
	if err := tx.QueryRow(ctx,
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, subjectID).
		Scan(&subjectOrg); err != nil {
		return im, fmt.Errorf("%w: no such user", ErrImpersonationRefused)
	}
	if subjectOrg != orgID {
		return im, fmt.Errorf("%w: that user belongs to another organisation",
			ErrImpersonationRefused)
	}

	// An impersonated session cannot start another. Otherwise the actor recorded
	// on the second episode is the person being impersonated on the first, and
	// the chain back to a real administrator is broken at exactly the point
	// somebody would want to follow it.
	var chained bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM core.impersonations
			 WHERE subject_id = $1::uuid AND ended_at IS NULL AND expires_at > now())`,
		actorID).Scan(&chained); err != nil {
		return im, err
	}
	if chained {
		return im, fmt.Errorf("%w: this is already an impersonated session, and "+
			"impersonation cannot be chained", ErrImpersonationRefused)
	}

	err := tx.QueryRow(ctx, `
		INSERT INTO core.impersonations
			(org_id, actor_id, subject_id, reason, expires_at, correlation_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, now() + $5::interval, $6)
		RETURNING id::text, started_at, expires_at`,
		orgID, actorID, subjectID, reason,
		fmt.Sprintf("%d seconds", int(ttl.Seconds())), correlationID).
		Scan(&im.ID, &im.StartedAt, &im.ExpiresAt)
	if err != nil {
		return im, fmt.Errorf("recording impersonation: %w", err)
	}
	im.OrgID, im.ActorID, im.SubjectID, im.Reason = orgID, actorID, subjectID, reason
	return im, nil
}

// AttachImpersonation binds the episode to the session created for it.
func AttachImpersonation(ctx context.Context, tx pgx.Tx, id, sid, actorID string) error {
	if _, err := tx.Exec(ctx,
		`UPDATE core.impersonations SET sid = $2 WHERE id = $1::uuid`, id, sid); err != nil {
		return err
	}
	// Written on the session too, so minting a token needs no join and cannot
	// forget one. A token that omits `act` is the failure this whole feature
	// exists to avoid.
	_, err := tx.Exec(ctx,
		`UPDATE core.sessions SET impersonator_id = $2::uuid WHERE sid = $1`, sid, actorID)
	return err
}

// EndImpersonation closes the episode and revokes its session.
func EndImpersonation(ctx context.Context, tx pgx.Tx, sid, why string) error {
	var id string
	err := tx.QueryRow(ctx, `
		UPDATE core.impersonations
		   SET ended_at = now(), ended_reason = $2
		 WHERE sid = $1 AND ended_at IS NULL
		RETURNING id::text`, sid, why).Scan(&id)
	if err == pgx.ErrNoRows {
		return nil // already ended, or never an impersonation
	}
	if err != nil {
		return err
	}
	// Through the one termination path, so relying parties are told. An episode
	// marked ended whose session still works is a record that lies.
	_, err = TerminateSessions(ctx, tx, sid, "", ReasonImpersonationEnded)
	return err
}

// ActorFor returns the administrator behind a session, or "".
func ActorFor(ctx context.Context, q Querier, sid string) (string, error) {
	rows, err := q.Query(ctx, `
		SELECT COALESCE(u.email, i.actor_id::text)
		  FROM core.sessions s
		  JOIN core.impersonations i ON i.sid = s.sid AND i.ended_at IS NULL
		  JOIN core.users u ON u.id = s.impersonator_id
		 WHERE s.sid = $1 AND s.impersonator_id IS NOT NULL AND i.expires_at > now()`, sid)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var actor string
		if err := rows.Scan(&actor); err != nil {
			return "", err
		}
		return actor, nil
	}
	return "", rows.Err()
}

// ExpireImpersonations ends episodes that ran out, and revokes their sessions.
//
// Called by the janitor. Without it "expires_at" is a column nobody reads, and
// support access lasts until someone happens to sign out.
func ExpireImpersonations(ctx context.Context, tx pgx.Tx) (int, error) {
	rows, err := tx.Query(ctx, `
		UPDATE core.impersonations
		   SET ended_at = now(), ended_reason = 'expired'
		 WHERE ended_at IS NULL AND expires_at <= now()
		RETURNING COALESCE(sid,'')`)
	if err != nil {
		return 0, err
	}
	var sids []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			rows.Close()
			return 0, err
		}
		if sid != "" {
			sids = append(sids, sid)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, sid := range sids {
		if _, err := TerminateSessions(ctx, tx, sid, "", ReasonImpersonationEnded); err != nil {
			return len(sids), err
		}
	}
	return len(sids), nil
}

// trimSpace without importing strings for one call.
func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

// MayImpersonate reports whether this user holds the capability.
//
// Membership of a group carrying `may_impersonate`, not a role. One power, named
// explicitly, granted to nobody by default -- a feature like this arriving
// switched on for whoever is in a group called "admins" is a privilege
// escalation delivered by an upgrade.
func MayImpersonate(ctx context.Context, q Querier, orgID, userID string) (bool, error) {
	rows, err := q.Query(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM core.group_members m
			  JOIN core.groups g ON g.id = m.group_id
			 WHERE m.user_id = $1::uuid AND g.org_id = $2::uuid AND g.may_impersonate)`,
		userID, orgID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if rows.Next() {
		var may bool
		if err := rows.Scan(&may); err != nil {
			return false, err
		}
		return may, nil
	}
	return false, rows.Err()
}
