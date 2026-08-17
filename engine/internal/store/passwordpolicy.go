package store

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"time"
)

// Previous passwords, for the reuse check.
//
// Returned most recent first, bounded by the depth the policy actually uses:
// verifying a candidate against a hash costs a full Argon2 evaluation, so
// fetching more than the policy will compare is paid for in CPU on every
// password change.
func RecentPasswordHashes(ctx context.Context, q Querier, userID string, depth int) (
	[]string, error) {

	if depth <= 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT hash FROM core.password_history
		 WHERE user_id = $1::uuid
		 ORDER BY retired_at DESC
		 LIMIT $2`, userID, depth)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RetirePassword records the outgoing hash before a new one replaces it.
//
// Called with the CURRENT hash, before the update. Doing it afterwards would
// record the new password as a previous one and refuse it on the next change.
func RetirePassword(ctx context.Context, e Execer, userID, orgID string) error {
	_, err := e.Exec(ctx, `
		INSERT INTO core.password_history (user_id, org_id, hash, algorithm)
		SELECT user_id, org_id, hash, algorithm
		  FROM core.password_credentials
		 WHERE user_id = $1::uuid`, userID)
	return err
}

// EmailForUser returns the address, for the contextual password check.
//
// A password containing the person's own address is guessable by anyone who
// knows who they are, and no composition rule catches that.
func EmailForUser(ctx context.Context, q Querier, userID string) (string, error) {
	rows, err := q.Query(ctx,
		`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid`, userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return "", err
		}
		return email, nil
	}
	return "", rows.Err()
}

// Execer is the write half, kept separate from Querier so a function that only
// reads cannot be handed something that writes by accident.
type Execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// PasswordChangeRequired reports whether this credential must be replaced
// before a session is created, and why.
//
// The reason is returned with it because an unexplained demand to change a
// password is indistinguishable from phishing -- and a user who has been
// trained to comply with unexplained demands is the vulnerability.
func PasswordChangeRequired(ctx context.Context, q Querier, userID string) (bool, string, error) {
	rows, err := q.Query(ctx,
		`SELECT must_change, COALESCE(must_change_reason,'')
		   FROM core.password_credentials WHERE user_id = $1::uuid`, userID)
	if err != nil {
		return false, "", err
	}
	defer rows.Close()
	if rows.Next() {
		var must bool
		var reason string
		if err := rows.Scan(&must, &reason); err != nil {
			return false, "", err
		}
		return must, reason, nil
	}
	return false, "", rows.Err()
}

// RequirePasswordChange flags a credential.
func RequirePasswordChange(ctx context.Context, e Execer, userID, reason string) error {
	_, err := e.Exec(ctx,
		`UPDATE core.password_credentials
		    SET must_change = true, must_change_reason = $2
		  WHERE user_id = $1::uuid`, userID, reason)
	return err
}

// BreachCheckDue reports whether the corpus should be consulted for this
// credential at sign-in.
//
// Bounded on purpose. Re-checking is what keeps the control alive as corpora
// grow, but doing it on every sign-in would put a third party on the critical
// path of every login in the deployment. Once per interval per credential
// catches a newly-breached password within that interval and costs one request
// per user per interval.
func BreachCheckDue(ctx context.Context, q Querier, userID string, every time.Duration) (bool, error) {
	if every <= 0 {
		return false, nil
	}
	rows, err := q.Query(ctx,
		`SELECT last_breach_check IS NULL OR last_breach_check < now() - $2::interval
		   FROM core.password_credentials WHERE user_id = $1::uuid`,
		userID, fmt.Sprintf("%d seconds", int(every.Seconds())))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if rows.Next() {
		var due bool
		if err := rows.Scan(&due); err != nil {
			return false, err
		}
		return due, nil
	}
	return false, rows.Err()
}

// RecordBreachCheck stamps the credential as checked.
//
// Stamped whatever the verdict, including when the corpus was unreachable --
// otherwise an outage turns into a retry on every sign-in by every user, which
// is how a third party's bad hour becomes our own.
func RecordBreachCheck(ctx context.Context, e Execer, userID string) error {
	_, err := e.Exec(ctx,
		`UPDATE core.password_credentials SET last_breach_check = now()
		  WHERE user_id = $1::uuid`, userID)
	return err
}

// CurrentPasswordHash returns the hash in force, or "" if there is none.
func CurrentPasswordHash(ctx context.Context, q Querier, userID string) (string, error) {
	rows, err := q.Query(ctx,
		`SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`, userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return "", err
		}
		return hash, nil
	}
	return "", rows.Err()
}

// SetPassword replaces the credential and clears everything the old one carried.
//
// The throttle counters, the must-change flag and the breach-check stamp all
// belong to the password that is being replaced. Leaving any of them behind
// attaches a previous password's history to a new one -- most visibly as a user
// who changes their password as instructed and is asked to do it again.
func SetPassword(ctx context.Context, e Execer, userID, newHash string) error {
	_, err := e.Exec(ctx, `
		UPDATE core.password_credentials
		   SET hash = $2, algorithm = 'argon2id', is_current = true, updated_at = now(),
		       failed_attempts = 0, throttled_until = NULL, last_failure_at = NULL,
		       must_change = false, must_change_reason = NULL, last_breach_check = NULL
		 WHERE user_id = $1::uuid`, userID, newHash)
	return err
}
