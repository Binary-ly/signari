// Package janitor runs the periodic maintenance every OIDC provider needs and
// most of them forget until the disk fills.
//
// Three jobs, each of which is a real failure if it never runs:
//
//   - Expired sessions are TERMINATED, not merely ignored. A session past
//     not_after is dead to the engine already, but relying parties do not know
//     that until a back-channel logout notice reaches them. Skipping this is how
//     an application keeps a user "signed in" for hours after the IdP stopped
//     agreeing -- the single most common complaint about federated logout.
//   - Spent authorization codes are purged, or the table grows without bound.
//   - Parked logout notices are surfaced. A notice that exhausted its retries is
//     an RP whose session was never ended; nobody finds out unless someone looks.
//
// # Why this is a singleton
//
// Sweeping sessions has an observable side effect: it queues logout notices.
// Running it on every node would multiply that work by the node count and, worse,
// have several transactions racing to terminate the same sessions. A PostgreSQL
// advisory lock makes the pass exclusive across the whole cluster without needing
// a leader election, a scheduler, or a separate deployment unit.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/store"
)

// lockID identifies the janitor's advisory lock. Any constant works as long as
// it is stable and not shared with another job; it is namespaced by database.
const lockID int64 = 0x1D9_1A17

const (
	// DefaultInterval is how often a pass runs. Sessions expire continuously, so
	// the interval is really "how stale may an RP's view of a dead session be".
	// A minute keeps that bounded without making the lock hot.
	DefaultInterval = time.Minute

	// sessionBatch bounds one pass. Each terminated session queues notices inside
	// the same transaction, so an unbounded batch after an outage would build one
	// enormous transaction and hold row locks for the duration of it.
	sessionBatch = 500

	// codeRetention keeps spent codes around well past their expiry ON PURPOSE.
	//
	// Reuse detection reads the row: a replayed code is recognised because its
	// consumed_at is set, and recognising it is what revokes the whole token
	// family. Delete the row promptly and a replay degrades into a plain
	// "unknown code" -- still rejected, but the tokens the thief already holds
	// stay live. The row is tiny; the detection window is worth far more than
	// the storage.
	codeRetention = 24 * time.Hour
)

// Stats is one pass's result, for logging and for tests.
type Stats struct {
	SessionsSwept int
	CodesPurged   int64
	// RevocationsPurged are denylist rows dropped because the token they name
	// has expired anyway.
	RevocationsPurged int64
	// RecoveriesPurged are password-reset requests dropped after expiry.
	RecoveriesPurged int64
	// DeviceCodesPurged are abandoned RFC 8628 device authorizations.
	DeviceCodesPurged int64
	// LogoutChainsSwept are SAML front-channel logouts the user abandoned.
	LogoutChainsSwept int64

	// Support-access episodes that ran out and were closed.
	ImpersonationsExpired int
	// FederatedLoginsSwept are external sign-ins abandoned at the provider.
	FederatedLoginsSwept int64
	// DPoPProofsSwept are proof identifiers past their replay window.
	DPoPProofsSwept int64
	// PushedRequestsSwept are PAR handles nobody redeemed.
	PushedRequestsSwept int64
	// SAMLSourceStateSwept are inbound SAML requests and spent assertion records
	// past their retention.
	SAMLSourceStateSwept int64
	// RateWindowsPurged are rate-limit counters whose window has passed.
	RateWindowsPurged int64
	// DuoChallengesSwept are Duo prompts the user abandoned.
	DuoChallengesSwept int64
	Parked             []string
	// Skipped means another node held the lock. Not an error, and deliberately
	// distinguished from "nothing to do" so a misconfigured cluster where every
	// pass is skipped is visible rather than looking idle.
	Skipped bool
}

// RunOnce performs a single maintenance pass, if this node can take the lock.
func RunOnce(ctx context.Context, db *pgxpool.Pool, log *slog.Logger) (Stats, error) {
	var st Stats

	tx, err := db.Begin(ctx)
	if err != nil {
		return st, fmt.Errorf("beginning janitor transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A TRANSACTION-scoped lock, not a session-scoped one: it is released by the
	// commit or rollback, so a node that dies mid-pass cannot leave the janitor
	// wedged for everyone. pg_try_advisory_lock would require an explicit unlock
	// on a pinned connection, which is exactly the thing that gets skipped on a
	// panic path.
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockID).Scan(&got); err != nil {
		return st, fmt.Errorf("taking janitor lock: %w", err)
	}
	if !got {
		st.Skipped = true
		return st, nil
	}

	if st.SessionsSwept, err = store.SweepExpiredSessions(ctx, tx, sessionBatch); err != nil {
		return st, fmt.Errorf("sweeping expired sessions: %w", err)
	}
	if st.CodesPurged, err = store.PurgeExpiredCodes(ctx, tx, codeRetention); err != nil {
		return st, fmt.Errorf("purging expired codes: %w", err)
	}
	// Denylist entries for access tokens that have since expired on their own.
	// Keeping them costs a lookup on every userinfo call and proves nothing: an
	// expired token is refused by its exp claim regardless.
	if st.RevocationsPurged, err = store.PurgeExpiredRevocations(ctx, tx); err != nil {
		return st, fmt.Errorf("purging expired revocations: %w", err)
	}
	// Device authorizations that were never completed. Each holds two code
	// hashes; an abandoned television login should not leave them behind.
	if st.DeviceCodesPurged, err = store.PurgeExpiredDeviceCodes(ctx, tx); err != nil {
		return st, fmt.Errorf("purging expired device authorizations: %w", err)
	}
	// Recovery requests nobody can use any more. Each row holds two token hashes
	// for a password reset, so keeping them past their expiry stores credentials
	// that grant nothing -- all risk, no purpose.
	n, err := store.PurgeExpiredRecoveries(ctx, tx)
	if err != nil {
		return st, fmt.Errorf("purging expired recovery requests: %w", err)
	}
	st.RecoveriesPurged = n

	// Support access that ran out. Without this, expires_at is a column nobody
	// reads and an administrator's session wearing somebody else's name lasts
	// until they happen to sign out -- which is precisely the case the time
	// bound exists for.
	if st.ImpersonationsExpired, err = store.ExpireImpersonations(ctx, tx); err != nil {
		return st, fmt.Errorf("expiring impersonations: %w", err)
	}

	// Abandoned SAML logout chains. A front-channel logout walks the browser
	// through each service provider in turn, and a user who closes the tab
	// halfway leaves a row behind holding a live chain token. They expire on
	// their own; this is what stops the table growing forever.
	if st.LogoutChainsSwept, err = store.SweepExpiredLogoutChains(ctx, tx); err != nil {
		return st, fmt.Errorf("sweeping abandoned SAML logout chains: %w", err)
	}

	// External logins the user abandoned at the provider's consent screen. Each
	// row holds a PKCE verifier and a nonce, so keeping them past expiry stores
	// live flow state for a flow nobody is going to finish.
	if st.FederatedLoginsSwept, err = store.SweepExpiredFederatedLogins(ctx, tx); err != nil {
		return st, fmt.Errorf("sweeping abandoned external logins: %w", err)
	}

	// Pushed authorization requests nobody redeemed.
	if st.PushedRequestsSwept, err = store.SweepExpiredPushedRequests(ctx, tx); err != nil {
		return st, fmt.Errorf("sweeping pushed authorization requests: %w", err)
	}

	// DPoP proof identifiers past their replay window.
	if st.DPoPProofsSwept, err = store.SweepExpiredDPoPProofs(ctx, tx); err != nil {
		return st, fmt.Errorf("sweeping DPoP proof records: %w", err)
	}

	// Duo prompts nobody finished. Each row holds a live challenge state, so
	// keeping them past expiry stores flow state for a flow nobody will finish.
	if st.DuoChallengesSwept, err = store.PurgeExpiredDuoChallenges(ctx, tx); err != nil {
		return st, fmt.Errorf("sweeping abandoned Duo challenges: %w", err)
	}

	// Inbound SAML: requests nobody answered, and the record of assertions
	// already spent. Both are bounded by the assertion lifetime, so this is
	// housekeeping rather than a security control -- but a table that only grows
	// is how a deployment discovers its disk on a Sunday.
	if st.SAMLSourceStateSwept, err = store.PurgeSAMLSourceState(ctx, tx); err != nil {
		return st, fmt.Errorf("sweeping inbound SAML state: %w", err)
	}

	// Rate-limit windows that have passed. Housekeeping rather than a security
	// control -- an old window cannot permit anything, since the current one is
	// computed from the clock.
	if st.RateWindowsPurged, err = store.PurgeRateLimits(ctx, tx); err != nil {
		return st, fmt.Errorf("purging rate limit windows: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return st, fmt.Errorf("committing janitor pass: %w", err)
	}

	// Read AFTER the commit, on the pool rather than the transaction: this is
	// reporting, and it must not be able to roll back the work above.
	if parked, err := outbox.Parked(ctx, db); err != nil {
		log.Error("reading parked logout notices", "err", err)
	} else {
		st.Parked = parked
	}

	return st, nil
}

// Run loops until ctx is cancelled.
func Run(ctx context.Context, db *pgxpool.Pool, log *slog.Logger, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	log.Info("janitor started", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			log.Info("janitor stopped")
			return
		case <-t.C:
			st, err := RunOnce(ctx, db, log)
			switch {
			case errors.Is(err, context.Canceled):
				// Shutdown, not a fault.
			case err != nil:
				// Logged and retried on the next tick. A failed pass must never
				// take the process down: maintenance falling behind is an
				// operational problem, refusing to serve tokens is an outage.
				log.Error("janitor pass failed", "err", err)
			default:
				st.Log(log)
			}
		}
	}
}

// Log emits a pass at a level matched to whether anyone needs to act.
func (s Stats) Log(log *slog.Logger) {
	if s.Skipped {
		return
	}
	// Every counter, not a chosen four.
	//
	// The first version listed the four sweeps that existed when it was written,
	// and each sweep added afterwards -- device codes, logout chains, federated
	// logins, DPoP proofs, PAR handles, inbound SAML state -- did its work and
	// reported nothing. A pass that deletes ten thousand rows and logs silence
	// is indistinguishable from a pass that is broken.
	fields := []any{}
	add := func(name string, n int64) {
		if n > 0 {
			fields = append(fields, name, n)
		}
	}
	add("sessions_swept", int64(s.SessionsSwept))
	add("codes_purged", s.CodesPurged)
	add("revocations_purged", s.RevocationsPurged)
	add("recoveries_purged", s.RecoveriesPurged)
	add("device_codes_purged", s.DeviceCodesPurged)
	add("logout_chains_swept", s.LogoutChainsSwept)
	add("federated_logins_swept", s.FederatedLoginsSwept)
	add("dpop_proofs_swept", s.DPoPProofsSwept)
	add("pushed_requests_swept", s.PushedRequestsSwept)
	add("saml_source_state_swept", s.SAMLSourceStateSwept)
	add("rate_windows_purged", s.RateWindowsPurged)
	add("duo_challenges_swept", s.DuoChallengesSwept)
	add("impersonations_expired", int64(s.ImpersonationsExpired))

	if len(fields) > 0 {
		log.Info("janitor pass", fields...)
	}
	// WARN, and one line per RP. Each of these is a relying party that still
	// believes a signed-out user is signed in, which is a security fact an
	// operator has to see -- not a debug detail.
	for _, p := range s.Parked {
		log.Warn("back-channel logout gave up; the relying party was never notified", "detail", p)
	}
}
