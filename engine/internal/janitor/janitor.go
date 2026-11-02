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
// advisory lock makes the work exclusive across the whole cluster without needing
// a leader election, a scheduler, or a separate deployment unit.
//
// # Why a pass is many short transactions
//
// It was one, and every sweep in it unbounded. After an outage that is one
// enormous transaction holding row locks on everything it touched and pinning a
// connection for as long as it took, and one bad table rolled all of it back. Now
// each batch commits by itself and takes the lock again, so nothing is held
// between batches, a failure costs only its own batch, and the lock is the
// transaction-scoped kind, which a node that dies cannot leave behind and a
// transaction-mode pooler can carry. Each sweep gets a batch before any gets a
// second, so a backlog of sessions cannot starve the rest, and a pass stops
// starting new work at passBudget and says what it left for the next.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// lockID identifies the janitor's advisory lock. Any constant works as long as
// it is stable and not shared with another job; it is namespaced by database.
const lockID int64 = 0x1D9_1A17

const (
	// DefaultInterval is how often a pass runs. Sessions expire continuously, so
	// the interval is really "how stale may an RP's view of a dead session be".
	// A minute keeps that bounded without making the lock hot.
	DefaultInterval = time.Minute

	// sessionBatch bounds one transaction. Each terminated session queues notices
	// inside it, so an unbounded batch after an outage would build one enormous
	// transaction and hold row locks for the duration of it.
	sessionBatch = 500

	// sweepBatch bounds what one transaction deletes from one table.
	sweepBatch = 1000

	// passBudget is when a pass stops starting new batches. Short of the interval,
	// so one pass has ended before the next is due.
	passBudget = 45 * time.Second

	// codeRetention keeps spent codes around well past their expiry ON PURPOSE.
	//
	// Reuse detection reads the row: a replayed code is recognised because its
	// consumed_at is set, and recognising it is what revokes the whole token
	// family. Delete the row promptly and a replay degrades into a plain
	// "unknown code" -- still rejected, but the tokens the thief already holds
	// stay live. The row is tiny; the detection window is worth far more than
	// the storage.
	codeRetention = 24 * time.Hour

	// pollEventRetention is how long an undelivered SET waits on a poll stream
	// before the janitor drops it. Generous on purpose: dropping a security event
	// the receiver has not yet collected is a real loss, so this is a backstop for
	// an ABANDONED receiver, not a delivery deadline for a slow one. A receiver
	// polling even once a fortnight keeps its queue drained.
	pollEventRetention = 30 * 24 * time.Hour
)

// Stats is one pass's result, for logging and for tests.
type Stats struct {
	SessionsSwept int64
	CodesPurged   int64
	// RevocationsPurged are denylist rows dropped because the token they name
	// has expired anyway.
	RevocationsPurged int64
	// OpaqueTokensPurged are handles dropped past their expiry.
	OpaqueTokensPurged int64
	// RecoveriesPurged are password-reset requests dropped after expiry.
	RecoveriesPurged int64
	// DeviceCodesPurged are abandoned RFC 8628 device authorizations.
	DeviceCodesPurged int64

	// AttestationChallengesPurged are spent ABCA challenges. Single-use and two
	// minutes long, so the table is almost entirely dead rows within the hour.
	AttestationChallengesPurged int64
	// LogoutChainsSwept are SAML front-channel logouts the user abandoned.
	LogoutChainsSwept int64

	// Support-access episodes that ran out and were closed.
	ImpersonationsExpired int64
	// FederatedLoginsSwept are external sign-ins abandoned at the provider.
	FederatedLoginsSwept int64
	// AssertionsSwept are RFC 7523 replay records past the assertion's own
	// expiry.
	AssertionsSwept int64
	// DPoPProofsSwept are proof identifiers past their replay window.
	DPoPProofsSwept int64
	// CeremoniesSwept are spent WebAuthn challenges past their ceremony's expiry.
	CeremoniesSwept int64
	// OffersSwept are credential offers (pre-authorized codes) no token can
	// still need.
	OffersSwept int64
	// KeptOffersSwept are offers kept by reference whose code is over.
	KeptOffersSwept int64
	// PersistedClaimsSwept are UMA persisted claims tokens past their month.
	PersistedClaimsSwept int64
	// NotificationsSwept are records of issuance no token can report on any more.
	NotificationsSwept int64
	// CredentialRequestsSwept are parked requests no token can come back for.
	CredentialRequestsSwept int64
	// CredentialStatusListsSwept are full status lists whose credentials have all expired.
	CredentialStatusListsSwept int64
	// PushedRequestsSwept are PAR handles nobody redeemed.
	PushedRequestsSwept int64
	// SAMLSourceStateSwept are inbound SAML requests and spent assertion records
	// past their retention.
	SAMLSourceStateSwept int64
	// RateWindowsPurged are rate-limit counters whose window has passed.
	RateWindowsPurged int64
	// DuoChallengesSwept are Duo prompts the user abandoned.
	DuoChallengesSwept int64
	// FactorChallengesSwept are external factors nobody came back from.
	FactorChallengesSwept int64
	// PollEventsPurged are SETs queued for a poll stream whose receiver stopped
	// collecting them, dropped after a long retention.
	PollEventsPurged int64
	Parked           []string
	// Retained is how many rows the retention deleted, by table.
	Retained map[string]int
	// HeadSigned is whether the pass signed the audit chain's head (3.20).
	HeadSigned bool
	// Behind names the sweeps a pass left work in, because its budget ran out. The
	// next one carries on; one that says the same every minute is a deployment
	// expiring rows faster than this deletes them.
	Behind []string
	// Skipped means another node held the lock. Not an error, and deliberately
	// distinguished from "nothing to do" so a misconfigured cluster where every
	// pass is skipped is visible rather than looking idle.
	Skipped bool
}

// sweep is one kind of work a pass does, a batch at a time. It says how many
// rows the batch took, and a full batch means there may be more.
type sweep struct {
	name  string
	limit int
	into  *int64
	work  func(ctx context.Context, tx pgx.Tx, limit int) (int64, error)
}

// sweeps is the work of a pass, in the order each gets its turn.
func sweeps(st *Stats, keep store.Retention) []sweep {
	return []sweep{
		{"expired sessions", sessionBatch, &st.SessionsSwept, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			n, err := store.SweepExpiredSessions(ctx, tx, limit)
			return int64(n), err
		}},
		{"expired codes", sweepBatch, &st.CodesPurged, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			return store.PurgeExpiredCodes(ctx, tx, codeRetention, limit)
		}},
		// Spent attestation challenges. They are single-use and two minutes long, so
		// the table is almost all dead rows within the hour -- and a purge that is
		// written but never called is the defect this file exists to prevent.
		{"attestation challenges", sweepBatch, &st.AttestationChallengesPurged, store.PurgeExpiredAttestationChallenges},
		// Denylist entries for access tokens that have since expired on their own.
		// Keeping them costs a lookup on every userinfo call and proves nothing: an
		// expired token is refused by its exp claim regardless.
		{"revocations", sweepBatch, &st.RevocationsPurged, store.PurgeExpiredRevocations},
		// Handles past their expiry, which refuse anyway.
		{"opaque tokens", sweepBatch, &st.OpaqueTokensPurged, store.PurgeExpiredOpaqueTokens},
		// Device authorizations that were never completed. Each holds two code
		// hashes; an abandoned television login should not leave them behind.
		{"device authorizations", sweepBatch, &st.DeviceCodesPurged, store.PurgeExpiredDeviceCodes},
		// UMA permission tickets. Each is a single-use bearer credential describing
		// what somebody asked for on which resource -- keeping spent ones past their
		// expiry stores a record of intent that grants nothing.
		{"permission tickets", sweepBatch, nil, store.PurgeExpiredPermissionTickets},
		// Claims interactions that were shown and never confirmed. Each is a
		// half-finished consent naming a person, a client and a resource; an
		// abandoned browser tab should not leave one behind.
		{"claims interactions", sweepBatch, nil, store.PurgeExpiredInteractions},
		// UMA requests nobody decided. A pending request is a STANDING OFFER to
		// grant access -- unlike everything else swept here, letting it linger is a
		// liability rather than merely clutter: somebody approving a month-old
		// request is approving a context they cannot remember.
		{"UMA requests", sweepBatch, nil, store.PurgeExpiredPendingRequests},
		// Recovery requests nobody can use any more. Each row holds two token hashes
		// for a password reset, so keeping them past their expiry stores credentials
		// that grant nothing -- all risk, no purpose.
		{"recovery requests", sweepBatch, &st.RecoveriesPurged, store.PurgeExpiredRecoveries},
		// Support access that ran out. Without this, expires_at is a column nobody
		// reads and an administrator's session wearing somebody else's name lasts
		// until they happen to sign out -- which is precisely the case the time
		// bound exists for.
		{"impersonations", sweepBatch, &st.ImpersonationsExpired, func(ctx context.Context, tx pgx.Tx, _ int) (int64, error) {
			n, err := store.ExpireImpersonations(ctx, tx)
			return int64(n), err
		}},
		// Abandoned SAML logout chains. A front-channel logout walks the browser
		// through each service provider in turn, and a user who closes the tab
		// halfway leaves a row behind holding a live chain token. They expire on
		// their own; this is what stops the table growing forever.
		{"SAML logout chains", sweepBatch, &st.LogoutChainsSwept, store.SweepExpiredLogoutChains},
		// External logins the user abandoned at the provider's consent screen. Each
		// row holds a PKCE verifier and a nonce, so keeping them past expiry stores
		// live flow state for a flow nobody is going to finish.
		{"external logins", sweepBatch, &st.FederatedLoginsSwept, store.SweepExpiredFederatedLogins},
		// RFC 7523 assertion identifiers past the assertion's own expiry. Keeping
		// them longer protects nothing: an assertion past its `exp` is refused for
		// being expired before this table is ever consulted, so the row would only
		// be storing which workloads authenticated and when.
		{"used assertions", sweepBatch, &st.AssertionsSwept, store.SweepUsedAssertions},
		{"used request objects", sweepBatch, &st.AssertionsSwept, store.SweepRequestObjectReplay},
		// Pushed authorization requests nobody redeemed.
		{"pushed requests", sweepBatch, &st.PushedRequestsSwept, store.SweepExpiredPushedRequests},
		// DPoP proof identifiers past their replay window.
		{"DPoP proofs", sweepBatch, &st.DPoPProofsSwept, store.SweepExpiredDPoPProofs},
		// Spent WebAuthn challenges past their ceremony's expiry, after which the
		// ceremony cookie is refused as expired before the record is consulted.
		{"WebAuthn challenges", sweepBatch, &st.CeremoniesSwept, store.SweepSpentCeremonies},
		// Credential offers past their expiry by more than any token minted from
		// one can live. Each holds a code hash and the minted token's jti, and
		// nothing removed them, so they accumulated for as long as the deployment
		// ran.
		{"credential offers", sweepBatch, &st.OffersSwept, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			return store.SweepSpentPreAuthorizedCodes(ctx, tx, tokens.MaxAccessTokenTTL, limit)
		}},
		{"kept credential offers", sweepBatch, &st.KeptOffersSwept, store.SweepExpiredCredentialOffers},
		{"persisted claims", sweepBatch, &st.PersistedClaimsSwept, store.SweepExpiredPersistedClaims},
		{"credential notifications", sweepBatch, &st.NotificationsSwept, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			return store.SweepCredentialNotifications(ctx, tx, tokens.MaxAccessTokenTTL, limit)
		}},
		{"credential requests", sweepBatch, &st.CredentialRequestsSwept, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			return store.SweepCredentialRequests(ctx, tx, tokens.MaxAccessTokenTTL, limit)
		}},
		// A list whose credentials have all expired. A day's grace for a clock that
		// runs behind the one an expired credential is judged by.
		{"credential status lists", sweepBatch, &st.CredentialStatusListsSwept, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			return store.SweepCredentialStatusLists(ctx, tx, 24*time.Hour, limit)
		}},
		// Duo prompts nobody finished. Each row holds a live challenge state, so
		// keeping them past expiry stores flow state for a flow nobody will finish.
		{"Duo challenges", sweepBatch, &st.DuoChallengesSwept, store.PurgeExpiredDuoChallenges},
		// The same for an external factor: a nonce nobody came back with.
		{"external factor challenges", sweepBatch, &st.FactorChallengesSwept, store.SweepExpiredFactorChallenges},
		// Inbound SAML: requests nobody answered, and the record of assertions
		// already spent. Both are bounded by the assertion lifetime, so this is
		// housekeeping rather than a security control -- but a table that only grows
		// is how a deployment discovers its disk on a Sunday.
		{"inbound SAML state", sweepBatch, &st.SAMLSourceStateSwept, store.PurgeSAMLSourceState},
		// Rate-limit windows that have passed. Housekeeping rather than a security
		// control -- an old window cannot permit anything, since the current one is
		// computed from the clock.
		{"rate limit windows", sweepBatch, &st.RateWindowsPurged, store.PurgeRateLimits},
		// Security Event Tokens queued for a poll stream whose receiver stopped
		// collecting them. A very long retention -- an abandoned stream is the only
		// thing this catches, and a live one drains itself.
		{"stale poll events", sweepBatch, &st.PollEventsPurged, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			n, err := store.PurgeStalePollEvents(ctx, tx, pollEventRetention, limit)
			return int64(n), err
		}},
		// Rows nothing reads any more, by the configured retention (3.17).
		{"retention", retentionBatch, nil, func(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
			got, err := store.PurgeRetained(ctx, tx, keep, limit)
			if err != nil {
				return 0, err
			}
			var most int
			if st.Retained == nil {
				st.Retained = map[string]int{}
			}
			for table, n := range got {
				st.Retained[table] += n
				most = max(most, n)
			}
			return int64(most), nil
		}},
	}
}

// errLockHeld is a batch that found another node working.
var errLockHeld = errors.New("the janitor's lock is held")

// RunOnce performs a single maintenance pass.
func RunOnce(ctx context.Context, db *pgxpool.Pool, log *slog.Logger) (Stats, error) {
	return runPass(ctx, db, log, passBudget)
}

func runPass(ctx context.Context, db *pgxpool.Pool, log *slog.Logger, budget time.Duration) (Stats, error) {
	var st Stats
	keep := store.DefaultRetention()
	if p := retention.Load(); p != nil {
		keep = *p
	}
	err := runSweeps(ctx, db, sweeps(&st, keep), budget, &st)
	if st.Skipped {
		return st, nil
	}

	// The audit chain's signed head (3.20), by the node holding the lock, so no
	// second ticker is needed. A head that cannot be signed is logged, and does
	// not undo the sweeping before it.
	if fn := headSigner.Load(); fn != nil {
		if _, herr := batch(ctx, db, sweep{work: func(ctx context.Context, tx pgx.Tx, _ int) (int64, error) {
			signed, err := (*fn)(ctx, tx)
			st.HeadSigned = signed
			return 0, err
		}}); herr != nil && !errors.Is(herr, errLockHeld) {
			log.Error("signing the audit head", "err", herr)
		}
	}
	if fn := retentionObserver.Load(); fn != nil {
		for table, n := range st.Retained {
			(*fn)(table, n)
		}
	}

	// Read after the work and on the pool: this is reporting, and it must not be
	// able to undo anything above.
	if parked, err := outbox.Parked(ctx, db); err != nil {
		log.Error("reading parked logout notices", "err", err)
	} else {
		st.Parked = parked
	}
	return st, err
}

// runSweeps gives each sweep a batch, then a second batch to those with more, and
// so on until nothing has more or the budget has gone. A sweep that fails stops
// for this pass and the rest carry on: one broken table must not leave every
// other to grow. Their failures come back together.
func runSweeps(ctx context.Context, db *pgxpool.Pool, work []sweep, budget time.Duration, st *Stats) error {
	deadline := time.Now().Add(budget)
	worked := false
	var failed error
	for len(work) > 0 {
		var more []sweep
		for _, s := range work {
			n, err := batch(ctx, db, s)
			switch {
			case errors.Is(err, errLockHeld):
				// Another node is at it. Whatever is left is theirs or the next
				// pass's; only a pass that did nothing was skipped.
				st.Skipped = !worked
				return failed
			case err != nil:
				failed = errors.Join(failed, fmt.Errorf("sweeping %s: %w", s.name, err))
				if ctx.Err() != nil {
					return failed
				}
				continue
			}
			worked = true
			if s.into != nil {
				*s.into += n
			}
			if n >= int64(s.limit) {
				more = append(more, s)
			}
		}
		work = more
		if len(work) > 0 && !time.Now().Before(deadline) {
			for _, s := range work {
				st.Behind = append(st.Behind, s.name)
			}
			return failed
		}
	}
	return failed
}

// batch runs one sweep's batch in a transaction of its own.
//
// A TRANSACTION-scoped lock, not a session-scoped one: it is released by the
// commit or rollback, so a node that dies mid-batch cannot leave the janitor
// wedged for everyone. pg_try_advisory_lock would require an explicit unlock
// on a pinned connection, which is exactly the thing that gets skipped on a
// panic path.
func batch(ctx context.Context, db *pgxpool.Pool, s sweep) (int64, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("beginning a transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockID).Scan(&got); err != nil {
		return 0, fmt.Errorf("taking the lock: %w", err)
	}
	if !got {
		return 0, errLockHeld
	}
	n, err := s.work(ctx, tx, s.limit)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing: %w", err)
	}
	return n, nil
}

// retentionBatch bounds each table's deletions in one transaction, as
// sessionBatch bounds the sweep.
const retentionBatch = 1000

// retention is what each pass deletes as no longer needed; DefaultRetention
// until SetRetention is called at startup.
var retention atomic.Pointer[store.Retention]

// SetRetention sets what each pass keeps.
func SetRetention(r store.Retention) { retention.Store(&r) }

// headSigner, when set, signs the audit chain's head if one is due and says
// whether it did (3.20). serve sets it with the signing keys this package
// does not hold.
var headSigner atomic.Pointer[func(context.Context, pgx.Tx) (bool, error)]

// SetHeadSigner installs fn; nil removes it.
func SetHeadSigner(fn func(ctx context.Context, tx pgx.Tx) (bool, error)) {
	if fn == nil {
		headSigner.Store(nil)
		return
	}
	headSigner.Store(&fn)
}

// retentionObserver, when set, is told how many rows each pass deleted from
// each table, for the metrics.
var retentionObserver atomic.Pointer[func(table string, n int)]

// SetRetentionObserver installs fn; nil removes it.
func SetRetentionObserver(fn func(table string, n int)) {
	if fn == nil {
		retentionObserver.Store(nil)
		return
	}
	retentionObserver.Store(&fn)
}

// lastPass is when this process last completed a pass, in Unix seconds; 0
// before the first. A node whose passes another node's lock skipped never
// sets it, so a deployment's freshness is the newest across its nodes.
var lastPass atomic.Int64

// LastPass is when this process last completed a janitor pass, or the zero
// time (3.08). A janitor that stopped was invisible until a table had grown.
func LastPass() time.Time {
	if s := lastPass.Load(); s > 0 {
		return time.Unix(s, 0)
	}
	return time.Time{}
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
				if !st.Skipped {
					lastPass.Store(time.Now().Unix())
				}
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
	add("sessions_swept", s.SessionsSwept)
	add("codes_purged", s.CodesPurged)
	add("revocations_purged", s.RevocationsPurged)
	add("opaque_tokens_purged", s.OpaqueTokensPurged)
	add("recoveries_purged", s.RecoveriesPurged)
	add("device_codes_purged", s.DeviceCodesPurged)
	add("logout_chains_swept", s.LogoutChainsSwept)
	add("federated_logins_swept", s.FederatedLoginsSwept)
	add("dpop_proofs_swept", s.DPoPProofsSwept)
	add("ceremonies_swept", s.CeremoniesSwept)
	add("offers_swept", s.OffersSwept)
	add("kept_offers_swept", s.KeptOffersSwept)
	add("persisted_claims_swept", s.PersistedClaimsSwept)
	add("notifications_swept", s.NotificationsSwept)
	add("credential_requests_swept", s.CredentialRequestsSwept)
	add("credential_status_lists_swept", s.CredentialStatusListsSwept)
	add("pushed_requests_swept", s.PushedRequestsSwept)
	add("saml_source_state_swept", s.SAMLSourceStateSwept)
	add("rate_windows_purged", s.RateWindowsPurged)
	add("duo_challenges_swept", s.DuoChallengesSwept)
	add("factor_challenges_swept", s.FactorChallengesSwept)
	add("impersonations_expired", s.ImpersonationsExpired)
	for _, table := range store.RetentionTables {
		add(table+"_deleted", int64(s.Retained[table]))
	}
	if s.HeadSigned {
		add("audit_head_signed", 1)
	}

	if len(fields) > 0 {
		log.Info("janitor pass", fields...)
	}
	// WARN: rows are expiring faster than a pass can take them, or a backlog is
	// being worked through, and either is what an operator would want to know.
	if len(s.Behind) > 0 {
		log.Warn("the janitor ran out of time with work left; the next pass carries on", "sweeps", s.Behind)
	}
	// WARN, and one line per RP. Each of these is a relying party that still
	// believes a signed-out user is signed in, which is a security fact an
	// operator has to see -- not a debug detail.
	for _, p := range s.Parked {
		log.Warn("back-channel logout gave up; the relying party was never notified", "detail", p)
	}
}
