// Package audit writes the tamper-evident record of security decisions.
//
// The table has existed since the first migration and nothing has ever written
// to it. That is the worst of both worlds: the schema implies an audit trail
// exists, and during an incident there is nothing to read.
//
// Four design rules, each of which is a decision rather than a detail:
//
//  1. SUBJECT IDs ONLY, never an email address or an IP treated as identity.
//     An audit log outlives the account it describes, so putting the identifier
//     a person can ask you to erase into an append-only table means either
//     breaking the append-only property or refusing a lawful erasure request.
//     This rule is what actually protects erasure today, and it is load-bearing:
//     it is the ONLY thing keeping personal data out of this append-only table.
//
//  2. THE HASH CHAIN COVERS `detail`, WHICH IS PLAINTEXT.
//
//     This said the chain covered CIPHERTEXT, with personal detail in a
//     `detail_enc` column encrypted under the subject's key. Nothing ever wrote
//     or read that column, and migration 0165 dropped it (3.23). Nothing in this
//     table is encrypted, so anything personal written into `detail` would
//     survive a shred, and the safety of shredding rests on rule 1: enforced by
//     TestNoAuditRowNamesAPerson over the code that writes, and by
//     TestAnErasedPersonLeavesNoIdentifierInTheAuditTrail over the rows a
//     person's whole life through the admin API leaves.
//
//     Chaining over plaintext is correct given rule 1 -- the rows a shred
//     touches carry no personal content, so no link is invalidated.
//
//  3. WRITES JOIN THE CALLER'S TRANSACTION. An audit row that commits when the
//     decision it describes rolled back is a false record, and one that rolls
//     back when the decision committed is a missing one. Both are worse than no
//     log, so there is no fire-and-forget path here.
//
//  4. A FAILED AUDIT WRITE FAILS THE OPERATION. If we cannot record that a
//     session was created, we do not create it. This is the trade auditability
//     demands, and stating it plainly is better than discovering it during a
//     forensic review.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Event types. Constants rather than free strings so a typo is a compile error
// and the set is greppable -- an audit trail nobody can query is decoration.
//
// Not here, deliberately: an event per code issued or redeemed, per refresh,
// per client-credentials token. Constants for those were declared and written
// by nothing (2.52), and writing them would put the chain's advisory lock on
// the issuance of every token. What a token's life records is the decisions:
// sign-in, consent, a reused code or refresh token, a revocation.
const (
	EventLoginSucceeded = "login.succeeded"
	EventLoginFailed    = "login.failed"
	EventLogout         = "session.logout"
	EventCodeReused     = "oauth.code_reused"
	EventRefreshReused  = "oauth.refresh_reused"
	EventTokenRevoked   = "oauth.token_revoked"
	EventClientUpdated  = "admin.client_updated"
	EventKeyRotated     = "keys.rotated"
)

// Retention classes decide what survives an erasure request.
const (
	// Security events are kept on legitimate-interest grounds: sign-ins,
	// failures, revocations, anything an investigation needs.
	RetentionSecurity = "security"
	// Operational events are kept for running the system, not for investigating
	// people.
	RetentionOperational = "operational"
	// Profile events describe preferences and are erased on request.
	RetentionProfile = "profile"
)

// Event is one record. Every field is optional except Type, because the
// endpoints that most need auditing are exactly the ones where identity is not
// yet established -- a failed login has no subject by definition.
type Event struct {
	Type string
	// OrgID, SubjectID and ActorID are uuids as strings; empty means unknown.
	// ActorID differs from SubjectID when an administrator acts ON a user.
	OrgID     string
	SubjectID string
	ActorID   string
	ClientID  string
	// CorrelationID ties every record from one request together and is the short
	// code shown to the user on an error page.
	CorrelationID string
	Retention     string
	// AdminTokenID names the admin API credential that caused this change, when
	// one did. Empty for actions taken by a user, by the engine itself, or
	// through the break-glass environment token, which has no row to point at.
	AdminTokenID string
	// Detail is NON-personal context: reason codes, counts, scope names. Anything
	// identifying a person belongs in the encrypted column, not here.
	Detail map[string]any
	// OccurredAt is when it happened; the zero value is now. Set here and
	// hashed (hash version 2, 3.19): the column defaulted to the database's
	// clock and sat outside the hash, so a row's time could be rewritten and
	// the chain still verified.
	OccurredAt time.Time
}

// hashVersion is what Write hashes. Version 1 left occurred_at out; rows
// written before it, and by a release before this one, keep verifying as 1.
const hashVersion = 2

// Write appends one event inside the caller's transaction.
//
// auditChainLock is the advisory lock key serialising appends.
//
// An arbitrary constant, chosen once. It only has to be distinct from every
// other advisory lock this engine takes -- the janitor's is the other one --
// because two subsystems sharing a key would block each other for no reason
// and neither would be wrong about anything.
const auditChainLock int64 = 0x51474e415249_01

// The chain: entry_hash = SHA-256(prev_hash || canonical(record)). Reading the
// previous hash and inserting happen in the same transaction, so two concurrent
// writers cannot both chain off the same predecessor and silently fork the chain
// -- the second serialises behind the first.
func Write(ctx context.Context, tx pgx.Tx, e Event) error {
	return write(ctx, tx, e, hashVersion)
}

// write is Write at a given hash version; a test writes a version-1 row with it
// to prove such rows keep verifying.
func write(ctx context.Context, tx pgx.Tx, e Event, version int) error {
	if e.Type == "" {
		return fmt.Errorf("audit: event type is required")
	}
	if e.Retention == "" {
		// Default to the strictest retention. An event nobody classified is far
		// more likely to be security-relevant than to be a preference change,
		// and over-retaining is recoverable where under-retaining is not.
		e.Retention = RetentionSecurity
	}
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	// The subject column holds a person's id. A token's subject can be a
	// client, acting for itself, and an exchanged or transaction token passed
	// that here: the insert failed on the uuid cast and the record was lost.
	// Kept in the detail instead, on a copy, since the caller owns its map.
	if e.SubjectID != "" {
		if _, perr := uuid.Parse(e.SubjectID); perr != nil {
			detail := make(map[string]any, len(e.Detail)+1)
			for k, v := range e.Detail {
				detail[k] = v
			}
			detail["subject"] = e.SubjectID
			e.Detail, e.SubjectID = detail, ""
		}
	}

	raw, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("audit: encoding detail: %w", err)
	}

	// Hash the form PostgreSQL will actually STORE, not the bytes Go produced.
	//
	// jsonb is a normalising type: it reorders object keys (by length, then
	// bytewise -- not the lexicographic order Go's encoder emits), drops
	// insignificant whitespace, and canonicalises numbers. So the bytes written
	// and the bytes read back differ, and a chain hashed over the former can
	// never be verified against the latter. Every entry would report as
	// tampered, which is the most useless possible failure mode for an integrity
	// mechanism -- it would be indistinguishable from a real attack.
	//
	// One extra round trip to let the database canonicalise it, and both sides
	// then hash exactly the same string.
	//
	// The ids go through the same round trip, for the same reason. PostgreSQL
	// accepts a uuid in upper case, in braces, without hyphens or with one after
	// every four digits, and stores the canonical form. A respelled id therefore
	// hashed as one string and was stored as another, and the chain read as
	// tampered from that row on, permanently: an Admin API PATCH to
	// /admin/users/d578-90c1-... did exactly this to the shared test database.
	var detail string
	var org, subject, actor, correlation, token *string
	if err := tx.QueryRow(ctx,
		`SELECT $1::jsonb::text, $2::uuid::text, $3::uuid::text, $4::uuid::text, $5::uuid::text, $6::uuid::text`,
		raw, nullIfEmpty(e.OrgID), nullIfEmpty(e.SubjectID), nullIfEmpty(e.ActorID),
		nullIfEmpty(e.CorrelationID), nullIfEmpty(e.AdminTokenID)).
		Scan(&detail, &org, &subject, &actor, &correlation, &token); err != nil {
		return fmt.Errorf("audit: canonicalising the entry: %w", err)
	}
	e.OrgID, e.SubjectID, e.ActorID = deref(org), deref(subject), deref(actor)
	e.CorrelationID, e.AdminTokenID = deref(correlation), deref(token)

	// An advisory lock on the CHAIN, not a row lock on its current tail.
	//
	// The first version took FOR UPDATE on the tail row, reasoning that
	// appenders would then serialise. They do not, and the difference is a
	// property of READ COMMITTED that is easy to miss:
	//
	//	T1 and T2 both find row 134 as the tail. T1 locks it.
	//	T2 blocks.
	//	T1 inserts 135 (prev = 134) and commits, releasing the lock.
	//	T2 wakes, RE-READS ROW 134 -- unchanged, so it proceeds -- and inserts
	//	136, also claiming 134 as its predecessor.
	//
	// The lock was held on the row the query had already chosen, and the
	// ORDER BY was never re-evaluated. Two entries then share a predecessor,
	// which is exactly what a deleted entry looks like when the chain is
	// verified: the log reports tampering where there was none, and a log that
	// cries wolf is a log nobody checks.
	//
	// Found by running two instances against one database and watching the
	// audit tests fail on data nobody had touched. It was never specific to
	// more than one instance -- two concurrent sign-ins do it on a single one --
	// but two made it frequent enough to notice.
	//
	// The lock is transaction-scoped, so it is released by the commit or
	// rollback and a process that dies mid-append cannot wedge the log. The key
	// is a constant because the chain is global: it is verified in id order
	// across every organisation, so a per-organisation lock would permit
	// exactly the interleaving this prevents.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLock); err != nil {
		return fmt.Errorf("audit: taking the chain lock: %w", err)
	}

	var prev []byte
	err = tx.QueryRow(ctx, `
		SELECT entry_hash FROM core.audit_events
		ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("audit: reading chain head: %w", err)
	}

	// Microseconds, which is what timestamptz keeps, so the time hashed is the
	// time stored.
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	entry := hashFor(version, prev, e, detail)

	_, err = tx.Exec(ctx, `
		INSERT INTO core.audit_events
			(org_id, event_type, subject_id, actor_id, client_id, correlation_id,
			 retention_class, detail, prev_hash, entry_hash, admin_token_id, occurred_at, hash_version)
		VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6::uuid, $7, $8, $9, $10, $11::uuid, $12, $13)`,
		nullIfEmpty(e.OrgID), e.Type, nullIfEmpty(e.SubjectID), nullIfEmpty(e.ActorID),
		nullIfEmpty(e.ClientID), nullIfEmpty(e.CorrelationID), e.Retention,
		detail, prev, entry, nullIfEmpty(e.AdminTokenID), e.OccurredAt, version)
	if err != nil {
		return fmt.Errorf("audit: appending %s: %w", e.Type, err)
	}

	// Fan the event out to subscribers, in THIS transaction.
	//
	// Here rather than at each call site for the same reason the audit entry
	// itself is written here: there are dozens of places that record an event,
	// and a fan-out written at each of them is one missing from some of them --
	// discovered by an operator whose alerting never fired for the one event
	// type that mattered.
	//
	// Same transaction, which is the entire point of an outbox: the event and
	// the intent to deliver it commit together, so there is no window where the
	// log says something happened and nothing was ever sent.
	if observe != nil {
		observe(e)
	}
	if publish != nil && e.OrgID != "" {
		if err := publish(ctx, tx, e, detail); err != nil {
			// NOT fatal to the audit write. A subscription that cannot be
			// enqueued must not stop the thing being audited from happening --
			// that would make an event subscription a way to break sign-in.
			return nil
		}
	}
	return nil
}

// Publisher fans an audited event out to event subscriptions.
//
// A function variable rather than a direct call, because the fan-out lives in
// the store package and the store package is where the audit tables are read
// from -- importing it here would be a cycle. Set once at startup by whoever
// wires the server together.
type Publisher func(ctx context.Context, tx pgx.Tx, e Event, detail string) error

var publish Publisher

// SetPublisher installs the fan-out. Called once, at startup.
func SetPublisher(p Publisher) { publish = p }

// Observer sees every event Write appends, once it is written, for counting:
// the metrics engine counts sign-ins and failures here, so every path that
// audits one is counted by it. It runs before the caller commits, so a
// transaction that then rolls back has still been counted; a counter is an
// approximation, and the audit trail is the record.
type Observer func(e Event)

var observe Observer

// SetObserver installs the observer. Called once, at startup.
func SetObserver(o Observer) { observe = o }

// chainHash binds each entry to its predecessor.
//
// The fields are written in a fixed order with explicit separators rather than
// concatenated: without separators, ("ab","c") and ("a","bc") hash identically,
// which would let two different events share an entry_hash and make the chain
// unable to distinguish them.
func chainHash(prev []byte, e Event, detail string) []byte {
	h := sha256.New()
	h.Write(prev)
	for _, f := range []string{
		e.Type, e.OrgID, e.SubjectID, e.ActorID, e.ClientID, e.CorrelationID, e.Retention,
	} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}

	// # Why the attribution is appended conditionally
	//
	// AdminTokenID must be INSIDE the hash: attribution the chain does not cover
	// can be rewritten without breaking it, leaving a record that looks intact
	// while naming the wrong credential -- the single thing an attacker most
	// wants to change about an audit trail.
	//
	// But it is written ONLY when set. Appending an empty string plus its
	// separator still changes the digest, so hashing it unconditionally
	// invalidates every row written before this field existed. The chain is
	// append-only and those rows cannot be rehashed, so the entire history would
	// read as tampered -- indistinguishable from a real attack, which is the most
	// useless possible failure for an integrity mechanism.
	//
	// Skipping it when empty means a pre-existing row hashes exactly as it did,
	// and an attributed row commits to its token. Verified by
	// TestExistingChainSurvivesTheAttributionField.
	if e.AdminTokenID != "" {
		h.Write([]byte(e.AdminTokenID))
		h.Write([]byte{0})
	}

	h.Write([]byte(detail))
	return h.Sum(nil)
}

// hashFor is the entry hash at a version, or nil for one this binary does
// not know, which no stored hash equals: a row claiming an unknown version is
// read as broken, not skipped.
//
// Version 2 is version 1 followed by the version and occurred_at, in UTC to
// the microsecond. Appended rather than mixed in, so version 1 stays exactly
// what every existing row was hashed as.
func hashFor(version int, prev []byte, e Event, detail string) []byte {
	switch version {
	case 1:
		return chainHash(prev, e, detail)
	case 2:
		h := sha256.New()
		h.Write(chainHash(prev, e, detail))
		h.Write([]byte("v2\x00"))
		h.Write([]byte(e.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000Z")))
		return h.Sum(nil)
	}
	return nil
}

// Verify walks the chain and reports the first entry whose hash does not follow
// from its predecessor.
//
// This is what makes the chain worth having: a log nobody can check is a log
// that only deters attackers who have not thought about it. Returns the id of
// the first broken entry, or 0 when the chain is intact.
//
// After an archive (3.18) the trail starts where the latest one ended: the
// first entry left must link to the last one archived, and no entry the
// archive removed may still be here.
func Verify(ctx context.Context, tx pgx.Tx) (brokenAt int64, checked int, err error) {
	anchor, archivedThrough, err := archiveAnchor(ctx, tx)
	if err != nil {
		return 0, 0, fmt.Errorf("reading the latest archive: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT id, event_type, COALESCE(org_id::text,''), COALESCE(subject_id::text,''),
		       COALESCE(actor_id::text,''), COALESCE(client_id,''),
		       COALESCE(correlation_id::text,''), retention_class,
		       detail::text, prev_hash, entry_hash,
		       COALESCE(admin_token_id::text,''), occurred_at, hash_version
		FROM core.audit_events ORDER BY id`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	expectedPrev := anchor
	for rows.Next() {
		var id int64
		var e Event
		var detail string
		var prev, entry []byte
		var version int
		if err := rows.Scan(&id, &e.Type, &e.OrgID, &e.SubjectID, &e.ActorID,
			&e.ClientID, &e.CorrelationID, &e.Retention, &detail, &prev, &entry,
			&e.AdminTokenID, &e.OccurredAt, &version); err != nil {
			return 0, checked, err
		}
		checked++
		if id <= archivedThrough {
			return id, checked, nil
		}

		// A rewritten or deleted predecessor shows up here, not at the entry
		// that was tampered with -- which is the property that makes deletion
		// detectable rather than merely discouraged.
		if !equalBytes(prev, expectedPrev) {
			return id, checked, nil
		}
		want := hashFor(version, prev, e, detail)
		if !equalBytes(want, entry) {
			return id, checked, nil
		}
		expectedPrev = entry
	}
	return 0, checked, rows.Err()
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
