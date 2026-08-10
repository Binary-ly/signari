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
//     Personal detail goes in detail_enc, encrypted under the subject's own key,
//     so shredding that key removes the content and leaves the record.
//
//  2. THE HASH CHAIN COVERS CIPHERTEXT. If it covered plaintext, crypto-shredding
//     a subject would break every subsequent link and destroy the integrity
//     property for every other tenant in the table. Chaining over what is stored
//     means the chain still verifies after a shred.
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

	"github.com/jackc/pgx/v5"
)

// Event types. Constants rather than free strings so a typo is a compile error
// and the set is greppable -- an audit trail nobody can query is decoration.
const (
	EventLoginSucceeded   = "login.succeeded"
	EventLoginFailed      = "login.failed"
	EventLogout           = "session.logout"
	EventCodeIssued       = "oauth.code_issued"
	EventCodeRedeemed     = "oauth.code_redeemed"
	EventCodeReused       = "oauth.code_reused"
	EventTokenRefreshed   = "oauth.token_refreshed"
	EventRefreshReused    = "oauth.refresh_reused"
	EventTokenRevoked     = "oauth.token_revoked"
	EventClientCredential = "oauth.client_credentials_issued"
	EventClientUpdated    = "admin.client_updated"
	EventKeyRotated       = "keys.rotated"
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
	// Detail is NON-personal context: reason codes, counts, scope names. Anything
	// identifying a person belongs in the encrypted column, not here.
	Detail map[string]any
}

// Write appends one event inside the caller's transaction.
//
// The chain: entry_hash = SHA-256(prev_hash || canonical(record)). Reading the
// previous hash and inserting happen in the same transaction, so two concurrent
// writers cannot both chain off the same predecessor and silently fork the chain
// -- the second serialises behind the first.
func Write(ctx context.Context, tx pgx.Tx, e Event) error {
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
	var detail string
	if err := tx.QueryRow(ctx, `SELECT $1::jsonb::text`, raw).Scan(&detail); err != nil {
		return fmt.Errorf("audit: canonicalising detail: %w", err)
	}

	// FOR UPDATE on the tail row: this is what serialises concurrent appenders.
	// Without it two transactions read the same prev_hash and produce two
	// entries claiming the same predecessor, which is indistinguishable from a
	// deletion when the chain is later verified.
	var prev []byte
	err = tx.QueryRow(ctx, `
		SELECT entry_hash FROM core.audit_events
		ORDER BY id DESC LIMIT 1 FOR UPDATE`).Scan(&prev)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("audit: reading chain head: %w", err)
	}

	entry := chainHash(prev, e, detail)

	_, err = tx.Exec(ctx, `
		INSERT INTO core.audit_events
			(org_id, event_type, subject_id, actor_id, client_id, correlation_id,
			 retention_class, detail, prev_hash, entry_hash)
		VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6::uuid, $7, $8, $9, $10)`,
		nullIfEmpty(e.OrgID), e.Type, nullIfEmpty(e.SubjectID), nullIfEmpty(e.ActorID),
		nullIfEmpty(e.ClientID), nullIfEmpty(e.CorrelationID), e.Retention,
		detail, prev, entry)
	if err != nil {
		return fmt.Errorf("audit: appending %s: %w", e.Type, err)
	}
	return nil
}

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
	h.Write([]byte(detail))
	return h.Sum(nil)
}

// Verify walks the chain and reports the first entry whose hash does not follow
// from its predecessor.
//
// This is what makes the chain worth having: a log nobody can check is a log
// that only deters attackers who have not thought about it. Returns the id of
// the first broken entry, or 0 when the chain is intact.
func Verify(ctx context.Context, tx pgx.Tx) (brokenAt int64, checked int, err error) {
	rows, err := tx.Query(ctx, `
		SELECT id, event_type, COALESCE(org_id::text,''), COALESCE(subject_id::text,''),
		       COALESCE(actor_id::text,''), COALESCE(client_id,''),
		       COALESCE(correlation_id::text,''), retention_class,
		       detail::text, prev_hash, entry_hash
		FROM core.audit_events ORDER BY id`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	var expectedPrev []byte
	for rows.Next() {
		var id int64
		var e Event
		var detail string
		var prev, entry []byte
		if err := rows.Scan(&id, &e.Type, &e.OrgID, &e.SubjectID, &e.ActorID,
			&e.ClientID, &e.CorrelationID, &e.Retention, &detail, &prev, &entry); err != nil {
			return 0, checked, err
		}
		checked++

		// A rewritten or deleted predecessor shows up here, not at the entry
		// that was tampered with -- which is the property that makes deletion
		// detectable rather than merely discouraged.
		if !equalBytes(prev, expectedPrev) {
			return id, checked, nil
		}
		want := chainHash(prev, e, detail)
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
