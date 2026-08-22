package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oidfed"
)

// OpenID Federation 1.0 Trust Marks: what this entity has issued, and what it
// has been given.
//
// The two halves are separate tables and separate functions here for the reason
// migration 0103 gives: one is an artefact we are accountable for and can
// revoke, the other is somebody else's assertion we merely republish.

// TrustMarkDB is what these functions need from a connection: read, write, and
// a transaction for the one operation that is two statements.
//
// An interface rather than *pgxpool.Pool because both callers are real: the
// engine serves the endpoints from a pool, and the CLI issues and revokes marks
// over a single connection. Writing each function twice would be two copies of
// the supersede rule, and the copy nobody reads is the one that drifts.
type TrustMarkDB interface {
	Querier
	Execer
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

// ErrTrustMarkUnknown means no such Trust Mark was issued by this entity.
//
// §8.4.2 and §8.6.2 both answer this with 404, and they answer it for the same
// underlying reason: we have nothing to say about a document we did not create.
var ErrTrustMarkUnknown = errors.New("this entity has not issued that trust mark")

// IssuedTrustMark is a Trust Mark this entity minted.
type IssuedTrustMark struct {
	Type    string
	Subject string
	// JWT is the compact serialisation, exactly as signed.
	JWT string
	// ExpiresAt is the zero time for a Trust Mark with no `exp`, which §7.1
	// permits and which means it does not expire.
	ExpiresAt time.Time
	Status    string
	RevokedAt time.Time
	Reason    string
	IssuedAt  time.Time
}

// Live reports whether this mark would be served and listed.
//
// Two conditions, and both belong here rather than at each caller: `revoked` is
// a stored fact and `expired` is a derived one, and the whole reason migration
// 0103 does not store `expired` as a status is that a row asserting one while
// its timestamp said the other would be read differently by different queries.
func (m *IssuedTrustMark) Live(now time.Time) bool {
	if m.Status != "active" {
		return false
	}
	return m.ExpiresAt.IsZero() || m.ExpiresAt.After(now)
}

// StatusAt maps a stored mark onto §8.4.2's vocabulary.
//
// Order matters. A mark that was revoked BEFORE it would have expired is
// `revoked`, not `expired`: those are different facts about why it is not
// usable, and the one a relying party needs is that somebody withdrew it.
func (m *IssuedTrustMark) StatusAt(now time.Time) string {
	if m.Status == "revoked" {
		return oidfed.StatusRevoked
	}
	if !m.ExpiresAt.IsZero() && !m.ExpiresAt.After(now) {
		return oidfed.StatusExpired
	}
	return oidfed.StatusActive
}

// IssueTrustMark records a newly minted Trust Mark, superseding any active one
// of the same type for the same subject.
//
// Superseding rather than refusing: reassessment is the ordinary lifecycle of a
// conformance mark, and an operator re-issuing after a review should not have to
// revoke first and remember why. The superseded row is kept, marked revoked with
// a reason, because the question "what did we assert about this entity in March"
// has an answer only if we keep one.
//
// One transaction, because the partial unique index means the supersede and the
// insert are not independent: between them there is a moment with no active mark
// and a moment with two, and only one of those is allowed to be observable.
func IssueTrustMark(ctx context.Context, db TrustMarkDB, instanceID string,
	m IssuedTrustMark) error {

	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE core.federation_trust_marks_issued
		SET status = 'revoked', revoked_at = now(),
		    revocation_reason = 'superseded by a later issuance'
		WHERE instance_id = $1::uuid AND trust_mark_type = $2 AND subject = $3
		  AND status = 'active'`,
		instanceID, m.Type, m.Subject); err != nil {
		return fmt.Errorf("superseding the previous trust mark: %w", err)
	}

	var exp any
	if !m.ExpiresAt.IsZero() {
		exp = m.ExpiresAt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.federation_trust_marks_issued
			(instance_id, trust_mark_type, subject, trust_mark, trust_mark_hash, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
		instanceID, m.Type, m.Subject, m.JWT, HashToken(m.JWT), exp); err != nil {
		return fmt.Errorf("recording the trust mark: %w", err)
	}
	return tx.Commit(ctx)
}

// RevokeTrustMark withdraws the active Trust Mark of a type for a subject.
//
// The guard is in the WHERE clause, not in a preceding SELECT. Two operators
// revoking at once would otherwise both read `active`, both write, and the
// second would overwrite the first's reason and timestamp with its own -- so the
// record would say it was revoked for the second reason, at the second time, and
// the first revocation would have left no trace.
func RevokeTrustMark(ctx context.Context, db TrustMarkDB, instanceID, markType,
	subject, reason string) error {

	tag, err := db.Exec(ctx, `
		UPDATE core.federation_trust_marks_issued
		SET status = 'revoked', revoked_at = now(), revocation_reason = $4
		WHERE instance_id = $1::uuid AND trust_mark_type = $2 AND subject = $3
		  AND status = 'active'`,
		instanceID, markType, subject, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTrustMarkUnknown
	}
	return nil
}

const trustMarkColumns = `trust_mark_type, subject, trust_mark,
	COALESCE(expires_at, 'epoch'::timestamptz), status,
	COALESCE(revoked_at, 'epoch'::timestamptz), COALESCE(revocation_reason,''), issued_at`

func scanTrustMark(row pgx.Row) (*IssuedTrustMark, error) {
	var m IssuedTrustMark
	var exp, rev time.Time
	if err := row.Scan(&m.Type, &m.Subject, &m.JWT, &exp, &m.Status, &rev,
		&m.Reason, &m.IssuedAt); err != nil {
		return nil, err
	}
	// `epoch` stands in for NULL at the SQL boundary and is translated back
	// here, so no caller has to know which sentinel was used. A zero
	// time.Time is what the rest of this package means by "no expiry".
	if !exp.Equal(time.Unix(0, 0).UTC()) {
		m.ExpiresAt = exp
	}
	if !rev.Equal(time.Unix(0, 0).UTC()) {
		m.RevokedAt = rev
	}
	return &m, nil
}

// TrustMarkByJWT finds a Trust Mark by its exact bytes.
//
// This is what §8.4.1 needs: a stranger hands us a whole Trust Mark and asks
// whether it is still active. Looked up by hash of the serialisation rather than
// by (type, subject), because those coordinates identify a POSITION and the
// question is about a DOCUMENT -- a superseded mark and its replacement share
// coordinates, and answering "active" about the old one would be a wrong answer
// that looks right.
func TrustMarkByJWT(ctx context.Context, db TrustMarkDB, instanceID, raw string) (*IssuedTrustMark, error) {
	m, err := scanTrustMark(db.QueryRow(ctx, `
		SELECT `+trustMarkColumns+`
		FROM core.federation_trust_marks_issued
		WHERE instance_id = $1::uuid AND trust_mark_hash = $2`,
		instanceID, HashToken(raw)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTrustMarkUnknown
	}
	return m, err
}

// ActiveTrustMark finds the live Trust Mark of a type for a subject, for §8.6.
func ActiveTrustMark(ctx context.Context, db TrustMarkDB, instanceID, markType,
	subject string) (*IssuedTrustMark, error) {

	m, err := scanTrustMark(db.QueryRow(ctx, `
		SELECT `+trustMarkColumns+`
		FROM core.federation_trust_marks_issued
		WHERE instance_id = $1::uuid AND trust_mark_type = $2 AND subject = $3
		  AND status = 'active'
		  AND (expires_at IS NULL OR expires_at > now())`,
		instanceID, markType, subject))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTrustMarkUnknown
	}
	return m, err
}

// TrustMarkedEntities lists the subjects holding a live mark of a type, §8.5.
//
// subject is an optional filter: "The list obtained in the response MUST be
// filtered to only the Entity matching this value."
//
// The expiry and revocation guards are in SQL rather than applied to the result,
// which is the same rule a published advisory was about elsewhere in this engine: a
// filter applied after the query is one a later refactor moves, drops, or
// short-circuits, and the failure is a listing that publishes withdrawn
// accreditations.
func TrustMarkedEntities(ctx context.Context, db TrustMarkDB, instanceID,
	markType, subject string) ([]string, error) {

	rows, err := db.Query(ctx, `
		SELECT subject
		FROM core.federation_trust_marks_issued
		WHERE instance_id = $1::uuid AND trust_mark_type = $2
		  AND status = 'active'
		  AND (expires_at IS NULL OR expires_at > now())
		  AND ($3 = '' OR subject = $3)
		ORDER BY subject`,
		instanceID, markType, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Non-nil so an empty result marshals as `[]`. §8.5.2's response is "a JSON
	// array with Entity Identifiers", and `null` is not one -- a client decoding
	// into an array type fails on it, which turns "nobody holds this mark" into
	// a parse error.
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListIssuedTrustMarks returns everything this entity has issued, live or not.
//
// For an operator, not for the protocol: the endpoints all filter to live marks,
// and the question "what did we withdraw and why" is the one an audit asks.
func ListIssuedTrustMarks(ctx context.Context, db TrustMarkDB, instanceID string) ([]*IssuedTrustMark, error) {
	rows, err := db.Query(ctx, `
		SELECT `+trustMarkColumns+`
		FROM core.federation_trust_marks_issued
		WHERE instance_id = $1::uuid
		ORDER BY trust_mark_type, subject, issued_at DESC`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*IssuedTrustMark
	for rows.Next() {
		m, err := scanTrustMark(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- Trust Marks held by this entity ----------------------------------------

// HeldTrustMark is a Trust Mark somebody granted us.
type HeldTrustMark struct {
	Type      string
	JWT       string
	Issuer    string
	ExpiresAt time.Time
	AddedAt   time.Time
}

// AddHeldTrustMark records a Trust Mark granted to this entity.
//
// Replaces any previous mark of the same type from the same issuer: a renewal
// is the ordinary case, and keeping both would publish two marks that say the
// same thing, one of them expired.
func AddHeldTrustMark(ctx context.Context, db TrustMarkDB, instanceID string,
	m HeldTrustMark) error {

	var exp any
	if !m.ExpiresAt.IsZero() {
		exp = m.ExpiresAt
	}
	_, err := db.Exec(ctx, `
		INSERT INTO core.federation_trust_marks_held
			(instance_id, trust_mark_type, trust_mark, issuer, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5)
		ON CONFLICT (instance_id, trust_mark_type, issuer)
		DO UPDATE SET trust_mark = EXCLUDED.trust_mark,
		              expires_at = EXCLUDED.expires_at,
		              added_at = now()`,
		instanceID, m.Type, m.JWT, m.Issuer, exp)
	return err
}

// RemoveHeldTrustMark stops publishing a Trust Mark.
func RemoveHeldTrustMark(ctx context.Context, db TrustMarkDB, instanceID,
	markType, issuer string) error {

	tag, err := db.Exec(ctx, `
		DELETE FROM core.federation_trust_marks_held
		WHERE instance_id = $1::uuid AND trust_mark_type = $2 AND issuer = $3`,
		instanceID, markType, issuer)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTrustMarkUnknown
	}
	return nil
}

// PublishableTrustMarks returns the `trust_marks` claim for our own Entity
// Configuration, §3.1.2.
//
// EXPIRED MARKS ARE EXCLUDED, in SQL.
//
// §7.3's expiry step means every reader rejects an expired mark, so publishing
// one puts a claim in a signed document that everybody is required to throw
// away. Worse, it is indistinguishable at a glance from a mark that is being
// honoured -- an operator reading their own Entity Configuration sees the
// accreditation listed and concludes the federation sees it too.
func PublishableTrustMarks(ctx context.Context, db TrustMarkDB, instanceID string) ([]oidfed.TrustMarkEntry, error) {
	rows, err := db.Query(ctx, `
		SELECT trust_mark_type, trust_mark
		FROM core.federation_trust_marks_held
		WHERE instance_id = $1::uuid
		  AND (expires_at IS NULL OR expires_at > now())
		ORDER BY trust_mark_type, issuer`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []oidfed.TrustMarkEntry
	for rows.Next() {
		var e oidfed.TrustMarkEntry
		if err := rows.Scan(&e.Type, &e.JWT); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListHeldTrustMarks returns every held mark, expired ones included, for an
// operator who needs to know which accreditation lapsed.
func ListHeldTrustMarks(ctx context.Context, db TrustMarkDB, instanceID string) ([]*HeldTrustMark, error) {
	rows, err := db.Query(ctx, `
		SELECT trust_mark_type, trust_mark, issuer,
		       COALESCE(expires_at, 'epoch'::timestamptz), added_at
		FROM core.federation_trust_marks_held
		WHERE instance_id = $1::uuid
		ORDER BY trust_mark_type, issuer`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*HeldTrustMark
	for rows.Next() {
		var m HeldTrustMark
		var exp time.Time
		if err := rows.Scan(&m.Type, &m.JWT, &m.Issuer, &exp, &m.AddedAt); err != nil {
			return nil, err
		}
		if !exp.Equal(time.Unix(0, 0).UTC()) {
			m.ExpiresAt = exp
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

// --- the Trust Anchor's governing claims ------------------------------------

// SetTrustMarkIssuers writes §3.1.2's trust_mark_issuers claim.
//
// nil clears it. The distinction matters: an absent claim is a Trust Anchor that
// has not constrained issuers, and an empty OBJECT is one that has enumerated
// zero types -- which reads to a validator as "no type is governed", not as "no
// issuer is permitted". See oidfed.TrustMarkIssuers.IssuerPermitted for why
// those three states are kept apart all the way down.
func SetTrustMarkIssuers(ctx context.Context, db TrustMarkDB, instanceID string,
	issuers oidfed.TrustMarkIssuers) error {

	var blob any
	if issuers != nil {
		b, err := json.Marshal(issuers)
		if err != nil {
			return err
		}
		blob = b
	}
	tag, err := db.Exec(ctx, `
		UPDATE core.federation_config SET trust_mark_issuers = $2, updated_at = now()
		WHERE instance_id = $1::uuid`, instanceID, blob)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("this instance has no federation configuration; run " +
			"`signari federation enable` first")
	}
	return nil
}

// SetTrustMarkOwners writes §3.1.2's trust_mark_owners claim. nil clears it.
func SetTrustMarkOwners(ctx context.Context, db TrustMarkDB, instanceID string,
	owners oidfed.TrustMarkOwners) error {

	var blob any
	if owners != nil {
		b, err := json.Marshal(owners)
		if err != nil {
			return err
		}
		blob = b
	}
	tag, err := db.Exec(ctx, `
		UPDATE core.federation_config SET trust_mark_owners = $2, updated_at = now()
		WHERE instance_id = $1::uuid`, instanceID, blob)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("this instance has no federation configuration; run " +
			"`signari federation enable` first")
	}
	return nil
}

// IsTrustMarkIssuer reports whether this entity has ever issued a Trust Mark.
//
// Used to decide whether to advertise §5.1.1's three endpoints. Revoked and
// expired rows count: an issuer that has withdrawn every mark it granted is
// still the party that must answer "was this withdrawn", which is precisely
// what the status endpoint is for.
func IsTrustMarkIssuer(ctx context.Context, db TrustMarkDB, instanceID string) (bool, error) {
	var any bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.federation_trust_marks_issued
		               WHERE instance_id = $1::uuid)`, instanceID).Scan(&any)
	return any, err
}
