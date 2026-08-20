package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// WebAuthn credential storage.
//
// Two rules here are the ones that separate a passkey implementation from a
// passkey implementation people can safely rely on, and both are easy to get
// backwards.

// MinCredentialsForPasswordless is TWO.
//
// One passkey means losing that device locks the account out permanently -- the
// credential lives in a secure enclave and cannot be exported, copied or
// recovered. An IdP that lets a user delete their password while holding a
// single passkey has built a trapdoor, not a security feature.
//
// Two is not arbitrary: it is the smallest number where losing one device is a
// recoverable inconvenience rather than an account death.
const MinCredentialsForPasswordless = 2

var (
	ErrCredentialNotFound = errors.New("store: webauthn credential not found")
	// ErrCredentialCloned means the signature counter went backwards. See
	// UpdateSignCount for exactly what that does and does not prove.
	ErrCredentialCloned = errors.New("store: authenticator signature counter went backwards")
	// ErrWouldLockOut means removing this credential would leave the user with no
	// way in.
	ErrWouldLockOut = errors.New("store: removing this credential would lock the account out")
)

// WebAuthnCredential is one registered authenticator.
type WebAuthnCredential struct {
	ID             string
	CredentialID   []byte
	PublicKey      []byte
	SignCount      uint32
	IsDiscoverable bool
	// BackupEligible is the WebAuthn L3 BE flag, fixed at registration.
	//
	// §6.1.3: "The value of the BE flag is set during authenticatorMakeCredential
	// operation and MUST NOT change." It must therefore survive from registration
	// to every later assertion -- go-webauthn compares the asserted flag against
	// this one and refuses the login when they differ, so a credential loaded
	// without it cannot sign in if it is backup eligible.
	BackupEligible bool
	// BackupState is the BS flag as of the most recent ceremony. §6.1.3 RECOMMENDS
	// storing "the most recent value of these flags with the user account"; a
	// 1->0 transition means a credential stopped being backed up.
	BackupState  bool
	Transports   []string
	AAGUID       []byte
	RPID         string
	FriendlyName string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// SaveCredential records a newly registered authenticator.
//
// rp_id is stored PER CREDENTIAL, not merely read from the instance. The
// instance's value can legitimately be set before any passkey exists, and a
// credential must carry the value it was actually created under -- that is what
// makes a Related Origin Requests migration possible later, and what lets an
// operator see exactly which passkeys a change would have destroyed.
func SaveCredential(ctx context.Context, tx pgx.Tx, userID, orgID, rpID string,
	credentialID, publicKey, aaguid []byte, signCount uint32,
	discoverable, backupEligible, backupState bool,
	transports []string, attestation, friendlyName string) error {

	// discoverable and backupEligible are separate arguments deliberately, and
	// named apart from each other, because they were once ONE argument's worth of
	// confusion: the caller passed cred.Flags.BackupEligible into a parameter
	// called `discoverable`, and it went into is_discoverable. Two adjacent
	// booleans of the same type, so nothing complained for as long as it existed.
	_, err := tx.Exec(ctx, `
		INSERT INTO core.webauthn_credentials
			(user_id, org_id, credential_id, public_key, sign_count,
			 is_discoverable, backup_eligible, backup_state,
			 transports, aaguid, attestation_type, rp_id, friendly_name)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		userID, orgID, credentialID, publicKey, int64(signCount),
		discoverable, backupEligible, backupState,
		transports, aaguid, attestation, rpID, nullIfEmpty(friendlyName))
	if err != nil {
		return fmt.Errorf("saving webauthn credential: %w", err)
	}
	return nil
}

// CredentialsForUser lists a user's authenticators.
func CredentialsForUser(ctx context.Context, tx pgx.Tx, userID string) ([]WebAuthnCredential, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, credential_id, public_key, sign_count, is_discoverable,
		       backup_eligible, backup_state,
		       transports, aaguid, rp_id, COALESCE(friendly_name,''), created_at, last_used_at
		FROM core.webauthn_credentials
		WHERE user_id = $1::uuid
		ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("listing webauthn credentials: %w", err)
	}
	defer rows.Close()

	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var count int64
		if err := rows.Scan(&c.ID, &c.CredentialID, &c.PublicKey, &count, &c.IsDiscoverable,
			&c.BackupEligible, &c.BackupState,
			&c.Transports, &c.AAGUID, &c.RPID, &c.FriendlyName, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		c.SignCount = clampSignCount(count)
		out = append(out, c)
	}
	return out, rows.Err()
}

// CredentialByID finds one credential by its raw credential id.
func CredentialByID(ctx context.Context, tx pgx.Tx, credentialID []byte) (*WebAuthnCredential, string, error) {
	var c WebAuthnCredential
	var count int64
	var userID string
	err := tx.QueryRow(ctx, `
		SELECT id::text, user_id::text, credential_id, public_key, sign_count,
		       is_discoverable, backup_eligible, backup_state,
		       transports, aaguid, rp_id, COALESCE(friendly_name,''),
		       created_at, last_used_at
		FROM core.webauthn_credentials WHERE credential_id = $1
		FOR UPDATE`, credentialID).
		Scan(&c.ID, &userID, &c.CredentialID, &c.PublicKey, &count, &c.IsDiscoverable,
			&c.BackupEligible, &c.BackupState,
			&c.Transports, &c.AAGUID, &c.RPID, &c.FriendlyName, &c.CreatedAt, &c.LastUsedAt)
	if err == pgx.ErrNoRows {
		return nil, "", ErrCredentialNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("loading webauthn credential: %w", err)
	}
	c.SignCount = clampSignCount(count)
	return &c, userID, nil
}

// UpdateSignCount advances the signature counter and reports cloning.
//
// The counter is the only cloning signal WebAuthn provides, and it is a weak
// one, so the rules matter:
//
//   - MANY AUTHENTICATORS ALWAYS RETURN ZERO. Every Apple passkey does, and so do
//     most platform authenticators, because a credential synced across devices
//     cannot maintain a coherent counter. A server that treats 0 as suspicious
//     rejects the majority of real passkeys in the world.
//
//   - So an authenticator that has ALWAYS reported zero is never a signal. That
//     is the stored-zero-and-presented-zero case, and it is the common one.
//
//   - But a counter that WAS non-zero and now reports zero is a signal, and this
//     code used to discard it. WebAuthn Level 3, §7.2 step 21, verbatim:
//
//     "If authData.signCount is nonzero OR credentialRecord.signCount is
//     nonzero, then run the following sub-step: ... less than or equal to
//     credentialRecord.signCount: This is a signal, but not proof, that the
//     authenticator may be cloned."
//
//     The condition is a disjunction. Ours was a conjunction, which meant a
//     credential that demonstrably kept a counter and then reported zero was
//     ignored -- the one case that cannot be explained by "this authenticator
//     does not implement counters", because it evidently did.
//
//   - And even then it is evidence, not proof: a genuine authenticator with a
//     flaky counter, or a race between two concurrent assertions, can produce it.
//     The caller decides what to do.
//
// The counter is still written on the cloning path. Refusing to advance it would
// let an attacker replay the same assertion indefinitely, each attempt producing
// the same alarm and none of them closing the hole.
func UpdateSignCount(ctx context.Context, tx pgx.Tx, credentialID []byte, stored, presented uint32, backupState bool) error {
	// The disjunction WebAuthn L3 §7.2 step 21 specifies, not a conjunction.
	//
	// stored=0, presented=0  -> skipped entirely: the authenticator does not
	//                           count, which is most passkeys in the world.
	// stored=0, presented=N  -> first use of a counting authenticator, fine.
	// stored=N, presented>N  -> normal advance.
	// stored=N, presented<=N -> a signal, INCLUDING presented=0.
	cloned := (stored != 0 || presented != 0) && presented <= stored

	if _, err := tx.Exec(ctx, `
		UPDATE core.webauthn_credentials
		SET sign_count = GREATEST(sign_count, $2), last_used_at = now(),
		    -- §6.1.3: "It is RECOMMENDED that Relying Parties store the most
		    -- recent value of these flags with the user account for future
		    -- evaluation." BS is the one that legitimately changes; BE is fixed
		    -- at registration and is never written here.
		    backup_state = $3
		WHERE credential_id = $1`, credentialID, int64(presented), backupState); err != nil {
		return fmt.Errorf("updating sign count: %w", err)
	}
	if cloned {
		return ErrCredentialCloned
	}
	return nil
}

// CountCredentials returns how many authenticators a user has.
func CountCredentials(ctx context.Context, tx pgx.Tx, userID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx,
		`SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting webauthn credentials: %w", err)
	}
	return n, nil
}

// CanGoPasswordless reports whether it is safe to let this user remove their
// password. See MinCredentialsForPasswordless for why the answer is not one.
func CanGoPasswordless(ctx context.Context, tx pgx.Tx, userID string) (bool, error) {
	n, err := CountCredentials(ctx, tx, userID)
	if err != nil {
		return false, err
	}
	return n >= MinCredentialsForPasswordless, nil
}

// DeleteCredential removes an authenticator, refusing when it is the user's last
// way in.
//
// The check and the delete share one transaction and the count is taken FOR
// UPDATE, because two concurrent delete requests that each see "two credentials
// remain" would otherwise both proceed and leave zero.
func DeleteCredential(ctx context.Context, tx pgx.Tx, userID, credentialRowID string) error {
	// OWNERSHIP FIRST. Checking the lockout rule before confirming the caller
	// owns the credential computes it from the WRONG account: a stranger with no
	// credentials trips "this is your last one" and gets a misleading error,
	// while the ownership check never runs at all. Order is the whole fix.
	var owned bool
	err := tx.QueryRow(ctx, `
		SELECT true FROM core.webauthn_credentials
		WHERE id = $1::uuid AND user_id = $2::uuid
		FOR UPDATE`, credentialRowID, userID).Scan(&owned)
	if err == pgx.ErrNoRows {
		// Same answer whether the credential does not exist or belongs to
		// someone else -- distinguishing them would confirm which uuids are real.
		return ErrCredentialNotFound
	}
	if err != nil {
		return fmt.Errorf("locating webauthn credential: %w", err)
	}

	var total, withPassword int
	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid),
		       (SELECT count(*) FROM core.password_credentials WHERE user_id = $1::uuid)`,
		userID).Scan(&total, &withPassword); err != nil {
		return fmt.Errorf("checking remaining credentials: %w", err)
	}

	// Removing the last passkey is only safe when a password remains. Otherwise
	// the account has no authentication method at all, and no recovery path that
	// does not go through a human being -- which is the weakest link in any
	// system that has one.
	if total <= 1 && withPassword == 0 {
		return ErrWouldLockOut
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM core.webauthn_credentials
		WHERE id = $1::uuid AND user_id = $2::uuid`, credentialRowID, userID); err != nil {
		return fmt.Errorf("deleting webauthn credential: %w", err)
	}
	return nil
}

// clampSignCount narrows a stored counter without wrapping.
//
// signCount is a uint32 on the wire and an int64 in the database. A plain cast
// of a value above the uint32 range wraps to a small number -- and this counter
// is the CLONING DETECTOR: a wrapped value reads as "the counter went
// backwards", or worse, lets a replayed assertion look like progress. Clamping
// keeps the comparison monotonic whatever is in the column.
//
// Flagged by gosec (G115). The overflow is not reachable through the normal
// path, because what goes in came from a uint32; it is reachable through a
// corrupted or hand-edited row, which is exactly when a cloning detector should
// still behave.
func clampSignCount(v int64) uint32 {
	if v < 0 {
		return 0
	}
	if v > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}
