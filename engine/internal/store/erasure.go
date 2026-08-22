package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// Erasure — crypto-shredding a subject, which is irreversible by design.

var (
	// ErrSubjectUnknown means no key was ever minted for that subject.
	ErrSubjectUnknown = errors.New("no subject key exists for that identifier")
	// ErrAlreadyErased means the subject was erased before.
	ErrAlreadyErased = errors.New("that subject was already erased")
	// ErrSubjectStillActive means the account is live and the caller did not say
	// to deactivate it.
	ErrSubjectStillActive = errors.New("that subject's account is still active")
)

// ErasureReport describes what an erasure did or would do.
type ErasureReport struct {
	SubjectID string
	// OrgID is empty when the subject has no user row, which is possible: a
	// subject key outlives the account it was made for.
	OrgID string
	// Email is shown back to the operator so they can see WHO they are about to
	// erase. It is the only thing standing between a mistyped uuid and the wrong
	// person, and it is read before anything is destroyed for exactly that reason.
	Email        string
	AccountFound bool
	StillActive  bool
	// TOTPCredentials is what becomes unreadable. Counted rather than described,
	// because listing a person's credentials into an operator's terminal during
	// an erasure is the opposite of the point.
	TOTPCredentials int
	Deactivated     bool
}

// InspectSubject reports what erasing a subject would destroy, without doing it.
//
// Separate from EraseSubject so a caller can show the operator who they are about
// to erase BEFORE asking them to confirm. A confirmation prompt that cannot say
// whose data is at stake is a prompt people learn to answer without reading.
func InspectSubject(ctx context.Context, tx pgx.Tx, subjectID string) (*ErasureReport, error) {
	rep := &ErasureReport{SubjectID: subjectID}

	var erased bool
	err := tx.QueryRow(ctx, `
		SELECT erased_at IS NOT NULL FROM core.subject_keys
		WHERE subject_id = $1::uuid`, subjectID).Scan(&erased)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSubjectUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("reading the subject key: %w", err)
	}
	if erased {
		return nil, ErrAlreadyErased
	}

	// The account, if there still is one.
	var status string
	err = tx.QueryRow(ctx, `
		SELECT org_id::text, coalesce(email,''), status FROM core.users
		WHERE id = $1::uuid`, subjectID).Scan(&rep.OrgID, &rep.Email, &status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// A subject key with no user row. The account was deleted and the key
		// outlived it, so the ciphertext it protects is still readable and still
		// worth destroying -- which is the whole reason erasure is keyed on the
		// subject rather than on the account.
		rep.AccountFound = false
	case err != nil:
		return nil, fmt.Errorf("reading the account: %w", err)
	default:
		rep.AccountFound = true
		rep.StillActive = status == "active"
	}

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM core.totp_credentials WHERE user_id = $1::uuid`,
		subjectID).Scan(&rep.TOTPCredentials); err != nil {
		return nil, fmt.Errorf("counting protected credentials: %w", err)
	}
	return rep, nil
}

// EraseSubject destroys a subject's data-encryption key.
//
// # Why an active account is refused unless the caller says otherwise
//
// keys.LoadOrCreateSubjectKey returns ErrErased for an erased subject and
// deliberately never mints a replacement -- "doing so would make new data
// readable again under the same subject id and quietly undo an erasure that
// someone is legally entitled to rely on". That is right, and it means an erased
// subject can never hold a key again.
//
// So an account left ACTIVE after erasure is a broken account, not a working one
// with less data: every path that needs the key fails, permanently, and the
// failures look like bugs rather than like the erasure somebody asked for. That
// is not a state to arrive at by omission.
//
// It is refused rather than resolved, because which resolution is right is the
// operator's call -- the doctor has said so since this gap was reported, listing
// immediate, delay-and-notify and two-person as defensible answers. Passing
// deactivate makes the choice explicit; deactivating the account first and then
// erasing is the same thing in two deliberate steps.
func EraseSubject(ctx context.Context, tx pgx.Tx, subjectID string, deactivate bool) (*ErasureReport, error) {
	rep, err := InspectSubject(ctx, tx, subjectID)
	if err != nil {
		return nil, err
	}
	if rep.StillActive && !deactivate {
		return rep, ErrSubjectStillActive
	}

	if err := keys.EraseSubject(ctx, tx, subjectID); err != nil {
		return nil, err
	}

	if rep.StillActive && deactivate {
		// Same transaction as the shred. The two must not be able to diverge:
		// an account deactivated without the erasure is recoverable, and an
		// erasure without the deactivation is the broken state above.
		if _, err := tx.Exec(ctx, `
			UPDATE core.users SET status = 'deactivated', updated_at = now()
			WHERE id = $1::uuid`, subjectID); err != nil {
			return nil, fmt.Errorf("deactivating the erased account: %w", err)
		}
		rep.Deactivated = true
	}
	return rep, nil
}
