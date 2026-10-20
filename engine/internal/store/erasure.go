package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// Erasure — crypto-shredding a subject and removing their account, which is
// irreversible by design.
//
// # What it was, and why that was not erasure (3.37)
//
// Erasure destroyed the subject's key and, for an active account, deactivated
// it. The key protects only what was sealed under it: the account itself, the
// address, the username and the names, sits in core.users in the clear, and
// stayed there. A person who never enrolled a second factor had no key at all,
// so their erasure was refused as unknown, "nothing here to destroy", over an
// account holding everything that identifies them.
//
// So erasure now removes the account, as deleting a user does, ending its
// sessions and telling the applications first, in the transaction that shreds
// the key. A subject with no key is given an erased one, so the record that
// the erasure happened, and the refusal ever to mint them a key, are the same
// for everyone. What survives is that subject_keys row and the audit trail,
// which names people by subject id only.

var (
	// ErrSubjectUnknown means the subject has neither a key nor an account.
	ErrSubjectUnknown = errors.New("no subject key or account exists for that identifier")
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
	// KeyHeld is whether the subject had a key to shred; one who never enrolled
	// a second factor has none, and is given an erased one.
	KeyHeld bool
	// Deactivated is whether the account was still active, which the caller
	// had to agree to end.
	Deactivated bool
	// AccountDeleted, SessionsEnded and NoticesQueued are what removing the
	// account did.
	AccountDeleted bool
	SessionsEnded  int
	NoticesQueued  int
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
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// No key: somebody who never enrolled a second factor. Still a person
		// with an account to erase, if there is one.
	case err != nil:
		return nil, fmt.Errorf("reading the subject key: %w", err)
	case erased:
		return nil, ErrAlreadyErased
	default:
		rep.KeyHeld = true
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
	if !rep.KeyHeld && !rep.AccountFound {
		return nil, ErrSubjectUnknown
	}

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM core.totp_credentials WHERE user_id = $1::uuid`,
		subjectID).Scan(&rep.TOTPCredentials); err != nil {
		return nil, fmt.Errorf("counting protected credentials: %w", err)
	}
	return rep, nil
}

// EraseSubject destroys a subject's data-encryption key and removes their
// account.
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

	if rep.KeyHeld {
		if err := keys.EraseSubject(ctx, tx, subjectID); err != nil {
			return nil, err
		}
	} else if _, err := tx.Exec(ctx, `
		INSERT INTO core.subject_keys (subject_id, wrapped_dek, wrap_key_ref, erased_at)
		VALUES ($1::uuid, NULL, 'none', now())`, subjectID); err != nil {
		// The same evidence a shred leaves, and the same refusal ever to mint
		// this subject a key.
		return nil, fmt.Errorf("recording the erasure: %w", err)
	}

	if rep.AccountFound {
		// Same transaction as the shred, as deleting a user does it: signed out
		// everywhere, each application told, then the account and every row
		// keyed by it gone (ADR-005: deletion is real). An erasure that left the
		// account behind left the person's address and names behind with it.
		term, err := TerminateSessions(ctx, tx, "", subjectID, ReasonUserDeleted)
		if err != nil {
			return nil, fmt.Errorf("ending the erased account's sessions: %w", err)
		}
		if term != nil {
			rep.SessionsEnded, rep.NoticesQueued = term.Sessions, term.Notices
		}
		if _, err := tx.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, subjectID); err != nil {
			return nil, fmt.Errorf("removing the erased account: %w", err)
		}
		rep.AccountDeleted = true
		rep.Deactivated = rep.StillActive
	}
	return rep, nil
}
