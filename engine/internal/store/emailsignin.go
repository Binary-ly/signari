package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
)

// A code emailed to the account's address as the first factor (5.16).
//
// Asking makes the row and queues the notice in one transaction; the code is
// minted only when the outbox delivers it, so the page that asked does the
// same work whether or not the account exists and sends nothing while it
// waits. Only the hash is kept, a code lasts ten minutes, and five wrong codes
// end it.

const (
	EmailSignInTTL      = 10 * time.Minute
	EmailSignInAttempts = 5
)

// ErrEmailSignInInvalid is a code row that is no longer the live one: used,
// replaced, expired, or already sent.
var ErrEmailSignInInvalid = errors.New("no live sign-in code")

// StartEmailSignIn replaces any live code for userID with a new one to be sent,
// and queues the notice that sends it.
func StartEmailSignIn(ctx context.Context, tx pgx.Tx, userID, orgID string) error {
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.email_sign_in_codes (user_id, org_id, expires_at)
		VALUES ($1::uuid, $2::uuid, now() + make_interval(secs => $3))
		ON CONFLICT (user_id) DO UPDATE SET id = gen_random_uuid(), code_hash = NULL, attempts = 0,
		       created_at = now(), expires_at = EXCLUDED.expires_at
		RETURNING id::text`, userID, orgID, int(EmailSignInTTL.Seconds())).Scan(&id); err != nil {
		return fmt.Errorf("starting an emailed sign-in: %w", err)
	}
	return EnqueueAccountNotice(ctx, tx, AccountNotice{UserID: userID, Notice: NoticeSignInCode, LinkID: id})
}

// MintEmailSignInCode makes the code for row id, when it is still the live one
// and none has been made for it, and returns it with when it expires.
func MintEmailSignInCode(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string) (string, time.Time, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", time.Time{}, err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	var expires time.Time
	err = db.QueryRow(ctx, `
		UPDATE core.email_sign_in_codes SET code_hash = $2
		 WHERE id = $1::uuid AND code_hash IS NULL AND expires_at > now()
		RETURNING expires_at`, id, HashToken(code)).Scan(&expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrEmailSignInInvalid
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("minting a sign-in code: %w", err)
	}
	return code, expires, nil
}

// VerifyEmailSignIn checks a code for userID. A right one is spent; a wrong one
// is counted against the code, and the EmailSignInAttempts-th ends it.
func VerifyEmailSignIn(ctx context.Context, tx pgx.Tx, userID, code string) (bool, error) {
	var hash []byte
	var attempts int
	err := tx.QueryRow(ctx, `
		SELECT code_hash, attempts FROM core.email_sign_in_codes
		 WHERE user_id = $1::uuid AND code_hash IS NOT NULL AND expires_at > now()
		 FOR UPDATE`, userID).Scan(&hash, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading the sign-in code: %w", err)
	}
	if subtle.ConstantTimeCompare(HashToken(code), hash) == 1 {
		if _, err := tx.Exec(ctx, `DELETE FROM core.email_sign_in_codes WHERE user_id = $1::uuid`, userID); err != nil {
			return false, fmt.Errorf("spending the sign-in code: %w", err)
		}
		return true, nil
	}
	if attempts+1 >= EmailSignInAttempts {
		_, err = tx.Exec(ctx, `DELETE FROM core.email_sign_in_codes WHERE user_id = $1::uuid`, userID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE core.email_sign_in_codes SET attempts = attempts + 1
			WHERE user_id = $1::uuid`, userID)
	}
	if err != nil {
		return false, fmt.Errorf("counting a wrong sign-in code: %w", err)
	}
	return false, nil
}
