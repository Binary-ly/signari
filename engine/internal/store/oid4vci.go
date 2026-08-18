package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oid4vci"
)

// OID4VCI pre-authorized codes.
//
// The code is a bearer credential -- §6.1 makes client authentication OPTIONAL
// for this grant -- so it is stored hashed and claimed atomically, exactly like
// an authorization code.

// rowQuerier is the single-row read this file needs. Narrower than Querier,
// which returns pgx.Rows, so that both the server's pool and the CLI's single
// connection satisfy it -- offers are minted from the command line and redeemed
// by the token endpoint, and a signature naming *pgxpool.Pool would have meant
// the CLI writing its own copy of the INSERT.
type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ErrPreAuthUnknown means no live code matched.
var ErrPreAuthUnknown = errors.New("this pre-authorized code is unknown or has expired")

// NewPreAuthorizedCode records an offer and returns nothing; the caller already
// holds the plaintext it generated.
func NewPreAuthorizedCode(ctx context.Context, db Execer, orgID, userID, clientID string,
	codeHash []byte, configIDs []string, tx *oid4vci.TxCode, txHash []byte,
	ttl time.Duration) error {

	// Required here rather than by a NOT NULL, because the column had to be
	// nullable to be added. §6.1 lets the wallet omit client_id, so this is the
	// only place the client is decided -- an offer without one would redeem into
	// a token with no audience and no scopes.
	if clientID == "" {
		return fmt.Errorf("a pre-authorized code must name the client whose scopes " +
			"the resulting token carries: the wallet is permitted to omit client_id " +
			"at redemption, so nothing later can supply it")
	}

	var mode, desc *string
	var length *int
	if tx != nil {
		if tx.InputMode != "" {
			m := tx.InputMode
			mode = &m
		}
		if tx.Length > 0 {
			l := tx.Length
			length = &l
		}
		if tx.Description != "" {
			d := tx.Description
			desc = &d
		}
	}

	_, err := db.Exec(ctx, `
		INSERT INTO core.preauthorized_codes
			(org_id, user_id, client_id, code_hash, configuration_ids,
			 tx_code_hash, tx_code_input_mode, tx_code_length, tx_code_description,
			 expires_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, now() + $10::interval)`,
		orgID, userID, clientID, codeHash, configIDs, txHash, mode, length, desc, ttl.String())
	if err != nil {
		return fmt.Errorf("recording the pre-authorized code: %w", err)
	}
	return nil
}

// NewPreAuthCode mints the pre-authorized code itself.
//
// 32 bytes, the same width as an authorization code, because it is the same
// kind of thing: §6.1 makes client authentication optional for this grant, so
// whoever holds this string gets a token.
func NewPreAuthCode() (code string, hash []byte, err error) {
	return NewInvitationToken()
}

// NewTxCode mints a Transaction Code of n digits and returns its hash.
//
// Numeric, because §3.5's `input_mode` defaults to "numeric" and a wallet
// renders a numeric keypad for it — a code the holder types on a phone while
// standing at a counter. Short by necessity, which is why MaxTxCodeAttempts
// exists: the entropy here is a rate limit, not a key length.
func NewTxCode(n int) (code string, hash []byte, err error) {
	if n < 4 || n > 12 {
		return "", nil, fmt.Errorf("a transaction code of %d digits is outside "+
			"4..12: shorter is guessable within the attempt limit, and longer is "+
			"something nobody types correctly at a counter", n)
	}
	code, err = newNumericCode(n)
	if err != nil {
		return "", nil, err
	}
	return code, HashToken(code), nil
}

// PreAuthorized is a code read back at redemption.
type PreAuthorized struct {
	oid4vci.StoredCode
	ID     string
	OrgID  string
	UserID string
	// ClientID is the client chosen when the offer was minted. The redemption
	// uses this, not anything the wallet sends.
	ClientID string
	txHash   []byte
}

// LookupPreAuthorizedCode reads a code without consuming it.
//
// Reading before claiming, unlike the authorization code path, and the reason is
// the transaction code: a wrong one must NOT spend the offer, or an attacker who
// guesses once has denied the holder their credential. So the sequence is read,
// check the transaction code, then claim -- and a wrong guess costs an attempt
// rather than the whole offer.
func LookupPreAuthorizedCode(ctx context.Context, db rowQuerier, codeHash []byte) (*PreAuthorized, error) {
	var p PreAuthorized
	var redeemed *time.Time
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, user_id::text, coalesce(client_id, ''),
		       configuration_ids,
		       tx_code_hash, tx_attempts, expires_at, redeemed_at
		FROM core.preauthorized_codes
		WHERE code_hash = $1`, codeHash).
		Scan(&p.ID, &p.OrgID, &p.UserID, &p.ClientID, &p.ConfigurationIDs,
			&p.txHash, &p.Attempts, &p.ExpiresAt, &redeemed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPreAuthUnknown
		}
		return nil, err
	}
	p.Redeemed = redeemed != nil
	// The column being non-NULL is what records that the offer carried a
	// `tx_code` object -- including an empty one, which §6.1 says still requires
	// a value. Deriving this from the hash's length or emptiness would lose that.
	p.RequiresTxCode = len(p.txHash) > 0
	return &p, nil
}

// CheckTxCode compares a presented transaction code in constant time.
func (p *PreAuthorized) CheckTxCode(presentedHash []byte) bool {
	if len(p.txHash) == 0 {
		return true // no transaction code required
	}
	return subtle.ConstantTimeCompare(p.txHash, presentedHash) == 1
}

// RecordTxCodeFailure charges one attempt.
func RecordTxCodeFailure(ctx context.Context, db Execer, id string) error {
	_, err := db.Exec(ctx, `
		UPDATE core.preauthorized_codes SET tx_attempts = tx_attempts + 1
		WHERE id = $1::uuid`, id)
	return err
}

// ClaimPreAuthorizedCode marks the code redeemed, single use.
//
// The claim and the check are one statement, so two concurrent redemptions
// cannot both succeed -- the same reason the authorization code path uses
// `UPDATE ... WHERE consumed_at IS NULL RETURNING`.
func ClaimPreAuthorizedCode(ctx context.Context, db Execer, id string) error {
	tag, err := db.Exec(ctx, `
		UPDATE core.preauthorized_codes SET redeemed_at = now()
		WHERE id = $1::uuid AND redeemed_at IS NULL AND expires_at > now()`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("this pre-authorized code has already been used")
	}
	return nil
}
