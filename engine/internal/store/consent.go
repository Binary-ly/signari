package store

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Consent: the record of what a user actually agreed a client may see.
//
// The table has existed since the first migration with nothing writing to it,
// which meant every client was silently granted every scope it asked for. A user
// had no way to know what an application could read, and no way to take it back.
//
// The rule that makes consent mean anything, and the one implementations get
// wrong: consent is granted for a SPECIFIC SET OF SCOPES, not for a client. A
// client the user approved for `openid email` must ask again before it can have
// `offline_access` -- otherwise "approve once" becomes "approve forever, for
// anything you later decide to request".

// ConsentDecision is what the authorize endpoint needs to know.
type ConsentDecision struct {
	// Granted is true when every requested scope is already covered.
	Granted bool
	// Missing lists the scopes the user has not yet agreed to. These are what the
	// consent screen must show -- not the whole request, because re-asking about
	// scopes already granted trains people to click through.
	Missing []string
	// Previously lists scopes already granted, for context on the screen.
	Previously []string
}

// CheckConsent reports whether a user has already agreed to these scopes.
func CheckConsent(ctx context.Context, db *pgxpool.Pool, userID, clientID string, requested []string) (ConsentDecision, error) {
	var granted []string
	err := db.QueryRow(ctx, `
		SELECT scopes FROM core.consents
		WHERE user_id = $1::uuid AND client_id = $2 AND withdrawn_at IS NULL`,
		userID, clientID).Scan(&granted)
	if err != nil && err != pgx.ErrNoRows {
		return ConsentDecision{}, fmt.Errorf("checking consent: %w", err)
	}

	have := make(map[string]bool, len(granted))
	for _, s := range granted {
		have[s] = true
	}

	d := ConsentDecision{Previously: granted}
	for _, s := range requested {
		// `openid` is not a permission. It selects the protocol, carries no
		// personal data on its own, and asking a user to approve it is noise that
		// makes the real items harder to see.
		if s == "openid" {
			continue
		}
		if !have[s] {
			d.Missing = append(d.Missing, s)
		}
	}
	d.Granted = len(d.Missing) == 0
	return d, nil
}

// RecordConsent stores the user's decision, merging with anything already agreed.
//
// Merged rather than replaced: a client asking for one extra scope must not
// silently lose the ones the user granted last week, which would make every
// incremental request look like a fresh full grant.
func RecordConsent(ctx context.Context, tx pgx.Tx, userID, clientID string, scopes []string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.consents (user_id, client_id, scopes)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (user_id, client_id) DO UPDATE SET
			scopes = (
				SELECT array_agg(DISTINCT s ORDER BY s)
				FROM unnest(core.consents.scopes || EXCLUDED.scopes) AS s
			),
			granted_at = now(),
			-- Re-granting revives a withdrawn consent rather than leaving a row
			-- that says "withdrawn" while access works.
			withdrawn_at = NULL`,
		userID, clientID, scopes)
	if err != nil {
		return fmt.Errorf("recording consent: %w", err)
	}
	return nil
}

// WithdrawConsent revokes a client's access.
//
// The row is kept with withdrawn_at set rather than deleted: "this user withdrew
// access on this date" is a question worth being able to answer, and a deleted
// row answers nothing. Revoking the tokens is a SEPARATE step the caller must
// also take -- withdrawing consent does not retroactively invalidate a token
// already issued, and pretending otherwise would be the more dangerous lie.
func WithdrawConsent(ctx context.Context, tx pgx.Tx, userID, clientID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE core.consents SET withdrawn_at = now()
		WHERE user_id = $1::uuid AND client_id = $2 AND withdrawn_at IS NULL`,
		userID, clientID)
	if err != nil {
		return fmt.Errorf("withdrawing consent: %w", err)
	}
	return nil
}

// GrantedScopes lists everything a user has agreed to across all clients, for
// the account screen. Without this a user can grant access and never see it
// again, which is consent as a formality rather than a control.
func GrantedScopes(ctx context.Context, db *pgxpool.Pool, userID string) (map[string][]string, error) {
	rows, err := db.Query(ctx, `
		SELECT client_id, scopes FROM core.consents
		WHERE user_id = $1::uuid AND withdrawn_at IS NULL
		ORDER BY client_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("listing consents: %w", err)
	}
	defer rows.Close()

	out := map[string][]string{}
	for rows.Next() {
		var clientID string
		var scopes []string
		if err := rows.Scan(&clientID, &scopes); err != nil {
			return nil, err
		}
		sort.Strings(scopes)
		out[clientID] = scopes
	}
	return out, rows.Err()
}
