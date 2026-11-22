package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// SpendPushedRequest marks a handle used, in the transaction issuing its code. False
// means it was spent already, or has gone, and there is to be no code.
func SpendPushedRequest(ctx context.Context, tx pgx.Tx, uriHash []byte) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE core.pushed_requests SET used_at = now()
		WHERE uri_hash = $1 AND used_at IS NULL AND expires_at > now()`, uriHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// AnswerPushedPrompts takes prompts a person has answered out of a pushed request, as
// consumePrompt takes them out of a query. A prompt not answered, like `consent` beside
// `login`, stays. No row is no error: there is nothing left to ask.
func AnswerPushedPrompts(ctx context.Context, q SubjectDB, uriHash []byte, answered []string) error {
	var prompt string
	err := q.QueryRow(ctx, `SELECT COALESCE(params->'prompt'->>0, '') FROM core.pushed_requests
		WHERE uri_hash = $1`, uriHash).Scan(&prompt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && prompt == "") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading a pushed request's prompt: %w", err)
	}
	kept := slices.DeleteFunc(strings.Fields(prompt), func(p string) bool { return slices.Contains(answered, p) })
	if len(kept) == 0 {
		_, err = q.Exec(ctx, `UPDATE core.pushed_requests SET params = params - 'prompt' WHERE uri_hash = $1`, uriHash)
		return err
	}
	value, err := json.Marshal([]string{strings.Join(kept, " ")})
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE core.pushed_requests SET params = jsonb_set(params, '{prompt}', $2::jsonb)
		WHERE uri_hash = $1`, uriHash, string(value))
	return err
}

// SweepExpiredPushedRequests drops handles nobody redeemed.
func SweepExpiredPushedRequests(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.pushed_requests WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.pushed_requests WHERE expires_at <= now()
		LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
