package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/prompts"
)

// Querier is anything that can read: a pool or a transaction.
//
// This is not a convenience. The answer to a prompt is written inside the same
// transaction that then re-checks what is outstanding, and reading through the
// POOL there cannot see an uncommitted write — so the prompt comes back, is
// answered again, and comes back again. An unanswerable prompt is an infinite
// loop that locks every user out, and it only appears once a prompt exists.
type Querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// Prompts a user still owes an answer to.
//
// Ordered, and filtered by what they have already answered. A prompt marked
// `once` disappears after the first answer; one that is not is asked every time,
// which is right for a notice and wrong for terms acceptance.
func PendingPrompts(ctx context.Context, db Querier, orgID, userID string) (
	[]prompts.Prompt, error) {

	rows, err := db.Query(ctx, `
		SELECT p.id::text, p.slug, p.title, COALESCE(p.body,''), p.once, p.fields
		  FROM core.prompts p
		 WHERE p.org_id = $1::uuid AND p.enabled
		   AND (NOT p.once OR NOT EXISTS (
		         SELECT 1 FROM core.prompt_responses r
		          WHERE r.prompt_id = p.id AND r.user_id = $2::uuid))
		 ORDER BY p.position, p.slug`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []prompts.Prompt
	for rows.Next() {
		var p prompts.Prompt
		var fields []byte
		if err := rows.Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Once, &fields); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(fields, &p.Fields); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// LoadPrompt reads one by slug.
func LoadPrompt(ctx context.Context, db *pgxpool.Pool, orgID, slug string) (
	*prompts.Prompt, error) {

	var p prompts.Prompt
	var fields []byte
	err := db.QueryRow(ctx, `
		SELECT id::text, slug, title, COALESCE(body,''), once, fields
		  FROM core.prompts WHERE org_id = $1::uuid AND slug = $2 AND enabled`,
		orgID, slug).Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Once, &fields)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(fields, &p.Fields); err != nil {
		return nil, err
	}
	return &p, nil
}

// RecordAnswer stores a submission.
func RecordAnswer(ctx context.Context, tx pgx.Tx, promptID, userID, orgID string,
	answers prompts.Answers) error {

	raw, err := json.Marshal(answers)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO core.prompt_responses (prompt_id, user_id, org_id, answers)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		ON CONFLICT (prompt_id, user_id) DO UPDATE SET
			answers = EXCLUDED.answers, answered_at = now()`,
		promptID, userID, orgID, raw)
	return err
}
