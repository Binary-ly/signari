package store

import (
	"context"
	"encoding/json"
	"errors"

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

// ErrPromptChanged is an answer to a version of a prompt that is no longer the
// current one: it was edited while the person was reading it.
var ErrPromptChanged = errors.New("the prompt changed while it was being answered")

// Prompts a user still owes an answer to.
//
// Ordered, and filtered by what they have already answered. A prompt marked
// `once` disappears once its CURRENT version is answered (5.13), so editing
// the terms asks everybody again; one that is not once is asked every time,
// which is right for a notice and wrong for terms acceptance.
func PendingPrompts(ctx context.Context, db Querier, orgID, userID string) (
	[]prompts.Prompt, error) {

	rows, err := db.Query(ctx, `
		SELECT p.id::text, p.slug, p.title, COALESCE(p.body,''), p.once, p.fields, p.version
		  FROM core.prompts p
		 WHERE p.org_id = $1::uuid AND p.enabled
		   AND (NOT p.once OR NOT EXISTS (
		         SELECT 1 FROM core.prompt_responses r
		          WHERE r.prompt_id = p.id AND r.user_id = $2::uuid AND r.prompt_version = p.version))
		 ORDER BY p.position, p.slug`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []prompts.Prompt
	for rows.Next() {
		var p prompts.Prompt
		var fields []byte
		if err := rows.Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Once, &fields, &p.Version); err != nil {
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
		SELECT id::text, slug, title, COALESCE(body,''), once, fields, version
		  FROM core.prompts WHERE org_id = $1::uuid AND slug = $2 AND enabled`,
		orgID, slug).Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Once, &fields, &p.Version)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(fields, &p.Fields); err != nil {
		return nil, err
	}
	return &p, nil
}

// RecordAnswer stores a submission to the version of the prompt the person
// was shown, as a new row (5.13): earlier answers are kept, and an answer to a
// version since replaced is refused with ErrPromptChanged rather than filed
// against text the person never saw. The row carries the prompt's content hash
// as it stood, the evidence of exactly what was agreed.
func RecordAnswer(ctx context.Context, tx pgx.Tx, promptID string, version int, userID, orgID string,
	answers prompts.Answers) error {

	raw, err := json.Marshal(answers)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.prompt_responses (prompt_id, user_id, org_id, answers, prompt_version, content_hash)
		SELECT p.id, $2::uuid, $3::uuid, $4, p.version, p.content_hash
		  FROM core.prompts p WHERE p.id = $1::uuid AND p.version = $5`,
		promptID, userID, orgID, raw, version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrPromptChanged
	}
	return nil
}
