package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/prompts"
)

// The writes behind `signari prompt` and the Admin API's prompt routes (6.07),
// one implementation for both.

// PromptDefinition is a prompt as an operator writes it.
type PromptDefinition struct {
	Slug   string
	Title  string
	Body   string
	Once   bool
	Order  int
	Fields []prompts.Field
}

// ErrInvalidPrompt is a prompt that could not be answered, or a field writing
// an attribute the organisation did not declare or whose type its answers do
// not fit; refused when it is stored rather than shown on every sign-in.
type ErrInvalidPrompt struct{ Err error }

func (e ErrInvalidPrompt) Error() string { return e.Err.Error() }
func (e ErrInvalidPrompt) Unwrap() error { return e.Err }

// SavePrompt validates and stores a prompt, returning its version and how many
// people who answered an earlier version will be asked again. The version
// moves when what a person reads and answers changes -- the title, the body,
// the fields -- and not for the order or `once` (5.13), which migration 0183's
// trigger decides for this writer and any other.
func SavePrompt(ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string, d PromptDefinition) (version, reasked int, err error) {
	p := prompts.Prompt{Slug: d.Slug, Title: d.Title, Body: d.Body, Fields: d.Fields}
	if err := p.Validate(); err != nil {
		return 0, 0, ErrInvalidPrompt{err}
	}
	// A field that writes an attribute must name one the organisation
	// declared, of a type its answers fit (5.14).
	for _, f := range d.Fields {
		if f.Attribute == "" {
			continue
		}
		if err := CheckPromptAttribute(ctx, tx, orgID, f.Attribute, f.Candidates()); err != nil {
			return 0, 0, ErrInvalidPrompt{fmt.Errorf("prompt %q field %q: %w", d.Slug, f.Name, err)}
		}
	}
	if d.Fields == nil {
		d.Fields = []prompts.Field{}
	}
	fields, err := json.Marshal(d.Fields)
	if err != nil {
		return 0, 0, err
	}
	err = tx.QueryRow(ctx, `
		WITH saved AS (
			INSERT INTO core.prompts (org_id, slug, title, body, fields, once, position)
			VALUES ($1::uuid, $2, $3, NULLIF($4,''), $5, $6, $7)
			ON CONFLICT (org_id, slug) DO UPDATE SET
				title = EXCLUDED.title, body = EXCLUDED.body, fields = EXCLUDED.fields,
				once = EXCLUDED.once, position = EXCLUDED.position, updated_at = now()
			RETURNING id, version)
		SELECT s.version, (SELECT count(DISTINCT r.user_id) FROM core.prompt_responses r
		                    WHERE r.prompt_id = s.id AND r.prompt_version < s.version)
		  FROM saved s`,
		orgID, d.Slug, d.Title, d.Body, fields, d.Once, d.Order).Scan(&version, &reasked)
	return version, reasked, err
}

// SetPromptEnabled takes a prompt out of service or puts it back, reporting
// whether the organisation has it. Disabled, it is neither asked nor
// answerable; the answers given are kept.
func SetPromptEnabled(ctx context.Context, tx Execer, orgID, slug string, enabled bool) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE core.prompts SET enabled = $3
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, enabled)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// PromptSummary is one prompt as an operator sees it, with how many people
// answered its current version.
type PromptSummary struct {
	PromptDefinition
	Enabled  bool
	Version  int
	Answered int
}

// OrgPrompts lists an organisation's prompts in the order they are asked.
func OrgPrompts(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]PromptSummary, error) {
	rows, err := q.Query(ctx, `
		SELECT p.slug, p.title, COALESCE(p.body, ''), p.fields, p.once, p.position, p.enabled, p.version,
		       (SELECT count(DISTINCT r.user_id) FROM core.prompt_responses r
		         WHERE r.prompt_id = p.id AND r.prompt_version = p.version)
		  FROM core.prompts p WHERE p.org_id = $1::uuid
		 ORDER BY p.position, p.slug`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PromptSummary{}
	for rows.Next() {
		var s PromptSummary
		var fields []byte
		if err := rows.Scan(&s.Slug, &s.Title, &s.Body, &fields, &s.Once, &s.Order, &s.Enabled,
			&s.Version, &s.Answered); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(fields, &s.Fields); err != nil {
			return nil, fmt.Errorf("prompt %q holds fields that do not decode: %w", s.Slug, err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
