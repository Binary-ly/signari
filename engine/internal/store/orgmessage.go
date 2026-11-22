package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/i18n"
)

// OrgMessage is an organisation's own wording of one message in one language.
type OrgMessage struct {
	Locale string
	Key    string
	Body   string
}

// SetOrgMessage rewords a message for an organisation. The one writer the
// command, the route and a configuration file share, so all three refuse the same
// message for the same reason.
func SetOrgMessage(ctx context.Context, db Execer, orgID string, m OrgMessage) error {
	if err := i18n.Shipped().CheckWords(m.Locale, m.Key, m.Body); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `
		INSERT INTO core.org_messages (org_id, locale, key, body)
		VALUES ($1::uuid, $2, $3, $4)
		ON CONFLICT (org_id, locale, key) DO UPDATE SET body = EXCLUDED.body, updated_at = now()`,
		orgID, m.Locale, m.Key, m.Body)
	return err
}

// RemoveOrgMessage returns a message to the catalogue's wording, reporting
// whether the organisation had its own.
func RemoveOrgMessage(ctx context.Context, tx Execer, orgID, locale, key string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.org_messages
		WHERE org_id = $1::uuid AND locale = $2 AND key = $3`, orgID, locale, key)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// OrgMessages lists an organisation's own wording, by language then key.
func OrgMessages(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]OrgMessage, error) {
	rows, err := q.Query(ctx, `SELECT locale, key, body FROM core.org_messages
		WHERE org_id = $1::uuid ORDER BY locale, key`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrgMessage{}
	for rows.Next() {
		var m OrgMessage
		if err := rows.Scan(&m.Locale, &m.Key, &m.Body); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// OrgWords is an organisation's wording in one language, by key, for a printer.
func OrgWords(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID, locale string) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT key, body FROM core.org_messages
		WHERE org_id = $1::uuid AND locale = $2`, orgID, locale)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out map[string]string
	for rows.Next() {
		var key, body string
		if err := rows.Scan(&key, &body); err != nil {
			return nil, err
		}
		if out == nil {
			out = map[string]string{}
		}
		out[key] = body
	}
	return out, rows.Err()
}

// OrgSlug reads an organisation's slug, "" when there is no such organisation.
func OrgSlug(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (string, error) {
	var slug string
	err := q.QueryRow(ctx, `SELECT slug FROM core.organizations WHERE id = $1::uuid`, orgID).Scan(&slug)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return slug, err
}

// OrgSlugsKnown is which of these slugs name an organisation.
func OrgSlugsKnown(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, slugs []string) (map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT slug FROM core.organizations WHERE slug = ANY($1)`, slugs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	known := map[string]bool{}
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, err
		}
		known[slug] = true
	}
	return known, rows.Err()
}
