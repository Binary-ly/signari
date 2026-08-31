package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/provider"
)

// Extension providers (ADR-011).
//
// One provider per hook per organisation, enforced by a UNIQUE constraint rather
// than by ordering: two providers answering the same question raises "which
// wins?", and an engine that answers it by whichever row sorts first has made a
// policy decision nobody asked it to make.

// providerReader is what a provider read needs: both shapes, because a load
// reads one row and a list reads many. Narrow rather than taking a *pgxpool.Pool,
// so a caller inside a transaction can pass the transaction.
type providerReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// LoadProvider returns the enabled provider for a hook, or nil when none is
// registered.
//
// nil is the ordinary case and is NOT an error. Almost no deployment registers a
// provider, and treating its absence as a failure would put an error in the log
// of every decision made by everybody who never wanted the feature.
func LoadProvider(ctx context.Context, q providerReader, orgID string, hook provider.Hook) (*provider.Provider, error) {
	var (
		p         provider.Provider
		timeoutMS int
		token     *string
	)
	err := q.QueryRow(ctx, `
		SELECT name, url, mode, timeout_ms, NULL::text, allowed_claims
		  FROM core.providers
		 WHERE org_id = $1::uuid AND hook = $2 AND enabled
		 LIMIT 1`, orgID, string(hook)).
		Scan(&p.Name, &p.URL, &p.Mode, &timeoutMS, &token, &p.AllowedClaims)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading the %s provider: %w", hook, err)
	}
	p.Hook = hook
	p.Timeout = time.Duration(timeoutMS) * time.Millisecond
	if token != nil {
		p.Token = *token
	}

	// Validated on the way OUT of the database, not only on the way in.
	//
	// The table is reachable by the maintenance role, so a row can arrive without
	// passing through the registration path. A provider that fails validation here
	// is refused rather than called: the alternative is dialling a URL that the
	// checks would have rejected, which is exactly the case the checks exist for.
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("the stored %s provider is not usable: %w", hook, err)
	}
	return &p, nil
}

// SaveProvider registers or replaces the provider for a hook.
func SaveProvider(ctx context.Context, tx pgx.Tx, orgID string, p provider.Provider) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id, hook) DO UPDATE SET
			name = EXCLUDED.name, url = EXCLUDED.url, mode = EXCLUDED.mode,
			timeout_ms = EXCLUDED.timeout_ms, enabled = true, updated_at = now()
		RETURNING id::text`,
		orgID, p.Name, string(p.Hook), p.URL, string(p.Mode),
		int(p.Timeout/time.Millisecond)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("registering the %s provider: %w", p.Hook, err)
	}
	return id, nil
}

// DeleteProvider removes a hook's provider. Reports whether one was there.
func DeleteProvider(ctx context.Context, tx pgx.Tx, orgID string, hook provider.Hook) (bool, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.providers WHERE org_id = $1::uuid AND hook = $2`,
		orgID, string(hook))
	if err != nil {
		return false, fmt.Errorf("removing the %s provider: %w", hook, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListProviders returns every provider for an organisation.
type ProviderRow struct {
	ID      string
	Name    string
	Hook    string
	URL     string
	Mode    string
	Timeout time.Duration
	Enabled bool
}

func ListProviders(ctx context.Context, q providerReader, orgID string) ([]ProviderRow, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, name, hook, url, mode, timeout_ms, enabled
		  FROM core.providers WHERE org_id = $1::uuid ORDER BY hook`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing providers: %w", err)
	}
	defer rows.Close()

	var out []ProviderRow
	for rows.Next() {
		var r ProviderRow
		var ms int
		if err := rows.Scan(&r.ID, &r.Name, &r.Hook, &r.URL, &r.Mode, &ms, &r.Enabled); err != nil {
			return nil, err
		}
		r.Timeout = time.Duration(ms) * time.Millisecond
		out = append(out, r)
	}
	return out, rows.Err()
}
