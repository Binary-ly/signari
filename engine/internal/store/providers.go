package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
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
func LoadProvider(ctx context.Context, q providerReader, root *keys.RootKey, orgID string,
	hook provider.Hook) (*provider.Provider, error) {
	var (
		p         provider.Provider
		timeoutMS int
		sealed    []byte
	)
	err := q.QueryRow(ctx, `
		SELECT name, url, mode, timeout_ms, token_wrapped, allowed_claims
		  FROM core.providers
		 WHERE org_id = $1::uuid AND hook = $2 AND enabled
		 LIMIT 1`, orgID, string(hook)).
		Scan(&p.Name, &p.URL, &p.Mode, &timeoutMS, &sealed, &p.AllowedClaims)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading the %s provider: %w", hook, err)
	}
	p.Hook = hook
	p.Timeout = time.Duration(timeoutMS) * time.Millisecond
	if sealed != nil {
		// A secret that will not open is a configuration fault, and the call is
		// refused rather than made unsigned: a provider that checks signatures
		// would refuse it, and one fail_open would then be skipped silently.
		if root == nil {
			return nil, fmt.Errorf("the %s provider's signing secret is sealed and no root key is loaded", hook)
		}
		secret, oerr := root.Open(sealed, SealContextProviderSecret)
		if oerr != nil {
			return nil, fmt.Errorf("the %s provider's signing secret does not open: %w", hook, oerr)
		}
		p.Secret = string(secret)
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

// SealContextProviderSecret binds a sealed provider secret to its column.
const SealContextProviderSecret = "provider-secret"

// newProviderSecret is 32 random bytes, base64url: what the provider is given
// to check Signari-Signature with.
func newProviderSecret(root *keys.RootKey) (secret string, sealed []byte, err error) {
	if root == nil {
		return "", nil, fmt.Errorf("a provider's signing secret is sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", nil, err
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	sealed, err = root.Seal([]byte(secret), SealContextProviderSecret)
	return secret, sealed, err
}

// SaveProvider registers or replaces the provider for a hook.
//
// A new registration mints the signing secret and returns it, the one time it
// is shown. Replacing a registration keeps the secret the provider already
// holds, and returns "": changing a timeout must not break a provider that
// checks signatures. RotateProviderSecret replaces it on purpose.
func SaveProvider(ctx context.Context, tx pgx.Tx, root *keys.RootKey, orgID string,
	p provider.Provider) (id, secret string, err error) {
	if err := p.Validate(); err != nil {
		return "", "", err
	}
	minted, sealed, err := newProviderSecret(root)
	if err != nil {
		return "", "", err
	}
	var created bool
	err = tx.QueryRow(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms, token_wrapped, wrap_key_ref)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (org_id, hook) DO UPDATE SET
			name = EXCLUDED.name, url = EXCLUDED.url, mode = EXCLUDED.mode,
			timeout_ms = EXCLUDED.timeout_ms, enabled = true, updated_at = now()
		RETURNING id::text, xmax = 0`,
		orgID, p.Name, string(p.Hook), p.URL, string(p.Mode),
		int(p.Timeout/time.Millisecond), sealed, root.Ref()).Scan(&id, &created)
	if err != nil {
		return "", "", fmt.Errorf("registering the %s provider: %w", p.Hook, err)
	}
	if created {
		secret = minted
	}
	return id, secret, nil
}

// RotateProviderSecret replaces a hook's provider's signing secret and returns
// the new one, the one time it is shown. The old one stops verifying at once.
func RotateProviderSecret(ctx context.Context, tx pgx.Tx, root *keys.RootKey, orgID string,
	hook provider.Hook) (string, error) {
	secret, sealed, err := newProviderSecret(root)
	if err != nil {
		return "", err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.providers SET token_wrapped = $3, wrap_key_ref = $4, updated_at = now()
		 WHERE org_id = $1::uuid AND hook = $2`, orgID, string(hook), sealed, root.Ref())
	if err != nil {
		return "", fmt.Errorf("rotating the %s provider's secret: %w", hook, err)
	}
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("no %s provider is registered for this organisation", hook)
	}
	return secret, nil
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
	// Signed is whether calls carry a Signari-Signature. False for a provider
	// registered before secrets existed, until it is rotated.
	Signed bool
}

func ListProviders(ctx context.Context, q providerReader, orgID string) ([]ProviderRow, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, name, hook, url, mode, timeout_ms, enabled, token_wrapped IS NOT NULL
		  FROM core.providers WHERE org_id = $1::uuid ORDER BY hook`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing providers: %w", err)
	}
	defer rows.Close()

	var out []ProviderRow
	for rows.Next() {
		var r ProviderRow
		var ms int
		if err := rows.Scan(&r.ID, &r.Name, &r.Hook, &r.URL, &r.Mode, &ms, &r.Enabled, &r.Signed); err != nil {
			return nil, err
		}
		r.Timeout = time.Duration(ms) * time.Millisecond
		out = append(out, r)
	}
	return out, rows.Err()
}
