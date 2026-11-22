package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/provider"
)

// Extension providers (ADR-011).
//
// A hook may have several providers when each can only refuse (provider.Hook.Composes):
// they compose as AND, so there is no "which wins?" to answer. The two hooks whose answer
// is a value keep one, by a unique index rather than by ordering: an engine that chose by
// whichever row sorts first has made a policy decision nobody asked it to make.

// providerReader is what a provider read needs: both shapes, because a load
// reads one row and a list reads many. Narrow rather than taking a *pgxpool.Pool,
// so a caller inside a transaction can pass the transaction.
type providerReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// LoadProvider returns the enabled provider of a hook that has one, or nil when none
// is registered.
//
// nil is the ordinary case and is NOT an error. Almost no deployment registers a
// provider, and treating its absence as a failure would put an error in the log
// of every decision made by everybody who never wanted the feature.
func LoadProvider(ctx context.Context, q providerReader, root *keys.RootKey, orgID string,
	hook provider.Hook) (*provider.Provider, error) {
	ps, err := LoadProviders(ctx, q, root, orgID, hook)
	if err != nil || len(ps) == 0 {
		return nil, err
	}
	return ps[0], nil
}

// LoadProviders returns a hook's enabled providers in the order they are asked.
func LoadProviders(ctx context.Context, q providerReader, root *keys.RootKey, orgID string,
	hook provider.Hook) ([]*provider.Provider, error) {
	rows, err := q.Query(ctx, `
		SELECT name, position, url, mode, timeout_ms, token_wrapped, allowed_claims
		  FROM core.providers
		 WHERE org_id = $1::uuid AND hook = $2 AND enabled
		 ORDER BY position, name`, orgID, string(hook))
	if err != nil {
		return nil, fmt.Errorf("loading the %s providers: %w", hook, err)
	}
	defer rows.Close()
	var out []*provider.Provider
	for rows.Next() {
		var (
			p         provider.Provider
			timeoutMS int
			sealed    []byte
		)
		if err := rows.Scan(&p.Name, &p.Position, &p.URL, &p.Mode, &timeoutMS, &sealed, &p.AllowedClaims); err != nil {
			return nil, fmt.Errorf("loading the %s providers: %w", hook, err)
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
		out = append(out, &p)
	}
	return out, rows.Err()
}

// ErrProviderAmbiguous is a change that names a hook with several providers and not
// which of them.
var ErrProviderAmbiguous = errors.New("this hook has several providers; say which by name")

// ErrProviderTaken is a second provider for a hook whose answer is one value.
var ErrProviderTaken = errors.New("this hook has one provider, because its answer is a value and not a veto")

// ErrProviderClaim is a claim another of the hook's providers may already set.
var ErrProviderClaim = errors.New("another provider on this hook may already add that claim, and a claim has one source")

// providerWriter is what a change to one provider needs.
type providerWriter interface {
	Execer
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// whichProvider is the row a change means: the one named, or with no name the only one.
func whichProvider(ctx context.Context, q providerWriter, orgID string, hook provider.Hook, name string) (string, error) {
	rows, err := q.Query(ctx, `SELECT id::text FROM core.providers
		WHERE org_id = $1::uuid AND hook = $2 AND ($3 = '' OR name = $3) LIMIT 2`, orgID, string(hook), name)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	switch len(ids) {
	case 0:
		return "", providerNotRegistered{hook}
	case 1:
		return ids[0], nil
	}
	return "", ErrProviderAmbiguous
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

// SaveProvider registers or replaces a hook's provider of that name.
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
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms, token_wrapped, wrap_key_ref, position)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (org_id, hook, name) DO UPDATE SET
			url = EXCLUDED.url, mode = EXCLUDED.mode, position = EXCLUDED.position,
			timeout_ms = EXCLUDED.timeout_ms, enabled = true, updated_at = now()
		RETURNING id::text, xmax = 0`,
		orgID, p.Name, string(p.Hook), p.URL, string(p.Mode),
		int(p.Timeout/time.Millisecond), sealed, root.Ref(), p.Position).Scan(&id, &created)
	if err != nil {
		if strings.Contains(err.Error(), "providers_one_answer") {
			return "", "", ErrProviderTaken
		}
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
	hook provider.Hook, name string) (string, error) {
	id, err := whichProvider(ctx, tx, orgID, hook, name)
	if err != nil {
		return "", err
	}
	secret, sealed, err := newProviderSecret(root)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.providers SET token_wrapped = $2, wrap_key_ref = $3, updated_at = now()
		 WHERE id = $1::uuid`, id, sealed, root.Ref()); err != nil {
		return "", fmt.Errorf("rotating the %s provider's secret: %w", hook, err)
	}
	return secret, nil
}

// ErrProviderNotRegistered is a hook the organisation has no provider for;
// each change answers it as providerNotRegistered, which names the hook.
var ErrProviderNotRegistered = errors.New("no provider is registered for that hook")

type providerNotRegistered struct{ hook provider.Hook }

func (e providerNotRegistered) Error() string {
	return fmt.Sprintf("no %s provider is registered for this organisation", e.hook)
}

func (e providerNotRegistered) Is(target error) bool { return target == ErrProviderNotRegistered }

// ErrProtocolClaim is an allow-list naming a claim the protocol decides (sub,
// iss, aud, exp, iat, nbf, jti, nonce, azp, scope, client_id, auth_time, acr,
// amr): letting an external service overwrite one is how a token is minted
// for the wrong subject. The database refuses it too.
var ErrProtocolClaim = errors.New("a hook may not be allowed to set a protocol claim")

// ErrHookAddsNothing is a list for a hook that only answers yes or no, which would be a
// setting that reads as working and does nothing.
var ErrHookAddsNothing = errors.New("this hook adds nothing, so it has no list of what it may add")

// SetProviderClaims replaces the claims a token hook may add; empty lets it
// add none. The allow-list is the hook's whole security model: without it a
// service returning {"admin": true} would put that in a token this engine
// signed. Behind `signari provider claims` and the Admin API (6.07). A claim has one
// source on a hook, so that what a token says never depends on who was asked last.
func SetProviderClaims(ctx context.Context, tx providerWriter, orgID string, hook provider.Hook, name string, claims []string) error {
	if claims == nil {
		claims = []string{}
	}
	if len(claims) > 0 && !hook.Contributes() {
		return ErrHookAddsNothing
	}
	id, err := whichProvider(ctx, tx, orgID, hook, name)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE core.providers SET allowed_claims = $2 WHERE id = $1::uuid
		AND NOT EXISTS (SELECT 1 FROM core.providers o WHERE o.org_id = $3::uuid AND o.hook = $4
		                   AND o.id <> $1::uuid AND o.allowed_claims && $2)`, id, claims, orgID, string(hook))
	if err != nil {
		if strings.Contains(err.Error(), "providers_claims_are_not_protocol_claims") {
			return ErrProtocolClaim
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderClaim
	}
	return nil
}

// DeleteProvider removes a hook's provider. Reports whether one was there.
func DeleteProvider(ctx context.Context, tx pgx.Tx, orgID string, hook provider.Hook, name string) (bool, error) {
	id, err := whichProvider(ctx, tx, orgID, hook, name)
	if errors.Is(err, ErrProviderNotRegistered) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.providers WHERE id = $1::uuid`, id); err != nil {
		return false, fmt.Errorf("removing the %s provider: %w", hook, err)
	}
	return true, nil
}

// ListProviders returns every provider for an organisation.
type ProviderRow struct {
	ID   string
	Name string
	Hook string
	// Position is when it is asked among the hook's providers.
	Position int
	URL      string
	Mode     string
	Timeout  time.Duration
	Enabled  bool
	// Signed is whether calls carry a Signari-Signature. False for a provider
	// registered before secrets existed, until it is rotated.
	Signed bool
	// AllowedClaims are what a token hook may add.
	AllowedClaims []string
}

func ListProviders(ctx context.Context, q providerReader, orgID string) ([]ProviderRow, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, name, hook, position, url, mode, timeout_ms, enabled, token_wrapped IS NOT NULL,
		       COALESCE(allowed_claims, '{}')
		  FROM core.providers WHERE org_id = $1::uuid ORDER BY hook, position, name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing providers: %w", err)
	}
	defer rows.Close()

	var out []ProviderRow
	for rows.Next() {
		var r ProviderRow
		var ms int
		if err := rows.Scan(&r.ID, &r.Name, &r.Hook, &r.Position, &r.URL, &r.Mode, &ms, &r.Enabled, &r.Signed,
			&r.AllowedClaims); err != nil {
			return nil, err
		}
		r.Timeout = time.Duration(ms) * time.Millisecond
		out = append(out, r)
	}
	return out, rows.Err()
}
