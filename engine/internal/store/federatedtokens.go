package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
)

// federatedTokensContext separates this sealing from every other under the root key.
const federatedTokensContext = "federated_tokens"

// ErrNoFederatedTokens is a person with nothing kept at a provider.
var ErrNoFederatedTokens = errors.New("no tokens are kept for this person at this provider")

// KeepFederatedTokens seals what a provider handed over. The ID token is left out: it
// has done its work, and nothing is kept that nothing will read.
func KeepFederatedTokens(ctx context.Context, q SubjectDB, root *keys.RootKey, providerID, userID, orgID string,
	ts federation.TokenSet) error {
	if root == nil {
		return errors.New("keeping a provider's tokens needs the root key")
	}
	ts.IDToken = ""
	plain, err := json.Marshal(ts)
	if err != nil {
		return err
	}
	sealed, err := root.Seal(plain, federatedTokensContext)
	if err != nil {
		return fmt.Errorf("sealing a provider's tokens: %w", err)
	}
	var expires *time.Time
	if ts.ExpiresIn > 0 {
		at := time.Now().Add(time.Duration(ts.ExpiresIn) * time.Second)
		expires = &at
	}
	_, err = q.Exec(ctx, `
		INSERT INTO core.federated_tokens (provider_id, user_id, org_id, sealed, expires_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)
		ON CONFLICT (provider_id, user_id) DO UPDATE
		   SET sealed = EXCLUDED.sealed, expires_at = EXCLUDED.expires_at, updated_at = now()`,
		providerID, userID, orgID, sealed, expires)
	return err
}

// FederatedTokens opens what is kept for a person at a provider.
func FederatedTokens(ctx context.Context, q SubjectDB, root *keys.RootKey, providerID, userID string) (
	*federation.TokenSet, *time.Time, error) {
	if root == nil {
		return nil, nil, errors.New("reading a provider's tokens needs the root key")
	}
	var sealed []byte
	var expires *time.Time
	err := q.QueryRow(ctx, `SELECT sealed, expires_at FROM core.federated_tokens
		WHERE provider_id = $1::uuid AND user_id = $2::uuid`, providerID, userID).Scan(&sealed, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNoFederatedTokens
	}
	if err != nil {
		return nil, nil, err
	}
	plain, err := root.Open(sealed, federatedTokensContext)
	if err != nil {
		return nil, nil, fmt.Errorf("opening a provider's tokens: %w", err)
	}
	var ts federation.TokenSet
	if err := json.Unmarshal(plain, &ts); err != nil {
		return nil, nil, err
	}
	return &ts, expires, nil
}

// ForgetFederatedTokens removes what is kept for a person at a provider. A provider
// that will not refresh them has ended them, and nothing is gained by holding on.
func ForgetFederatedTokens(ctx context.Context, q Execer, providerID, userID string) error {
	_, err := q.Exec(ctx, `DELETE FROM core.federated_tokens WHERE provider_id = $1::uuid AND user_id = $2::uuid`,
		providerID, userID)
	return err
}
