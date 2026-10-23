package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/safedial"
)

// Signing secrets an operator holds rather than one the engine minted (6.19):
// a configuration file names a provider's or a subscription's secret by
// reference, so the receiver and the engine are given the same one from the
// same place instead of an operator copying a minted one across after every
// fresh deployment.

// ErrWeakSigningSecret is a secret too short to sign with. The secret is all
// that tells a receiver this engine sent the call, so it is held to the length
// of the ones the engine mints rather than to whatever was typed.
var ErrWeakSigningSecret = errors.New("a signing secret must be at least 32 characters")

// CheckSigningSecret refuses a secret too short to sign with.
func CheckSigningSecret(secret string) error {
	if len(secret) < 32 {
		return fmt.Errorf("%w: it is all that tells the receiver this engine sent the call", ErrWeakSigningSecret)
	}
	return nil
}

// SetProviderSecret replaces a hook's provider's signing secret with one the
// operator holds. The old one stops verifying at once, as on a rotation.
func SetProviderSecret(ctx context.Context, tx pgx.Tx, root *keys.RootKey, orgID string,
	hook provider.Hook, secret string) error {
	if err := CheckSigningSecret(secret); err != nil {
		return err
	}
	if root == nil {
		return fmt.Errorf("a provider's signing secret is sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	sealed, err := root.Seal([]byte(secret), SealContextProviderSecret)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.providers SET token_wrapped = $3, wrap_key_ref = $4, updated_at = now()
		 WHERE org_id = $1::uuid AND hook = $2`, orgID, string(hook), sealed, root.Ref())
	if err != nil {
		return fmt.Errorf("setting the %s provider's secret: %w", hook, err)
	}
	if tag.RowsAffected() == 0 {
		return providerNotRegistered{hook}
	}
	return nil
}

// ProviderSecret is the signing secret a hook's provider holds, "" for one
// registered before there were secrets, so a plan can say whether the one a
// file names differs. Never shown.
func ProviderSecret(ctx context.Context, q providerReader, root *keys.RootKey, orgID string,
	hook provider.Hook) (string, error) {
	var sealed []byte
	if err := q.QueryRow(ctx, `SELECT token_wrapped FROM core.providers WHERE org_id = $1::uuid AND hook = $2`,
		orgID, string(hook)).Scan(&sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", providerNotRegistered{hook}
		}
		return "", err
	}
	if sealed == nil {
		return "", nil
	}
	if root == nil {
		return "", fmt.Errorf("the %s provider's signing secret is sealed and no root key is loaded", hook)
	}
	secret, err := root.Open(sealed, SealContextProviderSecret)
	if err != nil {
		return "", fmt.Errorf("the %s provider's signing secret does not open: %w", hook, err)
	}
	return string(secret), nil
}

// sealContextSubscriptionSecret binds a sealed subscription secret to its
// column, as CreateSubscription and the delivery worker name it.
const sealContextSubscriptionSecret = "event-subscription"

// SetSubscriptionSecret replaces a subscription's signing secret with one the
// operator holds. Deliveries signed from now on use it, retries included.
func SetSubscriptionSecret(ctx context.Context, tx pgx.Tx, root *keys.RootKey, orgID, name, secret string) error {
	if err := CheckSigningSecret(secret); err != nil {
		return err
	}
	if root == nil {
		return fmt.Errorf("a subscription's signing secret is sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	sealed, err := root.Seal([]byte(secret), sealContextSubscriptionSecret)
	if err != nil {
		return fmt.Errorf("sealing the signing secret: %w", err)
	}
	tag, err := tx.Exec(ctx, `UPDATE core.event_subscriptions SET secret_sealed = $3
		WHERE org_id = $1::uuid AND display_name = $2`, orgID, name, sealed)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return subscriptionNamed{name}
	}
	return nil
}

// SubscriptionSecret is the signing secret a subscription holds, so a plan can
// say whether the one a file names differs. Never shown.
func SubscriptionSecret(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, root *keys.RootKey, orgID, name string) (string, error) {
	var sealed []byte
	if err := q.QueryRow(ctx, `SELECT secret_sealed FROM core.event_subscriptions
		WHERE org_id = $1::uuid AND display_name = $2`, orgID, name).Scan(&sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", subscriptionNamed{name}
		}
		return "", err
	}
	if root == nil {
		return "", fmt.Errorf("subscription %q's signing secret is sealed and no root key is loaded", name)
	}
	secret, err := root.Open(sealed, sealContextSubscriptionSecret)
	if err != nil {
		return "", fmt.Errorf("subscription %q's signing secret does not open: %w", name, err)
	}
	return string(secret), nil
}

// UpdateSubscription points a subscription at another URL, or changes the
// events it is sent, checked as CreateSubscription checks them. Deliveries
// already queued keep the URL they were queued for.
func UpdateSubscription(ctx context.Context, tx pgx.Tx, orgID, name, url string, eventTypes []string) error {
	if err := safedial.CheckURL(url); err != nil {
		return err
	}
	if err := CheckEventTypes(eventTypes); err != nil {
		return err
	}
	if eventTypes == nil {
		eventTypes = []string{}
	}
	tag, err := tx.Exec(ctx, `UPDATE core.event_subscriptions SET url = $3, event_types = $4
		WHERE org_id = $1::uuid AND display_name = $2`, orgID, name, url, eventTypes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return subscriptionNamed{name}
	}
	return nil
}
