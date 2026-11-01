package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oid4vci"
)

// An offer kept to be fetched, and what a wallet says became of a credential (12.08).

// CredentialOfferPath is where a kept offer is fetched from, under the issuer.
const CredentialOfferPath = "/oid4vci/offer/"

const sealContextCredentialOffer = "credential_offer"

func newCredentialHandle() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PublishCredentialOffer keeps an offer's JSON for as long as its code lasts, and
// returns what fetches it. Sealed, because the code in it is good for a credential; only
// the handle's hash is kept, for the same reason, so a read of this table buys nothing.
func PublishCredentialOffer(ctx context.Context, e Execer, root *keys.RootKey, orgID string, offer []byte,
	ttl time.Duration) (string, error) {
	handle, err := newCredentialHandle()
	if err != nil {
		return "", err
	}
	sealed, err := root.Seal(offer, sealContextCredentialOffer)
	if err != nil {
		return "", err
	}
	if _, err := e.Exec(ctx, `
		INSERT INTO core.credential_offers (org_id, handle_hash, offer_sealed, expires_at)
		VALUES ($1::uuid, $2, $3, now() + make_interval(secs => $4))`,
		orgID, HashToken(handle), sealed, ttl.Seconds()); err != nil {
		return "", fmt.Errorf("keeping the offer: %w", err)
	}
	return handle, nil
}

// OfferByReference keeps an offer and returns the address to give a wallet (§4.1.3), which
// is on the deployment that serves it, whatever the offer names as its Credential Issuer.
func OfferByReference(ctx context.Context, q outpostDB, root *keys.RootKey, orgID string, offer []byte, ttl time.Duration) (string, error) {
	base, err := OrgIssuer(ctx, q, orgID)
	if err != nil {
		return "", err
	}
	handle, err := PublishCredentialOffer(ctx, q, root, orgID, offer, ttl)
	if err != nil {
		return "", err
	}
	return oid4vci.CredentialOfferURIScheme + "://?credential_offer_uri=" +
		url.QueryEscape(strings.TrimRight(base, "/")+CredentialOfferPath+handle), nil
}

// CredentialOfferByHandle is a kept offer's JSON, or nil for a handle that is unknown,
// expired or another instance's.
func CredentialOfferByHandle(ctx context.Context, q rowQuerier, root *keys.RootKey, handle, instanceID string) ([]byte, error) {
	var sealed []byte
	err := q.QueryRow(ctx, `
		SELECT offer_sealed FROM core.credential_offers
		 WHERE handle_hash = $1 AND expires_at > now() AND `+InInstance("org_id", "$2"),
		HashToken(handle), instanceID).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return root.Open(sealed, sealContextCredentialOffer)
}

// SweepExpiredCredentialOffers removes kept offers whose code is over.
func SweepExpiredCredentialOffers(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.credential_offers WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.credential_offers WHERE expires_at < now()
		LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ErrNotificationUnknown is a notification_id this token was not given.
var ErrNotificationUnknown = errors.New("that notification id is not one this token was given")

// NewCredentialNotification records an issuance and returns the id for the wallet to
// report on it with, which only the token that asked may use.
func NewCredentialNotification(ctx context.Context, e Execer, orgID, userID, jti, configuration string) (string, error) {
	id, err := newCredentialHandle()
	if err != nil {
		return "", err
	}
	if _, err := e.Exec(ctx, `
		INSERT INTO core.credential_notifications (notification_id, org_id, user_id, token_jti, configuration)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5)`, id, orgID, userID, jti, configuration); err != nil {
		return "", fmt.Errorf("recording an issuance: %w", err)
	}
	return id, nil
}

// CredentialNotified is the configuration a notification id is about, for the token it
// was given to. What the wallet said is for the audit trail, every word of it, since a
// credential stored can later be deleted, and the same word twice is the same answer
// (§11: "it returns success").
func CredentialNotified(ctx context.Context, q rowQuerier, id, jti string) (string, error) {
	var configuration string
	err := q.QueryRow(ctx, `
		SELECT configuration FROM core.credential_notifications
		 WHERE notification_id = $1 AND token_jti = $2`, id, jti).Scan(&configuration)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotificationUnknown
	}
	return configuration, err
}

// SweepCredentialNotifications removes records no token can report on any more.
func SweepCredentialNotifications(ctx context.Context, tx pgx.Tx, tokenTTL time.Duration, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.credential_notifications WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.credential_notifications WHERE created_at < now() - $1::interval
		LIMIT $2 FOR UPDATE SKIP LOCKED))`, tokenTTL.String(), limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
