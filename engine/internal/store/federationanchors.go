package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
)

// Whose word this deployment takes for a relying party it has never met (OpenID
// Federation §12.1). The list is an operator's and an empty one means nobody: a
// federation is somebody else's opinion, and being in one should not be enough to
// start signing a deployment's people in to strangers.

// FederationAnchor is a Trust Anchor an operator accepts.
type FederationAnchor struct {
	EntityID string
	// OrgID is where the relying parties it vouches for are registered.
	OrgID string
	// JWKS are its Federation Entity Keys, as an operator was given them.
	JWKS json.RawMessage
	// TrustMarks are the Trust Mark types a relying party must hold besides.
	TrustMarks []string
}

// ErrFederationAnchorUnknown is an anchor that is not on the list.
var ErrFederationAnchorUnknown = errors.New("that entity is not a trust anchor here")

// Validate refuses an anchor nothing could verify a chain against.
func (a FederationAnchor) Validate() error {
	if !strings.HasPrefix(a.EntityID, "https://") {
		return errors.New("a trust anchor's entity identifier is an https URL")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(a.JWKS, &set); err != nil {
		return fmt.Errorf("the trust anchor's keys are not a JWKS document: %w", err)
	}
	if len(set.Keys) == 0 {
		return errors.New("the trust anchor's key set holds no keys")
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || !k.Valid() {
			return errors.New("the trust anchor's key set holds a key that is not a usable public key")
		}
	}
	return nil
}

// SetFederationAnchor adds an anchor to the list, or replaces what it says.
func SetFederationAnchor(ctx context.Context, q Execer, instanceID string, a FederationAnchor) error {
	marks := a.TrustMarks
	if marks == nil {
		marks = []string{}
	}
	_, err := q.Exec(ctx, `
		INSERT INTO core.federation_trust_anchors (instance_id, entity_id, org_id, jwks, required_trust_marks)
		VALUES ($1::uuid, $2, $3::uuid, $4::jsonb, $5)
		ON CONFLICT (instance_id, entity_id) DO UPDATE
		   SET org_id = EXCLUDED.org_id, jwks = EXCLUDED.jwks, required_trust_marks = EXCLUDED.required_trust_marks`,
		instanceID, a.EntityID, a.OrgID, string(a.JWKS), marks)
	return err
}

// RemoveFederationAnchor takes an anchor off the list, and deletes the clients it
// admitted. They had no other standing: nobody here ever chose them, and leaving them
// would have a deployment trusting on the word of a party it has stopped trusting.
// Deleting one that a later request can still vouch for costs it a sign-in. It answers
// how many went.
func RemoveFederationAnchor(ctx context.Context, tx pgx.Tx, instanceID, entityID string) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.federation_trust_anchors
		WHERE instance_id = $1::uuid AND entity_id = $2`, instanceID, entityID)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, ErrFederationAnchorUnknown
	}
	gone, err := tx.Exec(ctx, `DELETE FROM core.clients c USING core.organizations o
		WHERE o.id = c.org_id AND o.instance_id = $1::uuid AND c.federation_anchor = $2`, instanceID, entityID)
	if err != nil {
		return 0, err
	}
	return gone.RowsAffected(), nil
}

// FederationAnchors reads the list.
func FederationAnchors(ctx context.Context, q Querier, instanceID string) ([]FederationAnchor, error) {
	rows, err := q.Query(ctx, `SELECT entity_id, org_id::text, jwks::text, required_trust_marks
		FROM core.federation_trust_anchors WHERE instance_id = $1::uuid ORDER BY entity_id`, instanceID)
	if err != nil {
		return nil, fmt.Errorf("reading the trust anchors: %w", err)
	}
	defer rows.Close()
	out := []FederationAnchor{}
	for rows.Next() {
		var a FederationAnchor
		var jwks string
		if err := rows.Scan(&a.EntityID, &a.OrgID, &jwks, &a.TrustMarks); err != nil {
			return nil, err
		}
		a.JWKS = json.RawMessage(jwks)
		out = append(out, a)
	}
	return out, rows.Err()
}

// FederatedClient is a relying party a chain vouched for.
type FederatedClient struct {
	ClientID, OrgID, Name, Anchor string
	RedirectURIs, Scopes          []string
	JWKS                          []byte
	// Expiry is when what the chain said stops holding, and it is looked at again.
	Expiry time.Time
}

// RegisterFederatedClient writes one, or brings one it wrote before up to date. It
// authenticates with its keys and has no secret, as §12.1 says, and every request has
// to be signed, as that is the proof it is who it says. A client somebody here made is
// never touched, whatever a chain says about its name.
func RegisterFederatedClient(ctx context.Context, tx pgx.Tx, c FederatedClient) error {
	for _, uri := range c.RedirectURIs {
		if err := clients.ValidateRedirectURI(uri); err != nil {
			return fmt.Errorf("redirect_uri %q: %w", uri, err)
		}
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, scopes, token_endpoint_auth_method,
			jwks, require_signed_request_object, federation_anchor, federation_expires_at)
		VALUES ($1, $2::uuid, $3, 'confidential', $4, 'private_key_jwt', $5::jsonb, true, $6, $7)
		ON CONFLICT (client_id) DO UPDATE
		   SET display_name = EXCLUDED.display_name, scopes = EXCLUDED.scopes, jwks = EXCLUDED.jwks,
		       federation_anchor = EXCLUDED.federation_anchor, federation_expires_at = EXCLUDED.federation_expires_at,
		       updated_at = now()
		 WHERE core.clients.federation_anchor IS NOT NULL`,
		c.ClientID, c.OrgID, c.Name, c.Scopes, string(c.JWKS), c.Anchor, c.Expiry)
	if err != nil {
		return fmt.Errorf("registering a federated client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%q is a client already, and not one a chain made", c.ClientID)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.client_redirect_uris WHERE client_id = $1`, c.ClientID); err != nil {
		return err
	}
	for _, uri := range c.RedirectURIs {
		if _, err := tx.Exec(ctx, `INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`,
			c.ClientID, uri); err != nil {
			return err
		}
	}
	return nil
}

// ErrRequestObjectReplayed is a Request Object sent a second time.
var ErrRequestObjectReplayed = errors.New("that request object has been used")

// ClaimRequestObjectJTI spends a Request Object's `jti`. The INSERT is the check, for
// the reason ClaimAssertionJTI gives.
func ClaimRequestObjectJTI(ctx context.Context, q Execer, clientID, jti string, expiresAt time.Time) error {
	tag, err := q.Exec(ctx, `INSERT INTO core.request_object_replay (client_id, jti, expires_at)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, clientID, jti, expiresAt)
	if err != nil {
		return fmt.Errorf("recording a request object: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRequestObjectReplayed
	}
	return nil
}

// SweepRequestObjectReplay drops records past the object's own expiry, by which it is
// refused for that anyway.
func SweepRequestObjectReplay(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.request_object_replay WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.request_object_replay WHERE expires_at < now()
		LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
