package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
)

// Client ID Metadata Documents (internal/cimd): whose URLs an operator will fetch, and the
// clients that came of it.

// ErrClientMetadataRuleUnknown is a rule that is not on the list.
var ErrClientMetadataRuleUnknown = errors.New("no such client metadata rule")

// ClientMetadataRule says that a client_id under URLPrefix may sign people in here,
// landing in OrgID and given no more than Scopes.
type ClientMetadataRule struct {
	URLPrefix, OrgID string
	Scopes           []string
}

// Validate refuses a prefix that would not say what it looks like. It has to name a host
// and end in a slash, or https://good.example would also match
// https://good.example.evil.test/ and an operator's list would cover somebody else.
func (r ClientMetadataRule) Validate() error {
	if r.OrgID == "" {
		return errors.New("a rule names the organisation its clients land in")
	}
	u, err := url.Parse(r.URLPrefix)
	if err != nil {
		return fmt.Errorf("the prefix is not a URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasSuffix(r.URLPrefix, "/") {
		return errors.New("the prefix is an https URL with a host and a path ending in /, and nothing else")
	}
	for _, scope := range r.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return fmt.Errorf("%q is not a scope", scope)
		}
	}
	return nil
}

// ClientMetadataRules is an instance's list, longest prefix first, so that the first to
// match is the most particular.
func ClientMetadataRules(ctx context.Context, q Querier, instanceID string) ([]ClientMetadataRule, error) {
	rows, err := q.Query(ctx, `SELECT url_prefix, org_id::text, scopes FROM core.client_metadata_rules
		WHERE instance_id = $1::uuid ORDER BY length(url_prefix) DESC, url_prefix`, instanceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ClientMetadataRule, error) {
		var r ClientMetadataRule
		return r, row.Scan(&r.URLPrefix, &r.OrgID, &r.Scopes)
	})
}

// MatchClientMetadataRule is the rule that covers a client_id, by the list's order.
func MatchClientMetadataRule(rules []ClientMetadataRule, clientID string) (ClientMetadataRule, bool) {
	for _, r := range rules {
		if strings.HasPrefix(clientID, r.URLPrefix) {
			return r, true
		}
	}
	return ClientMetadataRule{}, false
}

// SetClientMetadataRule adds a rule, or replaces what it says.
func SetClientMetadataRule(ctx context.Context, q Execer, instanceID string, r ClientMetadataRule) error {
	if err := r.Validate(); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		INSERT INTO core.client_metadata_rules (instance_id, url_prefix, org_id, scopes)
		VALUES ($1::uuid, $2, $3::uuid, $4)
		ON CONFLICT (instance_id, url_prefix) DO UPDATE SET org_id = EXCLUDED.org_id, scopes = EXCLUDED.scopes`,
		instanceID, r.URLPrefix, r.OrgID, nonNil(r.Scopes))
	return err
}

// RemoveClientMetadataRule takes a rule off the list and deletes the clients it admitted,
// who had no other standing, and answers how many went.
func RemoveClientMetadataRule(ctx context.Context, tx pgx.Tx, instanceID, prefix string) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.client_metadata_rules
		WHERE instance_id = $1::uuid AND url_prefix = $2`, instanceID, prefix)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, ErrClientMetadataRuleUnknown
	}
	gone, err := tx.Exec(ctx, `DELETE FROM core.clients c USING core.organizations o
		WHERE o.id = c.org_id AND o.instance_id = $1::uuid AND c.client_metadata_prefix = $2`, instanceID, prefix)
	if err != nil {
		return 0, err
	}
	return gone.RowsAffected(), nil
}

// MetadataClient is a client as its document describes it, past everything that document
// was held to.
type MetadataClient struct {
	ClientID, OrgID, Name, Prefix string
	// Public is a client with no keys; otherwise it authenticates with private_key_jwt.
	Public             bool
	RedirectURIs       []string
	Scopes, GrantTypes []string
	JWKS               []byte
	Expiry             time.Time
}

// RegisterMetadataClient writes one, or brings up to date one it wrote before, which is
// also how a client's change of redirect URL reaches here. A client somebody made here is
// never touched, whatever a document at that URL says (§7.2's pre-registration).
func RegisterMetadataClient(ctx context.Context, tx pgx.Tx, c MetadataClient) error {
	for _, uri := range c.RedirectURIs {
		if err := clients.ValidateRedirectURI(uri); err != nil {
			return fmt.Errorf("redirect_uri %q: %w", uri, err)
		}
	}
	kind, method := "confidential", "private_key_jwt"
	var jwks any
	if c.Public {
		kind, method = "public", "none"
	} else {
		jwks = string(c.JWKS)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, scopes, grant_types,
			token_endpoint_auth_method, jwks, client_metadata_prefix, federation_expires_at)
		VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
		ON CONFLICT (client_id) DO UPDATE
		   SET display_name = EXCLUDED.display_name, client_type = EXCLUDED.client_type, scopes = EXCLUDED.scopes,
		       grant_types = EXCLUDED.grant_types, token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
		       jwks = EXCLUDED.jwks, client_metadata_prefix = EXCLUDED.client_metadata_prefix,
		       federation_expires_at = EXCLUDED.federation_expires_at, updated_at = now()
		 WHERE core.clients.client_metadata_prefix IS NOT NULL AND core.clients.org_id = EXCLUDED.org_id`,
		c.ClientID, c.OrgID, c.Name, kind, c.Scopes, c.GrantTypes, method, jwks, c.Prefix, c.Expiry)
	if err != nil {
		return fmt.Errorf("registering a client from its document: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%q is a client already, and not one a document made", c.ClientID)
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
