// Package clients is the OAuth client registry.
package clients

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound means no such client_id.
var ErrNotFound = errors.New("client not found")

// Client is the registry view of a relying party.
//
// Note what is NOT here: any notion of a cached snapshot. Per ADR-007, whether a
// client is enabled is a security-negative decision and is read from the database
// on the request path. A disabled client must stop working on the very next
// request, not at the next config refresh.
type Client struct {
	ClientID      string
	OrgID         string
	DisplayName   string
	Type          string // "confidential" | "public"
	SecretHash    string
	Enabled       bool
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	RequirePKCE   bool
	// FirstParty clients skip the consent screen -- see migration 0010. It
	// suppresses only that question; every other check still applies.
	FirstParty bool
	PKCEMethods   []string
	IDTokenAlg    string
	RedirectURIs  []string
	RefreshTTL    int
}

// RefreshTokenTTLSeconds is the client's configured refresh lifetime, with a
// sane floor so a misconfigured zero does not mint tokens that expire instantly.
func (c *Client) RefreshTokenTTLSeconds() int {
	if c.RefreshTTL <= 0 {
		return 30 * 24 * 3600
	}
	return c.RefreshTTL
}

// Store reads clients. It takes the querier rather than a pool so callers can
// pass a transaction and get a consistent read alongside the rest of a request.
type Store struct{ q pgx.Tx }

// Querier is the subset of pgx we need, satisfied by both *pgx.Conn and pgx.Tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Lookup fetches a client and its registered redirect URIs.
//
// The redirect URIs come back as a set for EXACT comparison. They are not
// patterns. There is no prefix matching, no wildcard, no trailing-slash
// tolerance, and no normalisation beyond what the client registered -- every one
// of those "conveniences" has produced a redirect-bypass CVE somewhere.
func Lookup(ctx context.Context, q Querier, clientID string) (*Client, error) {
	c := &Client{ClientID: clientID}
	var secret *string

	err := q.QueryRow(ctx, `
		SELECT org_id::text, display_name, client_type, client_secret_hash, enabled,
		       grant_types, response_types, scopes, require_pkce, pkce_methods,
		       id_token_signed_alg, refresh_token_ttl_s, first_party
		FROM core.clients
		WHERE client_id = $1`, clientID).
		Scan(&c.OrgID, &c.DisplayName, &c.Type, &secret, &c.Enabled,
			&c.GrantTypes, &c.ResponseTypes, &c.Scopes, &c.RequirePKCE, &c.PKCEMethods,
			&c.IDTokenAlg, &c.RefreshTTL, &c.FirstParty)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up client %q: %w", clientID, err)
	}
	if secret != nil {
		c.SecretHash = *secret
	}

	rows, err := q.Query(ctx,
		`SELECT redirect_uri FROM core.client_redirect_uris WHERE client_id = $1`, clientID)
	if err != nil {
		return nil, fmt.Errorf("loading redirect URIs for %q: %w", clientID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		c.RedirectURIs = append(c.RedirectURIs, u)
	}
	return c, rows.Err()
}

// HasRedirectURI reports whether the candidate is registered, by exact string
// equality.
//
// Deliberately not url.Parse-and-compare: two URLs that parse equal can differ
// as strings (percent-encoding case, default ports, an empty query marker), and
// a relying party echoes back the literal string it was configured with. Compare
// what was sent against what was registered, byte for byte.
func (c *Client) HasRedirectURI(candidate string) bool {
	for _, u := range c.RedirectURIs {
		if u == candidate {
			return true
		}
	}
	return false
}

// AllowsResponseType reports whether the client may use this response_type.
func (c *Client) AllowsResponseType(rt string) bool { return contains(c.ResponseTypes, rt) }

// AllowsGrantType reports whether the client may use this grant.
func (c *Client) AllowsGrantType(gt string) bool { return contains(c.GrantTypes, gt) }

// AllowsPKCEMethod reports whether the method is permitted for this client.
func (c *Client) AllowsPKCEMethod(m string) bool { return contains(c.PKCEMethods, m) }

// UnknownScopes returns any requested scope the client is not registered for.
func (c *Client) UnknownScopes(requested []string) []string {
	var bad []string
	for _, s := range requested {
		if !contains(c.Scopes, s) {
			bad = append(bad, s)
		}
	}
	return bad
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

var _ = Store{}
