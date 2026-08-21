package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/federation"
)

// ErrNoTrustedIssuer means no provider is trusted to issue assertions under that
// issuer identifier.
var ErrNoTrustedIssuer = errors.New("no provider is trusted for that issuer")

// ErrAmbiguousIssuer means two providers claim the same issuer.
var ErrAmbiguousIssuer = errors.New("more than one provider claims that issuer")

// ErrNoLinkedAccount means the assertion's subject is not linked to a usable
// local account.
var ErrNoLinkedAccount = errors.New("no active local account is linked to that subject")

// ErrAssertionReplayed means this assertion identifier has been spent already.
//
// A distinct error because the caller MUST be able to tell it from a database
// failure. Both used to arrive as "an error from ClaimAssertionJTI", and the
// grant reported every one of them to the client as "already used" and logged it
// as a replay -- so a missing GRANT on this table (which is exactly what
// happened) presented as an attack in progress rather than as an outage. That is
// a bad way to spend an incident.
var ErrAssertionReplayed = errors.New("assertion identifier has already been used")

// LoadJWTBearerProvider finds the provider trusted to sign assertions for an
// issuer.
//
// # The filter is in the SQL on purpose
//
// `enabled` and `allow_jwt_bearer` are conditions of the query rather than
// checks performed on the result. That is not a style preference. The most
// identity software has shipped a high-severity bug in this grant because its
// issuer lookup "omits filtering logic to exclude disabled IdPs from the lookup
// results" -- an administrator disabled a provider to revoke trust, and the grant
// kept working. LoadIdentityProvider, in this same package, has exactly that
// shape: it selects the row and then tests `enabled` in Go afterwards, which
// works and is one deleted line away from not working.
//
// Written as a WHERE clause, the row simply does not exist to be used.
//
// # Why this cannot be a lookup by the issuer column
//
// For a named kind -- google, microsoft, apple -- the `issuer` column is empty and
// the real issuer comes from the preset. A query matching on the column alone
// would silently fail to recognise every such provider, which reads as "trust not
// configured" and is impossible to debug from the outside. So the candidates are
// loaded and their EFFECTIVE issuers compared.
//
// The candidate set is small by construction: allow_jwt_bearer defaults to false,
// so it holds only providers somebody deliberately opted in.
//
// # Scoped to the client's organisation, and this was found the hard way
//
// The first version searched every provider in the deployment. That is wrong in
// the most ordinary multi-tenant configuration there is: two organisations both
// registering Google, or Entra, or the same CI platform -- which is not an edge
// case, it is what happens the second time anybody uses this feature. Both rows
// carry the same issuer, so the ambiguity check below fired and the grant broke
// for BOTH tenants, each having done nothing wrong.
//
// It was also a boundary the rest of this engine does not have: a client in one
// organisation could reach a provider row belonging to another. Scoping the query
// makes the tenant boundary part of the lookup rather than something checked
// afterwards, and leaves the ambiguity error for what it should mean -- one
// organisation registering the same issuer twice.
func LoadJWTBearerProvider(ctx context.Context, db *pgxpool.Pool, orgID, issuer string) (*federation.Config, error) {
	if issuer == "" || orgID == "" {
		return nil, ErrNoTrustedIssuer
	}
	rows, err := db.Query(ctx, `
		SELECT id::text, org_id::text, slug, display_name, kind,
		       client_id, COALESCE(issuer,''), COALESCE(jwks_url,'')
		FROM core.identity_providers
		WHERE org_id = $1::uuid AND enabled AND allow_jwt_bearer`, orgID)
	if err != nil {
		return nil, fmt.Errorf("loading trusted assertion issuers: %w", err)
	}
	defer rows.Close()

	var found *federation.Config
	for rows.Next() {
		var c federation.Config
		var kind string
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Slug, &c.DisplayName, &kind,
			&c.ClientID, &c.IssuerOverride, &c.JWKSOverride); err != nil {
			return nil, err
		}
		c.Kind = federation.Kind(kind)
		preset, err := federation.PresetFor(c.Kind)
		if err != nil {
			return nil, err
		}
		c.Preset = preset
		if c.Issuer() != issuer {
			continue
		}
		if found != nil {
			// Two providers answering to one issuer is a configuration error with
			// a security consequence: which one's JWKS verifies the assertion, and
			// therefore whose subjects are trusted, would depend on row order.
			// Refusing is the only answer that does not silently pick.
			return nil, ErrAmbiguousIssuer
		}
		cp := c
		found = &cp
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrNoTrustedIssuer
	}
	if found.JWKSURL() == "" {
		return nil, fmt.Errorf("provider %q is trusted for assertions but has no JWKS URL, "+
			"so nothing can verify them", found.Slug)
	}
	return found, nil
}

// FindActiveFederatedUser resolves an assertion's subject to a local account.
//
// # Two rules, both learned from somebody else's CVE
//
// The lookup is by (provider_id, subject) and never by subject alone. The unique
// constraint on those two columns is what makes an external subject meaningful:
// two issuers are two namespaces, and matching on `sub` across them would let any
// trusted issuer mint an assertion naming another issuer's subject. That is the
// same subject-confusion shape found in the Shared Signals receiver earlier in
// this codebase, and it is structural here rather than remembered.
//
// The join requires `users.status = 'active'`. a published advisory is precisely its
// absence: the grant "fails to validate the user's disabled status", so an
// assertion could still obtain tokens for an account an administrator had
// disabled. Deactivating a user has to mean it everywhere, and this is one of the
// everywheres.
func FindActiveFederatedUser(ctx context.Context, db *pgxpool.Pool, providerID, subject string) (userID, orgID string, err error) {
	if providerID == "" || subject == "" {
		return "", "", ErrNoLinkedAccount
	}
	err = db.QueryRow(ctx, `
		SELECT u.id::text, u.org_id::text
		FROM core.federated_identities f
		JOIN core.users u ON u.id = f.user_id
		WHERE f.provider_id = $1::uuid
		  AND f.subject = $2
		  AND u.status = 'active'`, providerID, subject).Scan(&userID, &orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// One error for "never linked" and for "linked but disabled". The
			// difference is exactly the account-existence oracle this engine
			// refuses to provide elsewhere, and the caller logs the real reason.
			return "", "", ErrNoLinkedAccount
		}
		return "", "", fmt.Errorf("resolving the assertion subject: %w", err)
	}
	return userID, orgID, nil
}

// ClaimAssertionJTI records an assertion identifier and refuses a repeat.
//
// RFC 7523 §6 says replay protection is optional -- "It is an optional feature,
// which implementations may employ at their own discretion". We employ it,
// because without it an assertion is a password for as long as its `exp`: any
// place it is logged, proxied or mis-delivered yields a credential that still
// works.
//
// The INSERT is the check. Asking "have I seen this?" and then recording it is
// two statements, and two concurrent replays both read "no" before either writes
// -- which is the exact race a replay attacker is trying to win. A primary key
// violation cannot be raced.
//
// Assertions with no `jti` are accepted, because §3 item 7 makes it a MAY and
// refusing them would reject conformant issuers. That is a real limit and it is
// stated rather than hidden: an issuer that omits `jti` gets no replay protection
// from us, and the operator can see which those are.
func ClaimAssertionJTI(ctx context.Context, tx pgx.Tx, providerID, jti string, expiresAt int64) error {
	if jti == "" {
		return nil
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.jwt_bearer_replay (provider_id, jti, expires_at)
		VALUES ($1::uuid, $2, to_timestamp($3))
		ON CONFLICT (provider_id, jti) DO NOTHING`, providerID, jti, expiresAt)
	if err != nil {
		return fmt.Errorf("recording the assertion identifier: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAssertionReplayed
	}
	return nil
}

// SweepUsedAssertions deletes replay records past the assertion's own expiry.
//
// Keeping them longer protects nothing: an assertion past its `exp` is refused
// for being expired before this table is ever consulted.
func SweepUsedAssertions(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.jwt_bearer_replay WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
