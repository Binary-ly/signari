package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// An upstream identity provider's settings as `signari idp` and the Admin API
// change them (6.07). A provider's slug is unique across the deployment,
// since /login/with/<slug> names no organisation.

// ErrIdPInvalid is a setting the rules refuse; its message says which.
var ErrIdPInvalid = errors.New("the identity provider setting is not one this engine can honour")

type idpInvalid struct{ msg string }

func (e idpInvalid) Error() string        { return e.msg }
func (e idpInvalid) Is(target error) bool { return target == ErrIdPInvalid }

// ErrIdPMappingUnknown is an attribute mapping removed that was never made.
var ErrIdPMappingUnknown = errors.New("the provider does not map that claim into that attribute")

// IdentityProviderOrg is the organisation and kind of the provider of that
// slug.
func IdentityProviderOrg(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, slug string) (orgID, kind string, err error) {
	err = q.QueryRow(ctx, `SELECT org_id::text, kind FROM core.identity_providers WHERE slug = $1`, slug).
		Scan(&orgID, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrProviderUnknown
	}
	return orgID, kind, err
}

// IdentityProviderChange is what the idp commands change, a nil field left
// as it is.
type IdentityProviderChange struct {
	// Enabled out of service closes every way in through the provider from
	// the next request: sign-in, linking, its SAML and jwt-bearer
	// assertions. Its settings and links are kept.
	Enabled *bool
	// AllowAssertions is the RFC 7523 jwt-bearer grant: any JWT the provider
	// signs, presented by a registered client with nobody present, mints
	// tokens for the linked account. Off until somebody turns it on.
	AllowAssertions *bool
	// TrustEmailVerification believes the provider's email_verified claim, so
	// an address it reports as verified is recorded as verified here. Only a
	// generic OIDC provider's and a SAML upstream's is read: a named
	// provider's comes from its preset, which says how that provider
	// actually behaves.
	TrustEmailVerification *bool
	// RequireVerifiedEmail refuses a new account through the provider unless
	// its address is one the provider verified and is believed about.
	RequireVerifiedEmail *bool
	// MFAAMR and MFAACR are the upstream amr and acr values that count as
	// multi-factor; empty trusts none.
	MFAAMR, MFAACR *[]string
}

// Empty reports whether the change names nothing.
func (c IdentityProviderChange) Empty() bool {
	return c.Enabled == nil && c.AllowAssertions == nil && c.TrustEmailVerification == nil &&
		c.RequireVerifiedEmail == nil && c.MFAAMR == nil && c.MFAACR == nil
}

// ChangeIdentityProvider applies a change to the organisation's provider of
// that slug. A setting is refused on a kind that never reads it, since it
// would be a setting nothing enforces: multi-factor values where no ID token
// arrives for them to be read from (GitHub's, a SAML upstream's), belief in
// email_verified where the preset decides it, and either email setting on an
// assertion issuer, which signs nobody in.
func ChangeIdentityProvider(ctx context.Context, q outpostDB, orgID, slug string, c IdentityProviderChange) error {
	var kind string
	if err := q.QueryRow(ctx, `SELECT kind FROM core.identity_providers WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProviderUnknown
		}
		return err
	}
	var amr, acr any
	if c.MFAAMR != nil {
		amr = nonNil(*c.MFAAMR)
	}
	if c.MFAACR != nil {
		acr = nonNil(*c.MFAACR)
	}
	if (kind == "github" || kind == "saml") && ((c.MFAAMR != nil && len(*c.MFAAMR) > 0) ||
		(c.MFAACR != nil && len(*c.MFAACR) > 0)) {
		return idpInvalid{fmt.Sprintf("%s is a %s provider, which sends no ID token for an amr or acr to be read from",
			slug, kind)}
	}
	if kind == "assertion" && (c.TrustEmailVerification != nil || c.RequireVerifiedEmail != nil) {
		return idpInvalid{fmt.Sprintf("%s is an assertion issuer, which signs nobody in, so no address of its is "+
			"recorded or required", slug)}
	}
	if c.TrustEmailVerification != nil && kind != "oidc" && kind != "saml" {
		return idpInvalid{fmt.Sprintf("%s is a %s provider, whose email_verified is believed or not as that "+
			"provider is known to behave; only a generic OIDC provider's or a SAML upstream's is set here", slug, kind)}
	}
	_, err := q.Exec(ctx, `
		UPDATE core.identity_providers
		   SET enabled                  = COALESCE($3::boolean, enabled),
		       allow_jwt_bearer         = COALESCE($4::boolean, allow_jwt_bearer),
		       trust_email_verification = COALESCE($5::boolean, trust_email_verification),
		       require_verified_email   = COALESCE($6::boolean, require_verified_email),
		       mfa_amr                  = COALESCE($7::text[], mfa_amr),
		       mfa_acr                  = COALESCE($8::text[], mfa_acr),
		       updated_at               = now()
		 WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, c.Enabled, c.AllowAssertions, c.TrustEmailVerification,
		c.RequireVerifiedEmail, amr, acr)
	return err
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// SetIdPAttributeMap routes a claim from the provider into a declared local
// attribute, by the attribute's id, so dropping the attribute takes the
// mapping with it. overwrite makes the provider the system of record for the
// attribute; maxLength bounds what is stored.
func SetIdPAttributeMap(ctx context.Context, q outpostDB, orgID, slug, claim, attribute string, overwrite bool,
	maxLength int) error {
	providerID, attributeID, err := mappingIDs(ctx, q, orgID, slug, attribute)
	if err != nil {
		return err
	}
	if maxLength <= 0 {
		maxLength = 256
	}
	_, err = q.Exec(ctx, `
		INSERT INTO core.idp_attribute_map
		    (provider_id, org_id, upstream_claim, attribute_id, overwrite, max_length)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6)
		ON CONFLICT (provider_id, upstream_claim, attribute_id) DO UPDATE
		   SET overwrite = EXCLUDED.overwrite, max_length = EXCLUDED.max_length`,
		providerID, orgID, claim, attributeID, overwrite, maxLength)
	return err
}

// RemoveIdPAttributeMap stops a claim reaching an attribute.
func RemoveIdPAttributeMap(ctx context.Context, q outpostDB, orgID, slug, claim, attribute string) error {
	providerID, attributeID, err := mappingIDs(ctx, q, orgID, slug, attribute)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `DELETE FROM core.idp_attribute_map
		WHERE provider_id = $1::uuid AND upstream_claim = $2 AND attribute_id = $3::uuid`, providerID, claim, attributeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrIdPMappingUnknown
	}
	return nil
}

func mappingIDs(ctx context.Context, q outpostDB, orgID, slug, attribute string) (providerID, attributeID string, err error) {
	if err := q.QueryRow(ctx, `SELECT id::text FROM core.identity_providers WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&providerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrProviderUnknown
		}
		return "", "", err
	}
	if err := q.QueryRow(ctx, `SELECT id::text FROM core.user_attribute_schema WHERE org_id = $1::uuid AND name = $2`,
		orgID, attribute).Scan(&attributeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", idpInvalid{fmt.Sprintf("the organisation has no attribute named %q; declare it first, "+
				"since an attribute carries whether its values are sealed and a mapping cannot decide that for it",
				attribute)}
		}
		return "", "", err
	}
	return providerID, attributeID, nil
}

// IdentityProviderRow is one provider as an administrator sees it, without
// its client secret.
type IdentityProviderRow struct {
	ID, Slug, Name, Kind, Issuer                                  string
	Enabled, AllowSignup, AllowLinking                            bool
	AllowAssertions, TrustEmailVerification, RequireVerifiedEmail bool
	MFAAMR, MFAACR                                                []string
	Linked                                                        int
	AttributeMap                                                  []IdPAttributeMapping
}

// IdPAttributeMapping is one claim and the attribute it fills.
type IdPAttributeMapping struct {
	Claim, Attribute string
	Overwrite        bool
	MaxLength        int
}

// IdentityProviders lists an organisation's providers by slug.
func IdentityProviders(ctx context.Context, q Querier, orgID string) ([]IdentityProviderRow, error) {
	rows, err := q.Query(ctx, `
		SELECT p.id::text, p.slug, p.display_name, p.kind, COALESCE(p.issuer, ''), p.enabled, p.allow_signup,
		       p.allow_linking, p.allow_jwt_bearer, p.trust_email_verification, p.require_verified_email,
		       p.mfa_amr, p.mfa_acr, (SELECT count(*) FROM core.federated_identities f WHERE f.provider_id = p.id)
		  FROM core.identity_providers p WHERE p.org_id = $1::uuid ORDER BY p.slug`, orgID)
	if err != nil {
		return nil, err
	}
	var out []IdentityProviderRow
	for rows.Next() {
		var p IdentityProviderRow
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.Kind, &p.Issuer, &p.Enabled, &p.AllowSignup,
			&p.AllowLinking, &p.AllowAssertions, &p.TrustEmailVerification, &p.RequireVerifiedEmail, &p.MFAAMR,
			&p.MFAACR, &p.Linked); err != nil {
			rows.Close()
			return nil, err
		}
		p.AttributeMap = []IdPAttributeMapping{}
		out = append(out, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		maps, err := q.Query(ctx, `
			SELECT m.upstream_claim, a.name, m.overwrite, m.max_length
			  FROM core.idp_attribute_map m JOIN core.user_attribute_schema a ON a.id = m.attribute_id
			 WHERE m.provider_id = $1::uuid ORDER BY m.upstream_claim, a.name`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for maps.Next() {
			var m IdPAttributeMapping
			if err := maps.Scan(&m.Claim, &m.Attribute, &m.Overwrite, &m.MaxLength); err != nil {
				maps.Close()
				return nil, err
			}
			out[i].AttributeMap = append(out[i].AttributeMap, m)
		}
		maps.Close()
		if err := maps.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
