package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/saml"
)

// Inbound SAML: the state that makes the two checks after the signature
// possible.
//
//	saml_source_requests     did THIS browser ask for this assertion
//	saml_source_assertions   has this assertion already been spent
//
// Both are single-use and both are enforced by the database rather than by a
// read followed by a write, because two tabs, a double-posted form and a
// retrying proxy all produce the concurrent case.

// SAMLSource is a configured upstream provider.
//
// ProviderID is a core.identity_providers row: a SAML source is an identity
// provider that happens to speak SAML, so the linking, the decision about
// unknown accounts, and the audit trail are the ones every other provider uses.
type SAMLSource struct {
	ProviderID  string
	OrgID       string
	Slug        string
	DisplayName string
	// Policy is the shared federation policy: allow signup, allow linking, and
	// the email-verification rules.
	Policy   federation.Policy
	Provider *saml.InboundProvider
}

// LoadSAMLSource reads one enabled source by slug.
//
// acsBase is the issuer, from which the ACS URL is derived rather than stored:
// a stored ACS URL is a second copy of the deployment's own address, and the
// copies drift.
func LoadSAMLSource(ctx context.Context, db *pgxpool.Pool, slug, acsBase string) (*SAMLSource, error) {
	s := &SAMLSource{Provider: &saml.InboundProvider{}}
	err := db.QueryRow(ctx, `
		SELECT p.id::text, p.org_id::text, p.slug, p.display_name,
		       p.allow_signup, p.allow_linking, p.require_verified_email,
		       p.trust_email_verification,
		       x.entity_id, x.sso_url, x.cert_pem, x.name_id_format,
		       x.force_authn, x.allow_unsolicited, x.skew_seconds
		FROM core.identity_providers p
		JOIN core.saml_sources x ON x.provider_id = p.id
		WHERE p.slug = $1 AND p.kind = 'saml' AND p.enabled`, slug).
		Scan(&s.ProviderID, &s.OrgID, &s.Slug, &s.DisplayName,
			&s.Policy.AllowSignup, &s.Policy.AllowLinking,
			&s.Policy.RequireVerifiedEmail, &s.Policy.TrustsEmailVerification,
			&s.Provider.EntityID, &s.Provider.SSOURL, &s.Provider.CertPEM,
			&s.Provider.NameIDFormat, &s.Provider.ForceAuthn,
			&s.Provider.AllowUnsolicited, &s.Provider.SkewSeconds)
	if err != nil {
		return nil, err
	}
	s.Provider.SPEntityID = acsBase
	s.Provider.ACSURL = acsBase + "/saml/source/" + slug + "/acs"
	return s, nil
}

// SAMLSourceRequest is an outstanding AuthnRequest.
type SAMLSourceRequest struct {
	ID         string
	ProviderID string
	RelayState string
	ReturnPath string
}

// RecordSAMLRequest remembers a request so its response can be matched to it.
func RecordSAMLRequest(ctx context.Context, db *pgxpool.Pool, providerID, id,
	relayState, returnPath string, ttl time.Duration) error {

	_, err := db.Exec(ctx, `
		INSERT INTO core.saml_source_requests
			(id, provider_id, relay_state, return_path, expires_at)
		VALUES ($1, $2::uuid, $3, $4, now() + $5::interval)`,
		id, providerID, relayState, returnPath, ttl.String())
	return err
}

// ConsumeSAMLRequest claims an outstanding request, exactly once.
//
// The UPDATE is the claim. Reading the row and then marking it used leaves a
// window in which two responses both find it unconsumed -- which is not
// hypothetical, because a browser that double-posts the SAML form produces it
// naturally, and an attacker replaying a captured response produces it on
// purpose.
func ConsumeSAMLRequest(ctx context.Context, db *pgxpool.Pool, relayState string) (
	*SAMLSourceRequest, error) {

	r := &SAMLSourceRequest{}
	err := db.QueryRow(ctx, `
		UPDATE core.saml_source_requests
		SET consumed_at = now()
		WHERE relay_state = $1 AND consumed_at IS NULL AND expires_at > now()
		RETURNING id, provider_id::text, relay_state, return_path`, relayState).
		Scan(&r.ID, &r.ProviderID, &r.RelayState, &r.ReturnPath)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no sign-in is in progress for this browser: the request " +
			"may have expired, already been completed, or been started in a different " +
			"browser")
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// RecordSAMLAssertion claims an assertion ID, exactly once.
//
// The primary key is the mechanism. A SELECT-then-INSERT would let two
// concurrent posts of the same captured assertion both find nothing and both
// proceed, which is precisely the replay this prevents.
func RecordSAMLAssertion(ctx context.Context, db *pgxpool.Pool, providerID,
	assertionID string, expires time.Time) error {

	tag, err := db.Exec(ctx, `
		INSERT INTO core.saml_source_assertions (provider_id, assertion_id, expires_at)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (provider_id, assertion_id) DO NOTHING`,
		providerID, assertionID, expires)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("this assertion has already been used. A valid assertion is " +
			"accepted once; a second presentation of the same one is a replay, whether " +
			"or not it was meant as an attack")
	}
	return nil
}

// PurgeSAMLSourceState removes expired requests and assertion records.
//
// Both tables are bounded by the assertion lifetime, so this is housekeeping
// rather than a security control -- but a table that only grows is how a
// deployment discovers its disk on a Sunday.
func PurgeSAMLSourceState(ctx context.Context, db *pgxpool.Pool) (int64, error) {
	var total int64
	tag, err := db.Exec(ctx,
		`DELETE FROM core.saml_source_requests WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	total += tag.RowsAffected()

	tag, err = db.Exec(ctx,
		`DELETE FROM core.saml_source_assertions WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return total, err
	}
	return total + tag.RowsAffected(), nil
}
