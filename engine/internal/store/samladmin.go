package store

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/saml"
)

// SAML service providers as `signari saml` and the Admin API register and
// configure them (6.07).

var (
	// ErrSAMLInvalid is a provider or a setting the rules refuse; its message
	// says which.
	ErrSAMLInvalid = errors.New("the SAML service provider is not one this engine can serve")
	// ErrSAMLEntityTaken is an entity ID registered already, in any
	// organisation: an AuthnRequest names only its entity ID and the SSO
	// endpoint names no organisation, so two registrations would be answered
	// at random.
	ErrSAMLEntityTaken = errors.New("a service provider with that entity id is already registered in this deployment")
	// ErrSAMLReleaseUnknown is a release removed that was never made.
	ErrSAMLReleaseUnknown = errors.New("the service provider is released no such thing")
)

type samlInvalid struct{ msg string }

func (e samlInvalid) Error() string        { return e.msg }
func (e samlInvalid) Is(target error) bool { return target == ErrSAMLInvalid }

// SAMLProviderSpec is a service provider to register. Its certificates are
// PEM: the one it signs requests with, and the one assertions are encrypted
// to, which is a different key.
type SAMLProviderSpec struct {
	EntityID, Name     string
	ACSURL             string
	NameIDFormat       string
	SLOURL, SLOBinding string
	SigningCertPEM     string
	EncryptionCertPEM  string
	KeyTransport       string
	WantSignedRequests bool
}

// Validate refuses a provider before anything is written. The ACS URL is
// checked as a redirect_uri is, because it is where a signed assertion for a
// real user is delivered: a mistake surfaces at registration, not during
// somebody else's integration.
func (s *SAMLProviderSpec) Validate() error {
	switch {
	case s.EntityID == "":
		return samlInvalid{"give the service provider's entity id"}
	case s.ACSURL == "":
		return samlInvalid{"give the AssertionConsumerService URL assertions are POSTed to"}
	case !strings.HasPrefix(s.ACSURL, "https://"):
		return samlInvalid{fmt.Sprintf("the ACS URL must be https: %q would carry a signed assertion for a "+
			"real user across the network in the clear", s.ACSURL)}
	case strings.Contains(s.ACSURL, "*"):
		return samlInvalid{fmt.Sprintf("%q contains a wildcard. ACS URLs are matched exactly, because anything "+
			"looser lets a request steer where the assertion is delivered", s.ACSURL)}
	}
	if s.Name == "" {
		s.Name = s.EntityID
	}
	switch s.KeyTransport {
	case "", saml.KeyTransportMGF1P:
		s.KeyTransport = saml.KeyTransportMGF1P
	case saml.KeyTransportSHA256:
		// Not the default: every provider implements mgf1p, and choosing
		// rsa-oaep-sha256 for one that cannot read it produces assertions
		// that decrypt nowhere.
		if s.EncryptionCertPEM == "" {
			return samlInvalid{"a key transport only affects encrypted assertions, and no encryption " +
				"certificate was given, so nothing would be encrypted"}
		}
	default:
		return samlInvalid{fmt.Sprintf("unknown key transport %q: use rsa-oaep-mgf1p or rsa-oaep-sha256",
			s.KeyTransport)}
	}
	switch s.NameIDFormat {
	case "", "persistent":
		s.NameIDFormat = "persistent"
	case "emailAddress", "transient":
	default:
		return samlInvalid{fmt.Sprintf("unknown NameID format %q: use persistent, emailAddress or transient",
			s.NameIDFormat)}
	}
	if s.SigningCertPEM != "" {
		if _, err := certificateIn(s.SigningCertPEM); err != nil {
			return samlInvalid{"the signing certificate: " + err.Error()}
		}
	}
	// Single logout needs a certificate to verify with: a LogoutRequest is
	// acted on only when signed, and a provider set up with a logout URL and
	// none looks configured and refuses every logout.
	if s.SLOURL != "" && s.SigningCertPEM == "" {
		return samlInvalid{"a logout URL was given with no signing certificate, so every logout would be refused"}
	}
	if s.SLOURL != "" && !strings.HasPrefix(s.SLOURL, "https://") {
		return samlInvalid{fmt.Sprintf("the logout URL must be https: %q", s.SLOURL)}
	}
	if s.SLOBinding == "" {
		s.SLOBinding = "HTTP-Redirect"
	}
	if s.SLOBinding != "HTTP-Redirect" && s.SLOBinding != "HTTP-POST" {
		return samlInvalid{fmt.Sprintf("unknown logout binding %q: use HTTP-Redirect or HTTP-POST", s.SLOBinding)}
	}
	if s.EncryptionCertPEM != "" {
		cert, err := certificateIn(s.EncryptionCertPEM)
		if err != nil {
			return samlInvalid{"the encryption certificate: " + err.Error()}
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return samlInvalid{fmt.Sprintf("the encryption certificate holds a %T key; assertion encryption "+
				"here needs RSA", cert.PublicKey)}
		}
		if pub.N.BitLen() < 2048 {
			return samlInvalid{fmt.Sprintf("the encryption certificate is a %d-bit RSA key; 2048 is the minimum",
				pub.N.BitLen())}
		}
		// The same file for both is the mistake the separation exists to
		// prevent, and it is silent: assertions encrypt fine and the
		// provider cannot read one.
		if strings.TrimSpace(s.EncryptionCertPEM) == strings.TrimSpace(s.SigningCertPEM) {
			return samlInvalid{"the signing and encryption certificates are the same; service providers use " +
				"separate keys for the two"}
		}
	}
	// Signed AuthnRequests with nothing to verify them against would refuse
	// every sign-in.
	if s.WantSignedRequests && s.SigningCertPEM == "" {
		return samlInvalid{"signed requests are wanted and no signing certificate was given, so every " +
			"AuthnRequest would be refused"}
	}
	return nil
}

func certificateIn(p string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, fmt.Errorf("not PEM; export the provider's certificate, not its private key or metadata")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("did not parse as a certificate: %w", err)
	}
	return cert, nil
}

// AddSAMLProvider registers a service provider, its default ACS URL and any
// logout URL, in one transaction.
func AddSAMLProvider(ctx context.Context, tx pgx.Tx, orgID string, s SAMLProviderSpec) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.saml_providers (org_id, entity_id, display_name, name_id_format,
		                                 sp_signing_cert, want_authn_requests_signed,
		                                 sp_encryption_cert, sp_key_transport)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5,''), $6, NULLIF($7,''), $8)
		RETURNING id::text`, orgID, s.EntityID, s.Name, s.NameIDFormat, s.SigningCertPEM,
		s.WantSignedRequests, s.EncryptionCertPEM, s.KeyTransport).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return "", ErrSAMLEntityTaken
		}
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
		VALUES ($1::uuid, $2, 'HTTP-POST', true)`, id, s.ACSURL); err != nil {
		return "", err
	}
	if s.SLOURL != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO core.saml_slo_urls (provider_id, url, binding) VALUES ($1::uuid, $2, $3)`,
			id, s.SLOURL, s.SLOBinding); err != nil {
			return "", err
		}
	}
	return id, nil
}

// SAMLProviderByEntity finds a provider by entity id, which is unique across
// the deployment, and its organisation.
func SAMLProviderByEntity(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, entityID string) (id, orgID string, err error) {
	err = q.QueryRow(ctx, `SELECT id::text, org_id::text FROM core.saml_providers WHERE entity_id = $1`,
		entityID).Scan(&id, &orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrSAMLProviderUnknown
	}
	return id, orgID, err
}

func requireSAMLProvider(ctx context.Context, q outpostDB, orgID, providerID string) error {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.saml_providers
		WHERE id::text = $2 AND org_id = $1::uuid)`, orgID, providerID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrSAMLProviderUnknown
	}
	return nil
}

// SetSAMLAttributeRelease releases a local attribute under a SAML attribute
// name in every assertion to the provider. The attribute must be declared:
// one that is not would resolve to nothing on every assertion, a release that
// silently releases nothing.
func SetSAMLAttributeRelease(ctx context.Context, q outpostDB, orgID, providerID, samlName, attribute string) error {
	if samlName == "" || attribute == "" {
		return samlInvalid{"give the SAML attribute name and the local attribute it carries"}
	}
	if err := requireSAMLProvider(ctx, q, orgID, providerID); err != nil {
		return err
	}
	var declared bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2)`, orgID, attribute).Scan(&declared); err != nil {
		return err
	}
	if !declared {
		return samlInvalid{fmt.Sprintf("the organisation has no attribute named %q; declare it before releasing it",
			attribute)}
	}
	_, err := q.Exec(ctx, `UPDATE core.saml_providers SET attributes = attributes || jsonb_build_object($2::text, $3::text),
		updated_at = now() WHERE id = $1::uuid`, providerID, samlName, attribute)
	return err
}

// RemoveSAMLAttributeRelease stops releasing a SAML attribute.
func RemoveSAMLAttributeRelease(ctx context.Context, q outpostDB, orgID, providerID, samlName string) error {
	if err := requireSAMLProvider(ctx, q, orgID, providerID); err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `UPDATE core.saml_providers SET attributes = attributes - $2, updated_at = now()
		WHERE id = $1::uuid AND attributes ? $2`, providerID, samlName)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSAMLReleaseUnknown
	}
	return nil
}

// SAMLSigningChange is what `saml signing` changes; a nil flag, a zero
// lifetime and an empty algorithm leave theirs alone, since writing both
// flags every time turned Response signing off again when only the lifetime
// was changed.
type SAMLSigningChange struct {
	Assertions, Responses *bool
	LifetimeSeconds       int
	SignatureAlg          string
}

// SetSAMLSigning applies a signing change and answers what is now in force.
// Signing neither is refused: an unsigned assertion inside an unsigned
// response is a document anyone can write. An algorithm with no active key
// of its kind in the provider's instance is refused too, because every
// sign-in to that provider would then fail at signing.
func SetSAMLSigning(ctx context.Context, q outpostDB, orgID, providerID string, c SAMLSigningChange) (
	signAssertions, signResponses bool, alg string, err error) {
	keyAlg := map[string]string{saml.SignatureAlgRSASHA256: "RS256", saml.SignatureAlgECDSASHA256: "ES256"}[c.SignatureAlg]
	if c.SignatureAlg != "" && keyAlg == "" {
		return false, false, "", samlInvalid{fmt.Sprintf("the signature algorithm is rsa-sha256 or ecdsa-sha256, "+
			"not %q", c.SignatureAlg)}
	}
	if c.LifetimeSeconds != 0 && (c.LifetimeSeconds < 30 || c.LifetimeSeconds > 3600) {
		return false, false, "", samlInvalid{fmt.Sprintf("the assertion lifetime is 30 to 3600 seconds; %d is "+
			"outside that. Short because an assertion is a bearer credential, and long enough to survive "+
			"clock skew", c.LifetimeSeconds)}
	}
	if err := q.QueryRow(ctx, `SELECT sign_assertions, sign_responses FROM core.saml_providers
		WHERE id::text = $2 AND org_id = $1::uuid`, orgID, providerID).Scan(&signAssertions, &signResponses); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, "", ErrSAMLProviderUnknown
		}
		return false, false, "", err
	}
	var algArg any
	if keyAlg != "" {
		var active bool
		if err := q.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM core.signing_keys k
			                 JOIN core.organizations o ON o.instance_id = k.instance_id
			               WHERE o.id = $1::uuid AND k.algorithm = $2
			                 AND k.state = 'active' AND k.purpose = 'oidc')`, orgID, keyAlg).Scan(&active); err != nil {
			return false, false, "", err
		}
		if !active {
			return false, false, "", samlInvalid{fmt.Sprintf("%s signs with the instance's active %s key and "+
				"there is none, so every sign-in to this provider would fail; add one first: "+
				"`signari keys rotate -alg %s`", c.SignatureAlg, keyAlg, keyAlg)}
		}
		algArg = c.SignatureAlg
	}
	if c.Assertions != nil {
		signAssertions = *c.Assertions
	}
	if c.Responses != nil {
		signResponses = *c.Responses
	}
	if !signAssertions && !signResponses {
		return false, false, "", samlInvalid{"assertions and responses cannot both go unsigned: an unsigned " +
			"assertion inside an unsigned response is a document anyone can write"}
	}
	var lifeArg any
	if c.LifetimeSeconds != 0 {
		lifeArg = c.LifetimeSeconds
	}
	err = q.QueryRow(ctx, `
		UPDATE core.saml_providers
		   SET sign_assertions = $2, sign_responses = $3,
		       lifetime_seconds = COALESCE($4::int, lifetime_seconds),
		       signature_alg = COALESCE($5::text, signature_alg), updated_at = now()
		 WHERE id = $1::uuid
		 RETURNING signature_alg`, providerID, signAssertions, signResponses, lifeArg, algArg).Scan(&alg)
	return signAssertions, signResponses, alg, err
}

// SetSAMLGroupRelease says which groups the provider is told of, under which
// attribute name (groups when empty): an allow-list, every named group one
// the organisation has, since a typo would silently release nothing. None
// named releases every group the person is in.
func SetSAMLGroupRelease(ctx context.Context, q outpostDB, orgID, providerID, attrName string, only []string) error {
	if err := requireSAMLProvider(ctx, q, orgID, providerID); err != nil {
		return err
	}
	if only == nil {
		only = []string{}
	}
	for _, n := range only {
		var ok bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.groups WHERE org_id = $1::uuid AND name = $2)`,
			orgID, n).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return samlInvalid{fmt.Sprintf("no group named %q in the organisation", n)}
		}
	}
	if attrName = strings.TrimSpace(attrName); attrName == "" {
		attrName = "groups"
	}
	_, err := q.Exec(ctx, `
		INSERT INTO core.saml_group_release (provider_id, org_id, attribute_name, only_groups)
		VALUES ($1::uuid, $2::uuid, $3, $4)
		ON CONFLICT (provider_id) DO UPDATE
		   SET attribute_name = EXCLUDED.attribute_name, only_groups = EXCLUDED.only_groups`,
		providerID, orgID, attrName, only)
	return err
}

// StopSAMLGroupRelease stops telling the provider of group membership.
func StopSAMLGroupRelease(ctx context.Context, q outpostDB, orgID, providerID string) error {
	if err := requireSAMLProvider(ctx, q, orgID, providerID); err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `DELETE FROM core.saml_group_release WHERE provider_id = $1::uuid`, providerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSAMLReleaseUnknown
	}
	return nil
}

// SAMLProviderRow is one service provider as an administrator sees it.
type SAMLProviderRow struct {
	ID, EntityID, Name, NameIDFormat, SignatureAlg string
	Enabled, SignAssertions, SignResponses         bool
	WantSignedRequests, Encrypted, HasSigningCert  bool
	LifetimeSeconds                                int
	ACSURLs, SLOURLs                               []string
	Attributes                                     map[string]string
	GroupAttribute                                 string
	ReleasesGroups                                 bool
	OnlyGroups                                     []string
}

// SAMLProviders lists an organisation's service providers by entity id.
func SAMLProviders(ctx context.Context, q Querier, orgID string) ([]SAMLProviderRow, error) {
	rows, err := q.Query(ctx, `
		SELECT p.id::text, p.entity_id, p.display_name, p.name_id_format, p.signature_alg, p.enabled,
		       p.sign_assertions, p.sign_responses, p.want_authn_requests_signed,
		       p.sp_encryption_cert IS NOT NULL, p.sp_signing_cert IS NOT NULL, p.lifetime_seconds,
		       COALESCE((SELECT array_agg(a.url ORDER BY a.url) FROM core.saml_acs_urls a WHERE a.provider_id = p.id), '{}'),
		       COALESCE((SELECT array_agg(s.url ORDER BY s.url) FROM core.saml_slo_urls s WHERE s.provider_id = p.id), '{}'),
		       p.attributes, COALESCE(r.attribute_name, ''), r.provider_id IS NOT NULL, COALESCE(r.only_groups, '{}')
		  FROM core.saml_providers p
		  LEFT JOIN core.saml_group_release r ON r.provider_id = p.id
		 WHERE p.org_id = $1::uuid ORDER BY p.entity_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SAMLProviderRow
	for rows.Next() {
		var p SAMLProviderRow
		if err := rows.Scan(&p.ID, &p.EntityID, &p.Name, &p.NameIDFormat, &p.SignatureAlg, &p.Enabled,
			&p.SignAssertions, &p.SignResponses, &p.WantSignedRequests, &p.Encrypted, &p.HasSigningCert,
			&p.LifetimeSeconds, &p.ACSURLs, &p.SLOURLs, &p.Attributes, &p.GroupAttribute, &p.ReleasesGroups,
			&p.OnlyGroups); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
