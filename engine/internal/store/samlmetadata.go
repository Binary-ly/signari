package store

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/saml"
)

// A SAML partner registered from its metadata, and asked again (8.01). The
// document is read and verified by the saml package; what lands here has passed.

// SAMLMetadataOrigin is where a partner's details came from and what they had to
// be signed with. Empty for a partner typed in by hand, and Read says one was not.
type SAMLMetadataOrigin struct {
	Read      bool
	URL       string
	SignerPEM string
}

// SAMLMetadataChange is one thing a refresh changed, or would. A certificate is
// its fingerprint.
type SAMLMetadataChange struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// SAMLMetadataRequest is a document and how far to believe it, from whoever asked.
type SAMLMetadataRequest struct {
	// Document is what they handed over. Empty, it is read from URL, and without
	// one from where the partner was last read.
	Document  []byte
	URL       string
	SignerPEM string
	Unsigned  bool
}

// ReadSAMLMetadata reads and verifies a partner's metadata. What the request
// does not say comes from was, where the partner was last read from, so a partner
// imported under a signature cannot lose it by being asked again: dropping it
// takes Unsigned, by name.
func ReadSAMLMetadata(ctx context.Context, client *http.Client, r SAMLMetadataRequest, entityID string,
	was SAMLMetadataOrigin) (*saml.EntityMetadata, SAMLMetadataOrigin, error) {
	next := SAMLMetadataOrigin{Read: true, URL: cmp.Or(r.URL, was.URL), SignerPEM: cmp.Or(r.SignerPEM, was.SignerPEM)}
	if r.Unsigned {
		if r.SignerPEM != "" {
			return nil, next, saml.ErrMetadataTrust
		}
		next.SignerPEM = ""
	}
	doc := r.Document
	if len(doc) == 0 {
		if next.URL == "" {
			return nil, next, errors.New("give the metadata, or its https URL: nothing says where this partner's " +
				"metadata comes from")
		}
		var err error
		if doc, err = saml.FetchMetadata(ctx, client, next.URL); err != nil {
			return nil, next, err
		}
	}
	entity, err := saml.ReadMetadata(saml.MetadataSource{Document: doc, EntityID: entityID, SignerPEM: next.SignerPEM,
		Unsigned: r.Unsigned})
	return entity, next, err
}

// ApplyMetadata fills a registration from what the provider says of itself. What
// the caller set stays: a name, a NameID format. The key the provider offers for
// encrypted assertions is taken only when encrypt says so.
func (s *SAMLProviderSpec) ApplyMetadata(entityID string, m *saml.ServiceProviderMetadata, encrypt bool, o SAMLMetadataOrigin) {
	s.EntityID, s.ACSURL, s.MoreACSURLs = entityID, m.ACSURLs[0], m.ACSURLs[1:]
	s.SLOURL, s.SLOBinding, s.SigningCertPEM = m.SLOURL, m.SLOBinding, m.SigningCertPEM
	if encrypt {
		s.EncryptionCertPEM = m.EncryptionCertPEM
	}
	s.WantSignedRequests = s.WantSignedRequests || m.WantSignedRequests
	s.NameIDFormat = cmp.Or(s.NameIDFormat, m.NameIDFormat)
	s.Origin = o
}

// ApplyMetadata fills an upstream's registration from what it says of itself.
func (s *IdentityProviderSpec) ApplyMetadata(entityID string, m *saml.IdentityProviderMetadata, o SAMLMetadataOrigin) {
	s.EntityID, s.SSOURL, s.CertPEM = entityID, m.SSOURL, m.SigningCertPEM
	s.NameIDFormat = cmp.Or(s.NameIDFormat, m.NameIDFormat)
	s.Origin = o
}

// SAMLProviderOriginOf reads a service provider's entity ID and origin.
func SAMLProviderOriginOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, providerID string) (string, SAMLMetadataOrigin, error) {
	var entity string
	var o SAMLMetadataOrigin
	err := q.QueryRow(ctx, `
		SELECT entity_id, metadata_read_at IS NOT NULL, COALESCE(metadata_url, ''), COALESCE(metadata_signer, '')
		  FROM core.saml_providers WHERE org_id = $1::uuid AND id::text = $2`, orgID, providerID).
		Scan(&entity, &o.Read, &o.URL, &o.SignerPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", o, ErrSAMLProviderUnknown
	}
	return entity, o, err
}

// SAMLSourceOriginOf reads an upstream's entity ID and origin.
func SAMLSourceOriginOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, slug string) (string, SAMLMetadataOrigin, error) {
	var entity string
	var o SAMLMetadataOrigin
	err := q.QueryRow(ctx, `
		SELECT s.entity_id, s.metadata_read_at IS NOT NULL, COALESCE(s.metadata_url, ''),
		       COALESCE(s.metadata_signer, '')
		  FROM core.saml_sources s JOIN core.identity_providers p ON p.id = s.provider_id
		 WHERE p.org_id = $1::uuid AND p.slug = $2`, orgID, slug).
		Scan(&entity, &o.Read, &o.URL, &o.SignerPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", o, ErrProviderUnknown
	}
	return entity, o, err
}

// RefreshSAMLProvider puts what a service provider now says in place of what it
// said, and answers what moved. An operator's own decisions stay: a provider that
// stops saying it signs its requests is not thereby excused from signing them,
// and one whose assertions are encrypted stays encrypted.
func RefreshSAMLProvider(ctx context.Context, tx pgx.Tx, orgID, providerID string,
	m *saml.ServiceProviderMetadata, o SAMLMetadataOrigin) ([]SAMLMetadataChange, error) {
	var cur SAMLProviderSpec
	err := tx.QueryRow(ctx, `
		SELECT entity_id, display_name, name_id_format, COALESCE(sp_signing_cert, ''),
		       COALESCE(sp_encryption_cert, ''), sp_key_transport, want_authn_requests_signed
		  FROM core.saml_providers WHERE org_id = $1::uuid AND id::text = $2 FOR UPDATE`, orgID, providerID).
		Scan(&cur.EntityID, &cur.Name, &cur.NameIDFormat, &cur.SigningCertPEM, &cur.EncryptionCertPEM,
			&cur.KeyTransport, &cur.WantSignedRequests)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSAMLProviderUnknown
	}
	if err != nil {
		return nil, err
	}
	var acs []string
	rows, err := tx.Query(ctx, `SELECT url FROM core.saml_acs_urls WHERE provider_id = $1::uuid
		ORDER BY is_default DESC, url`, providerID)
	if err != nil {
		return nil, err
	}
	if acs, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `SELECT url, binding FROM core.saml_slo_urls WHERE provider_id = $1::uuid
		ORDER BY url LIMIT 1`, providerID).Scan(&cur.SLOURL, &cur.SLOBinding)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	next := SAMLProviderSpec{EntityID: cur.EntityID, Name: cur.Name, NameIDFormat: cur.NameIDFormat,
		KeyTransport: cur.KeyTransport, ACSURL: m.ACSURLs[0], MoreACSURLs: m.ACSURLs[1:],
		SLOURL: m.SLOURL, SLOBinding: m.SLOBinding, SigningCertPEM: m.SigningCertPEM,
		EncryptionCertPEM:  cmp.Or(m.EncryptionCertPEM, cur.EncryptionCertPEM),
		WantSignedRequests: cur.WantSignedRequests || m.WantSignedRequests}
	if cur.EncryptionCertPEM == "" {
		next.EncryptionCertPEM = ""
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}

	var changes []SAMLMetadataChange
	note := func(field, from, to string) {
		if from != to {
			changes = append(changes, SAMLMetadataChange{field, from, to})
		}
	}
	note("acs_urls", strings.Join(acs, " "), strings.Join(m.ACSURLs, " "))
	note("slo_url", cur.SLOURL, next.SLOURL)
	if next.SLOURL != "" {
		note("slo_binding", cur.SLOBinding, next.SLOBinding)
	}
	note("signing_certificate", fingerprints(cur.SigningCertPEM), fingerprints(next.SigningCertPEM))
	note("encryption_certificate", fingerprints(cur.EncryptionCertPEM), fingerprints(next.EncryptionCertPEM))
	if next.WantSignedRequests != cur.WantSignedRequests {
		note("want_signed_requests", "false", "true")
	}

	if _, err := tx.Exec(ctx, `DELETE FROM core.saml_acs_urls WHERE provider_id = $1::uuid`, providerID); err != nil {
		return nil, err
	}
	if err := insertACSURLs(ctx, tx, providerID, m.ACSURLs); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.saml_slo_urls WHERE provider_id = $1::uuid`, providerID); err != nil {
		return nil, err
	}
	if next.SLOURL != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO core.saml_slo_urls (provider_id, url, binding) VALUES ($1::uuid, $2, $3)`,
			providerID, next.SLOURL, next.SLOBinding); err != nil {
			return nil, err
		}
	}
	_, err = tx.Exec(ctx, `
		UPDATE core.saml_providers SET sp_signing_cert = NULLIF($2, ''), sp_encryption_cert = NULLIF($3, ''),
		       want_authn_requests_signed = $4, metadata_url = NULLIF($5, ''), metadata_signer = NULLIF($6, ''),
		       metadata_read_at = now(), updated_at = now()
		 WHERE id = $1::uuid`, providerID, next.SigningCertPEM, next.EncryptionCertPEM, next.WantSignedRequests,
		o.URL, o.SignerPEM)
	return changes, err
}

// insertACSURLs writes a provider's endpoints, the first as the default.
func insertACSURLs(ctx context.Context, tx pgx.Tx, providerID string, urls []string) error {
	for i, u := range urls {
		if _, err := tx.Exec(ctx, `INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
			VALUES ($1::uuid, $2, 'HTTP-POST', $3)`, providerID, u, i == 0); err != nil {
			return err
		}
	}
	return nil
}

// RefreshSAMLSource puts what an upstream now says in place of what it said. The
// NameID format stays: it is what accounts here are linked to, and changing it
// would strand everybody.
func RefreshSAMLSource(ctx context.Context, tx pgx.Tx, orgID, slug string, m *saml.IdentityProviderMetadata,
	o SAMLMetadataOrigin) ([]SAMLMetadataChange, error) {
	var id string
	cur := IdentityProviderSpec{Slug: slug, Kind: "saml"}
	err := tx.QueryRow(ctx, `
		SELECT s.provider_id::text, s.entity_id, s.sso_url, s.cert_pem, s.name_id_format
		  FROM core.saml_sources s JOIN core.identity_providers p ON p.id = s.provider_id
		 WHERE p.org_id = $1::uuid AND p.slug = $2 FOR UPDATE OF s`, orgID, slug).
		Scan(&id, &cur.EntityID, &cur.SSOURL, &cur.CertPEM, &cur.NameIDFormat)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProviderUnknown
	}
	if err != nil {
		return nil, err
	}
	next := cur
	next.SSOURL, next.CertPEM = m.SSOURL, m.SigningCertPEM
	if err := next.Validate(); err != nil {
		return nil, err
	}
	var changes []SAMLMetadataChange
	if cur.SSOURL != next.SSOURL {
		changes = append(changes, SAMLMetadataChange{"sso_url", cur.SSOURL, next.SSOURL})
	}
	if from, to := fingerprints(cur.CertPEM), fingerprints(next.CertPEM); from != to {
		changes = append(changes, SAMLMetadataChange{"signing_certificate", from, to})
	}
	_, err = tx.Exec(ctx, `
		UPDATE core.saml_sources SET sso_url = $2, cert_pem = $3, metadata_url = NULLIF($4, ''),
		       metadata_signer = NULLIF($5, ''), metadata_read_at = now()
		 WHERE provider_id = $1::uuid`, id, next.SSOURL, next.CertPEM, o.URL, o.SignerPEM)
	return changes, err
}

// fingerprints names the certificates in a PEM text, in an order that does not
// depend on the file's, so a reshuffled document reports no change.
func fingerprints(certPEM string) string {
	if strings.TrimSpace(certPEM) == "" {
		return ""
	}
	certs, err := saml.ParseCertificates(certPEM)
	if err != nil {
		return "unreadable"
	}
	var names []string
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		names = append(names, hex.EncodeToString(sum[:]))
	}
	slices.Sort(names)
	return strings.Join(names, " ")
}

// firstUnusableACS is a further endpoint a registration must refuse, by the rules
// of the default one.
func firstUnusableACS(urls []string) error {
	for _, u := range urls {
		if !strings.HasPrefix(u, "https://") || strings.Contains(u, "*") {
			return samlInvalid{fmt.Sprintf("the ACS URL %q has to be https and exact", u)}
		}
	}
	return nil
}
