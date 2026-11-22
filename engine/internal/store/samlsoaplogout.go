package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Telling a service provider of a logout with no browser in it (8.03). Queued where
// a session ends, by ids alone: the NameID may be somebody's address and a queue is
// the last place to keep one, so delivery reads it from the participant row.

// SAMLLogoutTopic is its outbox topic.
const SAMLLogoutTopic = "saml_logout"

// SAMLLogoutNotice is one provider to tell of one session.
type SAMLLogoutNotice struct {
	SID        string `json:"sid"`
	ProviderID string `json:"provider_id"`
}

// SAMLLogoutTarget is what telling it takes.
type SAMLLogoutTarget struct {
	URL, NameID, NameIDFormat, SessionIndex, SignatureAlg, InstanceID string
	// EndpointOrg is as saml.Provider's: it says who the provider knows us as.
	EndpointOrg string
}

// SAMLLogoutTargetOf reads it. pgx.ErrNoRows is a provider since disabled, deleted or
// no longer taking this, with nothing left to do.
func SAMLLogoutTargetOf(ctx context.Context, q rowQuerier, sid, providerID string) (SAMLLogoutTarget, error) {
	var t SAMLLogoutTarget
	err := q.QueryRow(ctx, `
		SELECT u.url, p.name_id, COALESCE(p.name_id_format, ''), p.session_index, sp.signature_alg, o.instance_id::text,
		       CASE WHEN sp.org_endpoint THEN o.slug ELSE '' END
		  FROM core.saml_session_participants p
		  JOIN core.saml_providers sp ON sp.id = p.provider_id AND sp.enabled
		  JOIN core.saml_slo_urls u ON u.provider_id = p.provider_id AND u.binding = 'SOAP'
		  JOIN core.organizations o ON o.id = sp.org_id
		 WHERE p.sid = $1 AND p.provider_id = $2::uuid
		 ORDER BY u.url LIMIT 1`, sid, providerID).
		Scan(&t.URL, &t.NameID, &t.NameIDFormat, &t.SessionIndex, &t.SignatureAlg, &t.InstanceID, &t.EndpointOrg)
	return t, err
}

// SetSAMLSOAPLogout says where a service provider is told of a logout with no
// browser; empty stops telling it.
func SetSAMLSOAPLogout(ctx context.Context, q outpostDB, orgID, providerID, url string) error {
	if url != "" && !strings.HasPrefix(url, "https://") {
		return samlInvalid{"the SOAP logout URL must be https"}
	}
	var held bool
	err := q.QueryRow(ctx, `SELECT true FROM core.saml_providers WHERE id::text = $1 AND org_id = $2::uuid`,
		providerID, orgID).Scan(&held)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSAMLProviderUnknown
	}
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM core.saml_slo_urls WHERE provider_id = $1::uuid AND binding = 'SOAP'`, providerID); err != nil {
		return err
	}
	if url == "" {
		return nil
	}
	_, err = q.Exec(ctx, `INSERT INTO core.saml_slo_urls (provider_id, url, binding) VALUES ($1::uuid, $2, 'SOAP')`, providerID, url)
	return err
}
