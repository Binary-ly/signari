package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/saml"
)

// Where a service provider resolves the artifacts it issues (8.08, 0288), which is how
// a request it sends by artifact is fetched.

// ErrNoArtifactResolution is an index a provider has no resolution service at.
var ErrNoArtifactResolution = errors.New("the service provider has no artifact resolution service at that index")

// checkArtifactResolution refuses an address this deployment would not fetch from: what
// the service answers is believed for coming from there.
func checkArtifactResolution(services []saml.IndexedEndpoint) error {
	seen := map[int]bool{}
	for _, e := range services {
		switch {
		case e.Index < 0 || e.Index > saml.MaxEndpointIndex:
			return samlInvalid{fmt.Sprintf("the artifact resolution index %d is not one an artifact can name "+
				"(0 to %d)", e.Index, saml.MaxEndpointIndex)}
		case !strings.HasPrefix(e.URL, "https://"):
			return samlInvalid{fmt.Sprintf("the artifact resolution service %q must be https: what it answers "+
				"is believed for coming from there", e.URL)}
		case strings.Contains(e.URL, "*"):
			return samlInvalid{fmt.Sprintf("%q contains a wildcard; an artifact resolution service is one "+
				"address", e.URL)}
		case seen[e.Index]:
			return samlInvalid{fmt.Sprintf("the artifact resolution index %d is given twice", e.Index)}
		}
		seen[e.Index] = true
	}
	return nil
}

// insertArtifactResolution writes a provider's resolution services.
func insertArtifactResolution(ctx context.Context, tx pgx.Tx, providerID string, services []saml.IndexedEndpoint) error {
	for _, e := range services {
		if _, err := tx.Exec(ctx, `INSERT INTO core.saml_artifact_resolution (provider_id, endpoint_index, url)
			VALUES ($1::uuid, $2, $3)`, providerID, e.Index, e.URL); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceSAMLArtifactResolution puts services in place of a provider's, none for none.
func ReplaceSAMLArtifactResolution(ctx context.Context, tx pgx.Tx, providerID string, services []saml.IndexedEndpoint) error {
	if err := checkArtifactResolution(services); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.saml_artifact_resolution WHERE provider_id = $1::uuid`,
		providerID); err != nil {
		return err
	}
	return insertArtifactResolution(ctx, tx, providerID, services)
}

// indexedText writes services as a change note says them: "index=url", spaced.
func indexedText(services []saml.IndexedEndpoint) string {
	parts := make([]string, len(services))
	for i, e := range services {
		parts[i] = fmt.Sprintf("%d=%s", e.Index, e.URL)
	}
	return strings.Join(parts, " ")
}

// SAMLArtifactResolution is a provider's resolution services, by index.
func SAMLArtifactResolution(ctx context.Context, q Querier, providerID string) ([]saml.IndexedEndpoint, error) {
	rows, err := q.Query(ctx, `SELECT endpoint_index, url FROM core.saml_artifact_resolution
		WHERE provider_id = $1::uuid ORDER BY endpoint_index`, ExactUUIDOrNil(providerID))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (saml.IndexedEndpoint, error) {
		var e saml.IndexedEndpoint
		return e, r.Scan(&e.Index, &e.URL)
	})
}

// SAMLArtifactResolutionURL is where a provider resolves the artifacts naming index, or
// ErrNoArtifactResolution.
func SAMLArtifactResolutionURL(ctx context.Context, q rowQuerier, providerID string, index int) (string, error) {
	var url string
	err := q.QueryRow(ctx, `SELECT url FROM core.saml_artifact_resolution
		WHERE provider_id = $1::uuid AND endpoint_index = $2`, ExactUUIDOrNil(providerID), index).Scan(&url)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoArtifactResolution
	}
	return url, err
}

// SAMLLogoutBinding is the binding a provider's logout endpoint at url was registered
// with, HTTP-Redirect when it is not registered: the binding a logout used before
// there was any other.
func SAMLLogoutBinding(ctx context.Context, q rowQuerier, providerID, url string) (string, error) {
	var binding string
	err := q.QueryRow(ctx, `SELECT binding FROM core.saml_slo_urls WHERE provider_id = $1::uuid AND url = $2`,
		ExactUUIDOrNil(providerID), url).Scan(&binding)
	if errors.Is(err, pgx.ErrNoRows) {
		return "HTTP-Redirect", nil
	}
	return binding, err
}

// SAMLArtifactSenders are the entity ids of the providers answered at an organisation's
// endpoints, or at the deployment's for none, that resolve artifacts somewhere. An
// artifact names its issuer only by the SHA-1 of its entity id, which the database
// cannot compute, so the caller compares; and only a provider with a resolution
// service can have sent one this deployment could fetch.
func SAMLArtifactSenders(ctx context.Context, q Querier, orgID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT p.entity_id FROM core.saml_providers p
		WHERE (CASE WHEN $1 = '' THEN NOT p.org_endpoint ELSE p.org_endpoint AND p.org_id = $2::uuid END)
		  AND EXISTS (SELECT 1 FROM core.saml_artifact_resolution a WHERE a.provider_id = p.id)`,
		orgID, ExactUUIDOrNil(orgID))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
