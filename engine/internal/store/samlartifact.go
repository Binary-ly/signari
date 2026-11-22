package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// A SAML response waiting for its artifact to be resolved (8.08).

// SAMLArtifactLifetime is how long an artifact can be resolved. "The artifact
// issuer SHOULD enforce the shortest practical time limit" (saml-core-2.0-os
// lines 2401-2403): a provider resolves on the browser's arrival, a round trip
// later, and a minute leaves room for a slow one and no more.
const SAMLArtifactLifetime = time.Minute

const samlArtifactContext = "signari saml artifact"

// ErrSAMLArtifactGone is an artifact resolved before, expired, or never issued.
var ErrSAMLArtifactGone = errors.New("no response waits for that artifact")

// HoldSAMLArtifact keeps message for the provider until the artifact carrying
// handle is resolved. It is sealed under a key derived from the handle and found
// by the handle's hash, and the handle is not stored, so the row opens nothing
// without the artifact.
func HoldSAMLArtifact(ctx context.Context, q outpostDB, providerID, orgID string, handle, message []byte) error {
	sealed, err := sealUnder(handle, samlArtifactContext, message, []byte(providerID))
	if err != nil {
		return err
	}
	h := sha256.Sum256(handle)
	_, err = q.Exec(ctx, `
		INSERT INTO core.saml_artifacts (handle_hash, provider_id, org_id, message, expires_at)
		VALUES ($1, $2::uuid, $3::uuid, $4, now() + $5::interval)`,
		h[:], providerID, orgID, sealed, SAMLArtifactLifetime.String())
	return err
}

// TakeSAMLArtifact takes the message an artifact's handle names, and the
// provider it was issued to. The row goes with the first attempt, whoever makes
// it and whether or not it is then refused: "any subsequent request with the
// same artifact by any requester results in an empty response"
// (saml-core-2.0-os lines 2393-2394).
func TakeSAMLArtifact(ctx context.Context, q outpostDB, handle []byte) (providerID string, message []byte, err error) {
	h := sha256.Sum256(handle)
	var sealed []byte
	var live bool
	err = q.QueryRow(ctx, `
		DELETE FROM core.saml_artifacts WHERE handle_hash = $1
		RETURNING provider_id::text, message, expires_at > now()`, h[:]).Scan(&providerID, &sealed, &live)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", nil, ErrSAMLArtifactGone
	case err != nil:
		return "", nil, err
	case !live:
		return "", nil, ErrSAMLArtifactGone
	}
	message, err = openUnder(handle, samlArtifactContext, sealed, []byte(providerID))
	if err != nil {
		return "", nil, err
	}
	return providerID, message, nil
}

// SweepExpiredSAMLArtifacts deletes artifacts nobody resolved in time.
func SweepExpiredSAMLArtifacts(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.saml_artifacts WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.saml_artifacts WHERE expires_at <= now()
		LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
