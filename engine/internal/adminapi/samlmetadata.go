package adminapi

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// A SAML partner read from its metadata, and read again, as `signari saml
// refresh-sp` and `signari idp refresh-saml` do it (8.01). Only ever when asked:
// a partner's metadata says where assertions go.

// maxMetadataRequest is what a request carrying a document may be. A federation's
// aggregate is larger, and is given by its URL.
const maxMetadataRequest = 2 << 20

type samlMetadataRequest struct {
	// Metadata is the document. Empty, it is read from metadata_url, and without
	// one from where the partner was last read.
	Metadata    string `json:"metadata"`
	MetadataURL string `json:"metadata_url"`
	// MetadataSigner is the certificate it must be signed with. Empty, the one it
	// was last checked against.
	MetadataSigner string `json:"metadata_signer"`
	// MetadataUnsigned takes it with no signature check, by name.
	MetadataUnsigned bool `json:"metadata_unsigned"`
	// DryRun answers what would change and changes nothing.
	DryRun bool `json:"dry_run"`
}

// partnerMetadata reads and verifies a document, outside any transaction: a slow
// partner must not hold one open. It writes the refusal itself. The caller has
// checked the token's narrowing; the organisation is checked here, so a token for
// another one cannot make this engine fetch anything.
func (s *Server) partnerMetadata(w http.ResponseWriter, r *http.Request, orgID string, req samlMetadataRequest,
	entityID string, was store.SAMLMetadataOrigin) (*saml.EntityMetadata, store.SAMLMetadataOrigin, bool) {
	ctx := r.Context()
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return nil, was, false
	}
	entity, origin, err := store.ReadSAMLMetadata(ctx, s.hookClient(30*time.Second), store.SAMLMetadataRequest{
		Document: []byte(req.Metadata), URL: req.MetadataURL, SignerPEM: req.MetadataSigner,
		Unsigned: req.MetadataUnsigned}, entityID, was)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata", "detail": err.Error()})
		return nil, was, false
	}
	return entity, origin, true
}

func (s *Server) refreshSAMLProviderMetadata(w http.ResponseWriter, r *http.Request) {
	orgID, providerID := r.PathValue("orgID"), r.PathValue("providerID")
	var req samlMetadataRequest
	if !decodeStrictUpTo(w, r, &req, maxMetadataRequest) {
		return
	}
	if narrowedTokenRefused(w, r, samlRefusal) {
		return
	}
	if err := requireOrg(r.Context(), orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	entityID, was, err := store.SAMLProviderOriginOf(r.Context(), s.db, orgID, providerID)
	if s.writeSAMLFailure(w, err, orgID) {
		return
	}
	entity, origin, ok := s.partnerMetadata(w, r, orgID, req, entityID, was)
	if !ok {
		return
	}
	if entity.SP == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata",
			"detail": "the metadata no longer declares a SAML 2.0 service provider"})
		return
	}
	s.applyMetadataRefresh(w, r, orgID, req.DryRun, entity, origin, map[string]any{"provider": providerID, "entity_id": entityID},
		s.writeSAMLFailure, func(tx pgx.Tx) ([]store.SAMLMetadataChange, error) {
			return store.RefreshSAMLProvider(r.Context(), tx, orgID, providerID, entity.SP, origin)
		})
}

func (s *Server) refreshIdentityProviderMetadata(w http.ResponseWriter, r *http.Request) {
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req samlMetadataRequest
	if !decodeStrictUpTo(w, r, &req, maxMetadataRequest) {
		return
	}
	if narrowedTokenRefused(w, r, idpRefusal) {
		return
	}
	if err := requireOrg(r.Context(), orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	entityID, was, err := store.SAMLSourceOriginOf(r.Context(), s.db, orgID, slug)
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	entity, origin, ok := s.partnerMetadata(w, r, orgID, req, entityID, was)
	if !ok {
		return
	}
	if entity.IdP == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata",
			"detail": "the metadata no longer declares a SAML 2.0 identity provider"})
		return
	}
	s.applyMetadataRefresh(w, r, orgID, req.DryRun, entity, origin, map[string]any{"provider": slug, "entity_id": entityID},
		s.writeIdPFailure, func(tx pgx.Tx) ([]store.SAMLMetadataChange, error) {
			return store.RefreshSAMLSource(r.Context(), tx, orgID, slug, entity.IdP, origin)
		})
}

// applyMetadataRefresh makes the change, or for a dry run makes it in a
// transaction nothing commits, so the answer is what would really happen.
func (s *Server) applyMetadataRefresh(w http.ResponseWriter, r *http.Request, orgID string, dryRun bool,
	entity *saml.EntityMetadata, origin store.SAMLMetadataOrigin, detail map[string]any,
	failed func(http.ResponseWriter, error, string) bool, apply func(pgx.Tx) ([]store.SAMLMetadataChange, error)) {
	ctx := r.Context()
	answer := func(changes []store.SAMLMetadataChange) map[string]any {
		if changes == nil {
			changes = []store.SAMLMetadataChange{}
		}
		notes := entity.Notes
		if notes == nil {
			notes = []string{}
		}
		return map[string]any{"entity_id": entity.EntityID, "applied": !dryRun, "changes": changes, "notes": notes}
	}
	if dryRun {
		tx, err := s.db.Begin(ctx)
		if failed(w, err, orgID) {
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		changes, err := apply(tx)
		if failed(w, err, orgID) {
			return
		}
		writeJSON(w, http.StatusOK, answer(changes))
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var changes []store.SAMLMetadataChange
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if changes, err = apply(tx); err != nil {
			return err
		}
		fields := make([]string, 0, len(changes))
		for _, c := range changes {
			fields = append(fields, c.Field)
		}
		detail["changes"], detail["signed"], detail["url"] = fields, origin.SignerPEM != "", origin.URL
		return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_metadata_read", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if failed(w, err, orgID) {
		return
	}
	setETag(w, version)
	out := answer(changes)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}
