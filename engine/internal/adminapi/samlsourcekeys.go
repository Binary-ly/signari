package adminapi

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// This deployment's own keys toward a SAML upstream, as `signari idp saml-key` and
// `signari idp saml-use` keep them (8.04). A certificate goes out and a private
// key never does.

const samlKeyRefusal = "change the keys a SAML upstream is reached with"

func (s *Server) listSAMLSourceKeys(w http.ResponseWriter, r *http.Request) {
	list, err := store.SAMLSourceKeys(r.Context(), s.db, r.PathValue("orgID"), r.PathValue("slug"))
	if err != nil {
		s.writeIdPFailure(w, err, r.PathValue("orgID"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": list})
}

type addSAMLSourceKeyRequest struct {
	Purpose string `json:"purpose"`
}

func (s *Server) addSAMLSourceKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req addSAMLSourceKeyRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	if narrowedTokenRefused(w, r, samlKeyRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var key store.SAMLSourceKey
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if key, err = store.AddSAMLSourceKey(ctx, tx, s.root, orgID, slug, req.Purpose); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_source_key_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"provider": slug, "key": key.ID, "purpose": key.Purpose}})
	})
	if s.writeSAMLKeyFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": key.ID, "purpose": key.Purpose, "certificate": key.Certificate,
		"created_at": key.CreatedAt, "config_version": version})
}

func (s *Server) retireSAMLSourceKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug, id := r.PathValue("orgID"), r.PathValue("slug"), r.PathValue("keyID")
	if narrowedTokenRefused(w, r, samlKeyRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.RetireSAMLSourceKey(ctx, tx, orgID, slug, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_source_key_retired", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"provider": slug, "key": id}})
	})
	if s.writeSAMLKeyFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"retired": id, "config_version": version})
}

type samlKeyUseRequest struct {
	SignRequests      *bool `json:"sign_requests"`
	RequireEncryption *bool `json:"require_encryption"`
}

func (s *Server) setSAMLSourceKeyUse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req samlKeyUseRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	if req.SignRequests == nil && req.RequireEncryption == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change"})
		return
	}
	if narrowedTokenRefused(w, r, samlKeyRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.SetSAMLSourceKeyUse(ctx, tx, orgID, slug, req.SignRequests, req.RequireEncryption); err != nil {
			return err
		}
		detail := map[string]any{"provider": slug}
		if req.SignRequests != nil {
			detail["sign_requests"] = *req.SignRequests
		}
		if req.RequireEncryption != nil {
			detail["require_encryption"] = *req.RequireEncryption
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_source_key_use_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeSAMLKeyFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"config_version": version})
}

func (s *Server) writeSAMLKeyFailure(w http.ResponseWriter, err error, orgID string) bool {
	if errors.Is(err, store.ErrSAMLSourceKey) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "saml_key_refused", "detail": err.Error()})
		return true
	}
	return s.writeIdPFailure(w, err, orgID)
}
