package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Trusted Client Attesters (6.07), as `signari attester add` registers them:
// whose attestations attestation-based client authentication accepts. Read
// back without their keys, by name and count.

type attesterView struct {
	Name        string    `json:"name"`
	Keys        int       `json:"keys"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type putAttesterRequest struct {
	// JWKS is the attester's public key set.
	JWKS        json.RawMessage `json:"jwks"`
	Description string          `json:"description"`
}

func (s *Server) listAttesters(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.OrgAttesters(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing client attesters", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]attesterView, 0, len(got))
	for _, a := range got {
		out = append(out, attesterView{Name: a.Name, Keys: a.Keys, Description: a.Description, CreatedAt: a.CreatedAt})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "attesters": out})
}

func (s *Server) putAttester(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	var req putAttesterRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var keys int
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if keys, err = store.SetAttester(ctx, tx, orgID, name, req.JWKS, req.Description); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.attester_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"name": name, "keys": keys}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrInvalidAttester):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_attester", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("registering a client attester", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "keys": keys, "config_version": version})
}

func (s *Server) deleteAttester(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		removed, err := store.RemoveAttester(ctx, tx, orgID, name)
		if err != nil {
			return err
		}
		if !removed {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.attester_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"name": name}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "attester_not_found"})
		return
	case err != nil:
		s.log.Error("removing a client attester", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
