package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// An organisation's resource servers (1.87): the RFC 8707 resources its
// clients may ask for tokens audienced to. Also written by `signari resource`,
// both through the store functions. organizations:write, because a resource
// server is the organisation's own API, not one client's setting: a token
// restricted to some clients must not be able to widen what every client of the
// organisation may be issued.

type resourceServerRequest struct {
	Resource string `json:"resource"`
	Name     string `json:"name"`
}

func (s *Server) listResourceServers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	rs, err := store.ResourceServers(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing resource servers", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, rs)
}

func (s *Server) putResourceServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req resourceServerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if err := oauth.CheckResource(req.Resource); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_resource", "detail": err.Error()})
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
		if err := store.SetResourceServer(ctx, tx, orgID, req.Resource, req.Name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.resource_server_set", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"resource": req.Resource, "name": req.Name},
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrResourceIsAdminAPI):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_resource", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("registering a resource server", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"resource": req.Resource, "name": req.Name,
		"config_version": version})
}

func (s *Server) deleteResourceServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	resource := r.URL.Query().Get("resource")
	if resource == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request",
			"detail": "name the resource to remove with ?resource="})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		if err := store.RemoveResourceServer(ctx, tx, orgID, resource); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.resource_server_removed", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"resource": resource},
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, store.ErrResourceServerUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource_server_not_found"})
		return
	case err != nil:
		s.log.Error("removing a resource server", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
