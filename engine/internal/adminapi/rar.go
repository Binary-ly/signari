package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// RFC 9396 authorization details types an organisation accepts (6.07), as
// `signari rar register` records them. Which clients may ask for each is the
// client's own `authorization_detail_types`, set by PATCH /admin/clients. A
// type is named in the body, or the query for a DELETE, since it is often a
// URI.

type detailTypeView struct {
	Type        string   `json:"type"`
	Fields      []string `json:"fields"`
	Required    []string `json:"required"`
	Description string   `json:"description"`
	Clients     []string `json:"clients"`
}

type putDetailTypeRequest struct {
	Type        string   `json:"type"`
	Fields      []string `json:"fields"`
	Required    []string `json:"required"`
	Description string   `json:"description"`
}

func (s *Server) listDetailTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.OrgDetailTypes(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing authorization details types", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// The clients a token may see, as its reads are narrowed everywhere.
	allowed := clientFilter(ctx)
	out := make([]detailTypeView, 0, len(got))
	for _, t := range got {
		clients := []string{}
		for _, c := range t.Clients {
			if allowed == nil || slices.Contains(allowed, c) {
				clients = append(clients, c)
			}
		}
		out = append(out, detailTypeView{Type: t.Type, Fields: t.Fields, Required: t.Required,
			Description: t.Description, Clients: clients})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "authorization_detail_types": out})
}

func (s *Server) putDetailType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putDetailTypeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	t := store.DetailType{Type: strings.TrimSpace(req.Type), Fields: cleanList(req.Fields, false),
		Required: cleanList(req.Required, false), Description: strings.TrimSpace(req.Description)}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.RegisterDetailType(ctx, tx, orgID, t); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.authorization_details_type_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"type": t.Type, "fields": t.Fields, "required": t.Required}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrInvalidDetailType):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_authorization_details_type",
			"detail": err.Error()})
		return
	case err != nil:
		s.log.Error("registering an authorization details type", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"type": t.Type, "config_version": version})
}

func (s *Server) deleteDetailType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	if typ == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type_required",
			"detail": "name the type to forget as ?type="})
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
		removed, err := store.RemoveDetailType(ctx, tx, orgID, typ)
		if err != nil {
			return err
		}
		if !removed {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.authorization_details_type_removed",
			AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, Detail: map[string]any{"type": typ}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "authorization_details_type_not_found"})
		return
	case err != nil:
		s.log.Error("forgetting an authorization details type", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
