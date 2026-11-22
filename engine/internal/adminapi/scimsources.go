package adminapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Inbound SCIM sources (6.07), as `signari scim-source` registers them: an
// upstream directory that provisions people into the organisation through
// /scim/v2 with a bearer token. The token is shown once and stored hashed.

type scimSourceView struct {
	ID         string     `json:"id"`
	Slug       string     `json:"slug"`
	Name       string     `json:"name"`
	OnDelete   string     `json:"on_delete"`
	Enabled    bool       `json:"enabled"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	Linked     int        `json:"linked"`
}

// addSCIMSourceRequest registers a source. on_delete is deactivate (the
// default), which keeps a deprovisioned person's history, or delete, which
// destroys it.
type addSCIMSourceRequest struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	OnDelete string `json:"on_delete"`
}

type patchSCIMSourceRequest struct {
	Enabled *bool `json:"enabled"`
}

const scimSourceRefusal = "let another system create and deactivate the organisation's people"

func (s *Server) listSCIMSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.SCIMSources(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing SCIM sources", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]scimSourceView, 0, len(got))
	for _, src := range got {
		out = append(out, scimSourceView{ID: src.ID, Slug: src.Slug, Name: src.Name, OnDelete: src.OnDelete,
			Enabled: src.Enabled, LastSeenAt: src.LastSeenAt, Linked: src.Linked})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "sources": out})
}

func (s *Server) addSCIMSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addSCIMSourceRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	req.Slug, req.Name = strings.TrimSpace(req.Slug), strings.TrimSpace(req.Name)
	if req.Slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug_required"})
		return
	}
	if narrowedTokenRefused(w, r, scimSourceRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var id, token string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if id, token, err = store.AddSCIMSource(ctx, tx, orgID, req.Slug, req.Name, req.OnDelete); err != nil {
			return err
		}
		// Never the token.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_source_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"source": id, "slug": req.Slug, "on_delete": req.OnDelete}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrSCIMSourceOnDelete):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_on_delete", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrSCIMSourceExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("adding a SCIM source", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	// The upstream calls <issuer>/scim/v2 with this as its bearer token.
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "slug": req.Slug, "token": token,
		"config_version": version})
}

// patchSCIMSource takes a source out of service or puts it back, as
// `signari scim-source disable|enable` does: disabled, its token is refused
// from the next request, and its links and settings are kept.
func (s *Server) patchSCIMSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req patchSCIMSourceRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change", "detail": "give enabled"})
		return
	}
	if narrowedTokenRefused(w, r, scimSourceRefusal) {
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
		if err := store.SetSCIMSourceEnabledIn(ctx, tx, orgID, slug, *req.Enabled); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_source_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"source": slug, "enabled": *req.Enabled}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrSCIMSourceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "source_not_found"})
		return
	case err != nil:
		s.log.Error("changing a SCIM source", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "enabled": *req.Enabled, "config_version": version})
}
