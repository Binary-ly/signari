package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/store"
)

// Interstitial prompts (6.07), as `signari prompt` manages them: terms and
// notices asked between authentication and the session. A prompt is changed,
// enabled and disabled, never deleted here: its answers are the record of
// what people agreed to, and the command keeps them too.

type promptView struct {
	Slug    string          `json:"slug"`
	Title   string          `json:"title"`
	Body    string          `json:"body"`
	Once    bool            `json:"once"`
	Order   int             `json:"order"`
	Fields  []prompts.Field `json:"fields"`
	Enabled bool            `json:"enabled"`
	Version int             `json:"version"`
	// Answered is how many people answered the current version.
	Answered int `json:"answered"`
}

// putPromptRequest defines or replaces a prompt. Once is true unless set
// false, as the command's default.
type putPromptRequest struct {
	Title  string          `json:"title"`
	Body   string          `json:"body"`
	Once   *bool           `json:"once"`
	Order  int             `json:"order"`
	Fields []prompts.Field `json:"fields"`
}

type patchPromptRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) listPrompts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.OrgPrompts(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing prompts", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]promptView, 0, len(got))
	for _, p := range got {
		fields := p.Fields
		if fields == nil {
			fields = []prompts.Field{}
		}
		out = append(out, promptView{Slug: p.Slug, Title: p.Title, Body: p.Body, Once: p.Once, Order: p.Order,
			Fields: fields, Enabled: p.Enabled, Version: p.Version, Answered: p.Answered})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "prompts": out})
}

func (s *Server) putPrompt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req putPromptRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	def := store.PromptDefinition{Slug: slug, Title: req.Title, Body: req.Body,
		Once: req.Once == nil || *req.Once, Order: req.Order, Fields: req.Fields}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var version, reasked int
	cv, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if version, reasked, err = store.SavePrompt(ctx, tx, orgID, def); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.prompt_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"slug": slug, "version": version, "asked_again": reasked}})
	})
	var invalid store.ErrInvalidPrompt
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.As(err, &invalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_prompt", "detail": invalid.Error()})
		return
	case err != nil:
		s.log.Error("saving a prompt", "org_id", orgID, "slug", slug, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, cv)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "version": version, "asked_again": reasked,
		"config_version": cv})
}

func (s *Server) patchPrompt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req patchPromptRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change",
			"detail": "enabled is the field a prompt is changed by here; its wording is a PUT"})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	cv, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		found, err := store.SetPromptEnabled(ctx, tx, orgID, slug, *req.Enabled)
		if err != nil {
			return err
		}
		if !found {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.prompt_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"slug": slug, "enabled": *req.Enabled}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "prompt_not_found"})
		return
	case err != nil:
		s.log.Error("changing a prompt", "org_id", orgID, "slug", slug, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, cv)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "enabled": *req.Enabled, "config_version": cv})
}
