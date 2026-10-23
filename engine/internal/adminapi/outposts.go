package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Outposts (6.07), as `signari outpost` registers them: a remote LDAP, RADIUS,
// proxy, desktop or decision server holding a token bound to its protocol
// and no database credentials. The token is shown once, when the outpost is
// made, and is stored hashed.

type outpostView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Enabled     bool       `json:"enabled"`
	SearchGroup string     `json:"search_group"`
	LastSeenAt  *time.Time `json:"last_seen_at"`
	LastSeenIP  string     `json:"last_seen_ip"`
}

type createOutpostRequest struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	SearchGroup string `json:"search_group"`
}

// patchOutpostRequest changes what is given: enabled takes the outpost out
// of service or puts it back, and search_group says whose members may search
// the whole directory through an LDAP outpost, empty for nobody.
type patchOutpostRequest struct {
	Enabled     *bool   `json:"enabled"`
	SearchGroup *string `json:"search_group"`
}

const outpostRefusal = "register or change an outpost, which verifies anybody's password in the organisation"

func (s *Server) listOutposts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.Outposts(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing outposts", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]outpostView, 0, len(got))
	for _, o := range got {
		out = append(out, outpostView{ID: o.ID, Name: o.Name, Kind: o.Kind, Enabled: o.Enabled,
			SearchGroup: o.SearchGroup, LastSeenAt: o.LastSeenAt, LastSeenIP: o.LastSeenIP})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "outposts": out})
}

func (s *Server) createOutpost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req createOutpostRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	req.Name, req.SearchGroup = strings.TrimSpace(req.Name), strings.TrimSpace(req.SearchGroup)
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name_required"})
		return
	}
	if narrowedTokenRefused(w, r, outpostRefusal) {
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
		if id, token, err = store.CreateOutpost(ctx, tx, orgID, req.Name, req.Kind, req.SearchGroup); err != nil {
			return err
		}
		// Never the token.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.outpost_created", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"outpost": id, "name": req.Name, "kind": req.Kind,
				"search_group": req.SearchGroup}})
	})
	if s.writeOutpostFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": req.Name, "kind": req.Kind, "token": token,
		"config_version": version})
}

func (s *Server) patchOutpost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	var req patchOutpostRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.Enabled == nil && req.SearchGroup == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change",
			"detail": "give enabled, search_group or both"})
		return
	}
	if narrowedTokenRefused(w, r, outpostRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	out := map[string]any{"name": name}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		// Both or neither: a refused search group leaves enabled as it was.
		detail := map[string]any{"name": name}
		if req.Enabled != nil {
			if err := store.SetOutpostEnabled(ctx, tx, orgID, name, *req.Enabled); err != nil {
				return err
			}
			out["enabled"], detail["enabled"] = *req.Enabled, *req.Enabled
		}
		if req.SearchGroup != nil {
			group := strings.TrimSpace(*req.SearchGroup)
			if err := store.SetOutpostSearchGroup(ctx, tx, orgID, name, group); err != nil {
				return err
			}
			out["search_group"], detail["search_group"] = group, group
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.outpost_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeOutpostFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}

// writeOutpostFailure answers a refused or failed outpost write, and reports
// whether it wrote anything.
func (s *Server) writeOutpostFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, store.ErrOutpostKind):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_kind", "detail": err.Error()})
	case errors.Is(err, store.ErrSearchGroupNotLDAP), errors.Is(err, store.ErrSearchGroupUnknown):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_search_group", "detail": err.Error()})
	case errors.Is(err, store.ErrOutpostExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
	case errors.Is(err, store.ErrOutpostUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "outpost_not_found"})
	default:
		s.log.Error("writing an outpost", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
