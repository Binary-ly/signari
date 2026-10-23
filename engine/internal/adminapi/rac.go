package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Remote-access connections (6.07), as `signari rac` registers them: a
// machine somebody reaches through the browser by way of guacd. The
// credentials are sealed and never read back.
//
// Two settings stay with the command, run from a shell on the deployment: a
// connection's recording path, and any guacd parameter naming a path. Each is
// a location on the machine guacd runs on, and choosing one decides where
// that machine writes, which is not a setting an organisation's administrator
// should hold over the deployment's host.

type racView struct {
	ID           string            `json:"id"`
	Slug         string            `json:"slug"`
	Name         string            `json:"name"`
	Protocol     string            `json:"protocol"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	RequireGroup string            `json:"require_group"`
	Recorded     bool              `json:"recorded"`
	Enabled      bool              `json:"enabled"`
	HasLogin     bool              `json:"has_credentials"`
	Parameters   map[string]string `json:"parameters"`
}

// addRACRequest registers a connection. require_group names the group whose
// members may reach it; empty lets anybody in the organisation, subject to
// the access policy.
type addRACRequest struct {
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Login        string `json:"login"`
	Password     string `json:"password"`
	RequireGroup string `json:"require_group"`
}

// patchRACRequest changes what is given: enabled takes the connection out of
// service or back, and parameters replaces its guacd parameters, empty for
// guacd's defaults.
type patchRACRequest struct {
	Enabled    *bool              `json:"enabled"`
	Parameters *map[string]string `json:"parameters"`
}

const racRefusal = "register or change a machine people in the organisation reach"

func (s *Server) listRAC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.RACConnections(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing remote-access connections", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]racView, 0, len(got))
	for _, c := range got {
		out = append(out, racView{ID: c.ID, Slug: c.Slug, Name: c.Name, Protocol: c.Protocol, Host: c.Host,
			Port: c.Port, RequireGroup: c.RequireGroup, Recorded: c.Recorded, Enabled: c.Enabled,
			HasLogin: c.HasLogin, Parameters: c.Parameters})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "connections": out})
}

func (s *Server) addRAC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addRACRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	req.Slug, req.Host = strings.TrimSpace(req.Slug), strings.TrimSpace(req.Host)
	req.RequireGroup = strings.TrimSpace(req.RequireGroup)
	switch {
	case req.Slug == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug_required",
			"detail": "the short name used in the connect URL"})
		return
	case req.Host == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_required"})
		return
	case req.Port < 0 || req.Port > 65535:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_port"})
		return
	}
	if narrowedTokenRefused(w, r, racRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var id string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if req.RequireGroup != "" {
			if err := s.requireNamedGroup(ctx, tx, orgID, req.RequireGroup); err != nil {
				return err
			}
		}
		var err error
		if id, err = store.AddRACConnection(ctx, tx, s.root, orgID, store.RACSpec{Slug: req.Slug, Name: req.Name,
			Protocol: req.Protocol, Host: req.Host, Port: req.Port, Login: req.Login, Password: req.Password,
			RequireGroup: req.RequireGroup}); err != nil {
			return err
		}
		// Never the credentials.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.rac_connection_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"connection": id, "slug": req.Slug, "protocol": req.Protocol,
				"host": req.Host, "require_group": req.RequireGroup, "credentials": req.Login != "" || req.Password != ""}})
	})
	if s.writeRACFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	out := map[string]any{"id": id, "slug": req.Slug, "config_version": version}
	writeJSON(w, http.StatusCreated, out)
}

// requireNamedGroup refuses a group the organisation does not have, or one
// outside a narrowed token: a connection restricted to a group nobody can be
// in reads as granted and reaches nobody.
func (s *Server) requireNamedGroup(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	id, err := store.GroupIDNamed(ctx, tx, orgID, name)
	if err != nil {
		return err
	}
	if id == "" {
		return errUnknownRACGroup
	}
	return requireGroup(ctx, id)
}

var errUnknownRACGroup = errors.New("no group of that name in the organisation")

func (s *Server) patchRAC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req patchRACRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.Enabled == nil && req.Parameters == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change",
			"detail": "give enabled, parameters or both"})
		return
	}
	var params map[string]string
	if req.Parameters != nil {
		params = map[string]string{}
		for k, v := range *req.Parameters {
			k = strings.TrimSpace(k)
			if k == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_parameter",
					"detail": "a parameter needs a name"})
				return
			}
			if strings.Contains(k, "path") {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parameter_names_a_path",
					"detail": k + " names a location on the machine guacd runs on; set it with `signari rac set-parameters` on the deployment"})
				return
			}
			params[k] = strings.TrimSpace(v)
		}
	}
	if narrowedTokenRefused(w, r, racRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	out := map[string]any{"slug": slug}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		detail := map[string]any{"slug": slug}
		if req.Enabled != nil {
			if err := store.SetRACEnabled(ctx, tx, orgID, slug, *req.Enabled); err != nil {
				return err
			}
			out["enabled"], detail["enabled"] = *req.Enabled, *req.Enabled
		}
		if params != nil {
			if err := store.SetRACParameters(ctx, tx, orgID, slug, params); err != nil {
				return err
			}
			names := make([]string, 0, len(params))
			for k := range params {
				names = append(names, k)
			}
			out["parameters"], detail["parameters"] = params, names
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.rac_connection_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeRACFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}

// writeRACFailure answers a refused or failed remote-access write, and
// reports whether it wrote anything.
func (s *Server) writeRACFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
	case errors.Is(err, errUnknownRACGroup):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_group", "detail": err.Error()})
	case errors.Is(err, store.ErrRACProtocol):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_protocol", "detail": err.Error()})
	case errors.Is(err, store.ErrRACReservedParameter):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reserved_parameter", "detail": err.Error()})
	case errors.Is(err, store.ErrRACExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
	case errors.Is(err, store.ErrRACUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection_not_found"})
	default:
		s.log.Error("writing a remote-access connection", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
