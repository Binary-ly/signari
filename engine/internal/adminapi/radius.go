package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/radius"
	"signari.dev/engine/internal/store"
)

// RADIUS (6.07), as `signari radius` configures it: the network devices that
// may send Access-Requests, and the VLAN or Filter-Id a group's members are
// given. A device's shared secret is sealed and never read back. Running
// listeners pick either change up within a minute.

type radiusClientView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Network string `json:"network"`
	Enabled bool   `json:"enabled"`
}

// addRADIUSClientRequest registers a device sending from network with the
// shared secret configured on it.
type addRADIUSClientRequest struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Secret  string `json:"secret"`
}

type patchRADIUSClientRequest struct {
	Enabled *bool `json:"enabled"`
}

type radiusAuthorizationView struct {
	GroupID  string `json:"group_id"`
	Group    string `json:"group"`
	VLAN     *int   `json:"vlan_id"`
	FilterID string `json:"filter_id"`
	Priority int    `json:"priority"`
}

// putRADIUSAuthorizationRequest places a group's members on a VLAN, a
// Filter-Id naming a filter list on the device, or both. Priority decides for
// somebody in several authorised groups: highest wins, ties by group id.
type putRADIUSAuthorizationRequest struct {
	VLAN     int    `json:"vlan_id"`
	FilterID string `json:"filter_id"`
	Priority int    `json:"priority"`
}

const radiusRefusal = "register or change a network device, which may ask for anybody's password"

func (s *Server) listRADIUSClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.RADIUSClients(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing RADIUS clients", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]radiusClientView, 0, len(got))
	for _, c := range got {
		out = append(out, radiusClientView{ID: c.ID, Name: c.Name, Network: c.Network, Enabled: c.Enabled})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "clients": out})
}

func (s *Server) addRADIUSClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addRADIUSClientRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.Name = strings.TrimSpace(req.Name); req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name_required",
			"detail": "it is what appears in the logs when this device asks"})
		return
	}
	// Checked before anything is written, so a refusal names the request: a
	// secret too short to survive offline grinding, or a range that is not
	// one, or is every address.
	if err := radius.ValidSecret(req.Secret); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_secret", "detail": err.Error()})
		return
	}
	if _, err := radius.ClientNetwork(req.Network); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_network", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, radiusRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var id, network string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if id, network, err = store.AddRADIUSClient(ctx, tx, s.root, orgID, req.Name, req.Network, req.Secret); err != nil {
			return err
		}
		// Never the secret.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.radius_client_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"radius_client": id, "name": req.Name, "network": network}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrRADIUSNetworkTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("adding a RADIUS client", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": req.Name, "network": network,
		"config_version": version})
}

func (s *Server) patchRADIUSClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, deviceID := r.PathValue("orgID"), r.PathValue("deviceID")
	var req patchRADIUSClientRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change", "detail": "give enabled"})
		return
	}
	if narrowedTokenRefused(w, r, radiusRefusal) {
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
		if err := store.SetRADIUSClientEnabled(ctx, tx, orgID, deviceID, *req.Enabled); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.radius_client_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"radius_client": deviceID, "enabled": *req.Enabled}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrRADIUSClientUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "radius_client_not_found"})
		return
	case err != nil:
		s.log.Error("changing a RADIUS client", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"id": deviceID, "enabled": *req.Enabled, "config_version": version})
}

func (s *Server) listRADIUSAuthorizations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	// A token narrowed to some groups sees theirs only.
	got, err := store.RADIUSAuthorizations(ctx, s.db, orgID, groupFilter(ctx))
	if err != nil {
		s.log.Error("listing RADIUS authorisations", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]radiusAuthorizationView, 0, len(got))
	for _, a := range got {
		out = append(out, radiusAuthorizationView{GroupID: a.GroupID, Group: a.Group, VLAN: a.VLAN,
			FilterID: a.FilterID, Priority: a.Priority})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "authorizations": out})
}

func (s *Server) putRADIUSAuthorization(w http.ResponseWriter, r *http.Request) {
	var req putRADIUSAuthorizationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	s.changeRADIUSAuthorization(w, r, &req)
}

func (s *Server) deleteRADIUSAuthorization(w http.ResponseWriter, r *http.Request) {
	s.changeRADIUSAuthorization(w, r, nil)
}

// changeRADIUSAuthorization sets what the group the path names is given at
// Access-Accept, or with nil takes it away, as `signari radius authorize`
// does. Members already connected keep what they were given until they are
// re-authorised: RADIUS attributes are decided at Access-Accept.
func (s *Server) changeRADIUSAuthorization(w http.ResponseWriter, r *http.Request, req *putRADIUSAuthorizationRequest) {
	ctx := r.Context()
	groupID := r.PathValue("groupID")
	if err := requireGroup(ctx, groupID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	out := map[string]any{"group_id": groupID}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx, `SELECT org_id::text FROM core.groups WHERE id = $1::uuid`,
			groupID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		if req == nil {
			if err := store.RemoveRADIUSAuthorization(ctx, tx, orgID, groupID); err != nil {
				return err
			}
			out["removed"] = true
			return audit.Write(ctx, tx, audit.Event{Type: "admin.radius_authorization_removed",
				AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, Detail: map[string]any{"group_id": groupID}})
		}
		if err := store.SetRADIUSAuthorization(ctx, tx, orgID, groupID, req.VLAN, req.FilterID, req.Priority); err != nil {
			return err
		}
		detail := map[string]any{"group_id": groupID, "priority": req.Priority}
		if req.VLAN != 0 {
			detail["vlan_id"] = req.VLAN
		}
		if f := strings.TrimSpace(req.FilterID); f != "" {
			detail["filter_id"] = f
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.radius_authorization_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	switch {
	case errors.Is(err, store.ErrRADIUSNothingAuthorised), errors.Is(err, store.ErrVLANRange),
		errors.Is(err, store.ErrFilterIDLength):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_radius_authorization",
			"detail": err.Error()})
		return
	case errors.Is(err, store.ErrRADIUSNotAuthorised):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "radius_authorization_not_found"})
		return
	}
	out["config_version"] = version
	s.finishGroupWrite(w, r, groupID, version, err, http.StatusOK, out)
}
