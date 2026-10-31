package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// The applications forward authentication protects.
//
// /proxy/start sends a signed-in person back to the application only when its
// host is registered here, and until these routes and their CLI twin existed
// nothing could register one: every forward-auth deployment stopped at the
// sign-in page, telling the person their application was "not a registered
// protected host".

type proxyHostRequest struct {
	Host string `json:"host"`
	// Enabled defaults to TRUE when absent, which is why it is a pointer: the
	// common case is registering a host to use it.
	Enabled *bool `json:"enabled"`
	// ReleaseGroups and SignedIdentity keep what the host has when absent.
	ReleaseGroups  *[]string `json:"release_groups"`
	SignedIdentity *bool     `json:"signed_identity"`
}

func (s *Server) listProxyHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	hosts, err := store.ProxyHosts(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing protected hosts", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxy_hosts": hosts})
}

// putProxyHost registers a protected host, or changes whether it is enabled.
func (s *Server) putProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")

	var req proxyHostRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	host, err := store.NormaliseProxyHost(req.Host)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_host", "detail": err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var release any
	if req.ReleaseGroups != nil {
		if err := store.CheckReleaseGroups(*req.ReleaseGroups); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_host", "detail": err.Error()})
			return
		}
		release = append([]string{}, *req.ReleaseGroups...)
	}

	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.proxy_hosts (org_id, host, enabled, release_groups, signed_identity)
			VALUES ($1::uuid, $2, $3, COALESCE($4::text[], '{}'), COALESCE($5::boolean, false))
			ON CONFLICT (org_id, host) DO UPDATE SET enabled = EXCLUDED.enabled,
				release_groups = COALESCE($4::text[], core.proxy_hosts.release_groups),
				signed_identity = COALESCE($5::boolean, core.proxy_hosts.signed_identity)`,
			orgID, host, enabled, release, req.SignedIdentity); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.proxy_host_set", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"host": host, "enabled": enabled, "releases_groups": req.ReleaseGroups != nil,
				"signed_identity": req.SignedIdentity},
		})
	})
	var pg *pgconn.PgError
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.As(err, &pg) && pg.ConstraintName == "proxy_hosts_host_key":
		// Held by another organisation (or by this one in other letters). A
		// host is unique across the deployment: verify admits whoever's
		// organisation registered it.
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":  "host_taken",
			"detail": "this host is already registered as a protected host",
		})
		return
	case err != nil:
		s.log.Error("setting a protected host", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"host": host, "enabled": enabled, "config_version": version,
	})
}

func (s *Server) deleteProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	host, err := store.NormaliseProxyHost(r.PathValue("host"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_host", "detail": err.Error()})
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
		// org_id in the WHERE as well as the host, so one tenant cannot remove
		// another's protection by naming its host.
		tag, err := tx.Exec(ctx,
			`DELETE FROM core.proxy_hosts WHERE org_id = $1::uuid AND host = $2`, orgID, host)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.proxy_host_removed", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"host": host},
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy_host_not_found"})
		return
	case err != nil:
		s.log.Error("removing a protected host", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"host": host, "config_version": version})
}
