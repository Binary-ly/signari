package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/directory"
)

// Directory sources (6.07), as `signari dir` manages them: Google Workspace,
// Entra ID or an LDAP directory whose people this organisation's accounts
// follow. Credentials are sealed and never read back.
//
// An LDAP source is registered only by a deployment-wide token. Its URL is
// dialled by this engine from inside the deployment's network, with no outbound
// filter, so choosing one is choosing where the engine connects; an
// organisation's administrator holds no such decision over the host.
//
// A sync calls the directory, so it runs outside the write's transaction:
// If-Match is checked before the call and the record written after it.

type directoryView struct {
	ID              string              `json:"id"`
	Slug            string              `json:"slug"`
	Name            string              `json:"name"`
	Kind            string              `json:"kind"`
	OnMissing       string              `json:"on_missing"`
	Enabled         bool                `json:"enabled"`
	DryRun          bool                `json:"dry_run"`
	FetchGroups     bool                `json:"fetch_groups"`
	MaxDeactivate   int                 `json:"max_deactivate_percent"`
	LastSyncAt      *time.Time          `json:"last_sync_at"`
	LastCreated     int                 `json:"last_created"`
	LastUpdated     int                 `json:"last_updated"`
	LastDeactivated int                 `json:"last_deactivated"`
	LastError       string              `json:"last_error"`
	GroupMap        []map[string]string `json:"group_map"`
}

// addDirectoryRequest registers a source: google by its service account key
// in credentials and an administrator to impersonate, entra by its
// credential JSON, ldap by URL, bind DN and password, base DN and flavour.
type addDirectoryRequest struct {
	Kind           string          `json:"kind"`
	Slug           string          `json:"slug"`
	Name           string          `json:"name"`
	Credentials    json.RawMessage `json:"credentials"`
	Domain         string          `json:"domain"`
	Impersonate    string          `json:"impersonate"`
	Filter         string          `json:"filter"`
	LDAPURL        string          `json:"ldap_url"`
	LDAPBindDN     string          `json:"ldap_bind_dn"`
	LDAPPassword   string          `json:"ldap_password"`
	LDAPBaseDN     string          `json:"ldap_base_dn"`
	LDAPFlavour    string          `json:"ldap_flavour"`
	LDAPCAPEM      string          `json:"ldap_ca_pem"`
	LDAPStartTLS   *bool           `json:"ldap_start_tls"`
	FetchGroups    bool            `json:"fetch_groups"`
	GroupAttribute string          `json:"group_attribute"`
}

// patchDirectoryRequest is `dir set`: what is given changes, the rest is
// kept, so changing one setting never resets the removal ceiling.
type patchDirectoryRequest struct {
	OnMissing      *string `json:"on_missing"`
	MaxDeactivate  *int    `json:"max_deactivate_percent"`
	Enabled        *bool   `json:"enabled"`
	DryRun         *bool   `json:"dry_run"`
	FetchGroups    *bool   `json:"fetch_groups"`
	GroupAttribute *string `json:"group_attribute"`
}

type groupMapRequest struct {
	RemoteGroup string `json:"remote_group"`
	Group       string `json:"group"`
}

const directoryRefusal = "decide which of the organisation's people exist and which groups they are in"

func (s *Server) listDirectories(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := directory.Sources(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing directory sources", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]directoryView, 0, len(got))
	for _, d := range got {
		maps := make([]map[string]string, 0, len(d.Mappings))
		for _, m := range d.Mappings {
			maps = append(maps, map[string]string{"remote_group": m.RemoteGroup, "group": m.Group})
		}
		out = append(out, directoryView{ID: d.ID, Slug: d.Slug, Name: d.Name, Kind: d.Kind, OnMissing: d.OnMissing,
			Enabled: d.Enabled, DryRun: d.DryRun, FetchGroups: d.FetchGroups, MaxDeactivate: d.MaxDeactivate,
			LastSyncAt: d.LastSyncAt, LastCreated: d.LastCreated, LastUpdated: d.LastUpdated,
			LastDeactivated: d.LastDeactivated, LastError: d.LastError, GroupMap: maps})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "sources": out})
}

func (s *Server) addDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addDirectoryRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	startTLS := true
	if req.LDAPStartTLS != nil {
		startTLS = *req.LDAPStartTLS
	}
	spec := directory.SourceSpec{Kind: req.Kind, Slug: req.Slug, Name: strings.TrimSpace(req.Name),
		Credentials: []byte(req.Credentials), Domain: req.Domain, Impersonate: req.Impersonate, Filter: req.Filter,
		LDAPURL: strings.TrimSpace(req.LDAPURL), LDAPBindDN: req.LDAPBindDN, LDAPPassword: req.LDAPPassword,
		LDAPBaseDN: req.LDAPBaseDN, LDAPFlavour: req.LDAPFlavour, LDAPCAPEM: req.LDAPCAPEM, LDAPStartTLS: startTLS,
		FetchGroups: req.FetchGroups, GroupAttribute: req.GroupAttribute}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_source", "detail": err.Error()})
		return
	}
	if spec.Kind == "ldap" && !deploymentWide(w, ctx) {
		return
	}
	if narrowedTokenRefused(w, r, directoryRefusal) {
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
		var err error
		if id, err = directory.AddSource(ctx, tx, s.root, orgID, spec); err != nil {
			return err
		}
		// Never the credentials.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.directory_source_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"source": id, "slug": spec.Slug, "kind": spec.Kind,
				"ldap_url": spec.LDAPURL}})
	})
	if s.writeDirectoryFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	// It starts in dry run, reporting missing people rather than
	// deactivating them.
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "slug": spec.Slug, "kind": spec.Kind, "dry_run": true,
		"config_version": version})
}

func (s *Server) patchDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req patchDirectoryRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	change := directory.SourceChange{OnMissing: req.OnMissing, MaxDeactivate: req.MaxDeactivate,
		Enabled: req.Enabled, DryRun: req.DryRun, FetchGroups: req.FetchGroups, GroupAttribute: req.GroupAttribute}
	if change.Empty() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change"})
		return
	}
	if err := change.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_source", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, directoryRefusal) {
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
		if err := directory.ChangeSource(ctx, tx, orgID, slug, change); err != nil {
			return err
		}
		detail := map[string]any{"slug": slug}
		if req.OnMissing != nil {
			detail["on_missing"] = *req.OnMissing
		}
		if req.MaxDeactivate != nil {
			detail["max_deactivate_percent"] = *req.MaxDeactivate
		}
		if req.Enabled != nil {
			detail["enabled"] = *req.Enabled
		}
		if req.DryRun != nil {
			detail["dry_run"] = *req.DryRun
		}
		if req.FetchGroups != nil {
			detail["fetch_groups"] = *req.FetchGroups
		}
		if req.GroupAttribute != nil {
			detail["group_attribute"] = *req.GroupAttribute
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.directory_source_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeDirectoryFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "config_version": version})
}

func (s *Server) mapDirectoryGroup(w http.ResponseWriter, r *http.Request) {
	var req groupMapRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	s.changeDirectoryGroupMap(w, r, req, true)
}

func (s *Server) unmapDirectoryGroup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.changeDirectoryGroupMap(w, r, groupMapRequest{RemoteGroup: q.Get("remote_group"), Group: q.Get("group")}, false)
}

// changeDirectoryGroupMap says which local group a directory group grants,
// or stops it, as `signari dir group-map` does. A sync grants nothing that is
// not mapped.
func (s *Server) changeDirectoryGroupMap(w http.ResponseWriter, r *http.Request, req groupMapRequest, add bool) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	req.RemoteGroup, req.Group = strings.TrimSpace(req.RemoteGroup), strings.TrimSpace(req.Group)
	if req.RemoteGroup == "" || req.Group == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_mapping",
			"detail": "give remote_group and group"})
		return
	}
	if narrowedTokenRefused(w, r, directoryRefusal) {
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
		detail := map[string]any{"slug": slug, "remote_group": req.RemoteGroup, "group": req.Group}
		if add {
			if err := directory.MapGroup(ctx, tx, orgID, slug, req.RemoteGroup, req.Group); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Event{Type: "admin.directory_group_mapped", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: detail})
		}
		if err := directory.UnmapGroup(ctx, tx, orgID, slug, req.RemoteGroup, req.Group); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.directory_group_unmapped", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeDirectoryFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "remote_group": req.RemoteGroup, "group": req.Group,
		"mapped": add, "config_version": version})
}

// syncDirectory runs one reconciliation, as `signari dir sync` does: with
// apply false, or on a source configured for dry run, it answers the plan and
// writes nothing. A plan past the removal ceiling is refused.
func (s *Server) syncDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var req syncRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	if narrowedTokenRefused(w, r, directoryRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	if err := s.preconditionHoldsNow(ctx, pre); err != nil {
		if !writePreconditionFailure(w, err) {
			s.writeDirectoryFailure(w, err, orgID)
		}
		return
	}
	if !s.orgExists(w, ctx, orgID) {
		return
	}
	report, syncErr := s.directorySync(ctx, s.db, s.root, orgID, slug, req.Apply)
	if errors.Is(syncErr, directory.ErrSourceUnknown) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "source_not_found"})
		return
	}
	out := map[string]any{"slug": slug, "upstream": report.Upstream, "active_before": report.ActiveBefore,
		"plan": report.Plan, "groups": report.Groups, "applied": report.Applied,
		"dry_run_configured": report.DryRunConfigured, "groups_skipped": report.GroupsSkipped}
	version, err := s.mutate(ctx, func(tx pgx.Tx) error {
		detail := map[string]any{"slug": slug, "apply": req.Apply, "applied": report.Applied,
			"upstream": report.Upstream}
		if syncErr != nil {
			detail["error"] = syncErr.Error()
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.directory_synced", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if err != nil {
		s.log.Error("recording a directory sync", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out["config_version"] = version
	switch {
	case errors.Is(syncErr, directory.ErrSyncRefused):
		out["error"], out["error_detail"] = "sync_refused", syncErr.Error()
		writeJSON(w, http.StatusConflict, out)
	case syncErr != nil:
		// The directory would not answer, or part of the pass failed; the
		// source records the error too.
		out["error"], out["error_detail"] = "sync_failed", syncErr.Error()
		writeJSON(w, http.StatusBadGateway, out)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

// writeDirectoryFailure answers a refused or failed directory write, and
// reports whether it wrote anything.
func (s *Server) writeDirectoryFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, directory.ErrSourceInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_source", "detail": err.Error()})
	case errors.Is(err, directory.ErrSourceExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
	case errors.Is(err, directory.ErrSourceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "source_not_found"})
	case errors.Is(err, directory.ErrLocalGroupUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
	case errors.Is(err, directory.ErrMappingUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mapping_not_found"})
	case errors.Is(err, directory.ErrGroupImpersonates):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "group_impersonates", "detail": err.Error()})
	default:
		s.log.Error("writing a directory source", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
