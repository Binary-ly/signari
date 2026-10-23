package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Provisioning targets (6.07), as `signari scim` and `signari provision`
// manage them: a SCIM server, Google Workspace or Entra ID that this
// deployment writes its people out to. A target's token or credentials are
// sealed and never read back.
//
// Three routes call the target: creating a group there, deleting one, and a
// sync. That call is not made inside the write's transaction, which would
// hold the configuration version's lock for as long as another system takes
// to answer. A precondition is checked before the call instead, and the
// record of what was done is written after it.

type scimTargetView struct {
	ID           string    `json:"id"`
	Slug         string    `json:"slug"`
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	BaseURL      string    `json:"base_url"`
	OnDeactivate string    `json:"on_deactivate"`
	ScopeGroup   string    `json:"scope_group"`
	DryRun       bool      `json:"dry_run"`
	Enabled      bool      `json:"enabled"`
	Linked       int       `json:"linked"`
	ShouldBeGone int       `json:"should_be_gone"`
	CreatedAt    time.Time `json:"created_at"`
}

// addSCIMTargetRequest registers a target: a SCIM one by base_url and the
// token it issued, a google or entra one by its credentials, the JSON file
// its console gave.
type addSCIMTargetRequest struct {
	Kind         string          `json:"kind"`
	Slug         string          `json:"slug"`
	Name         string          `json:"name"`
	BaseURL      string          `json:"base_url"`
	Token        string          `json:"token"`
	Credentials  json.RawMessage `json:"credentials"`
	Impersonate  string          `json:"impersonate"`
	TargetDomain string          `json:"target_domain"`
	OnDeactivate string          `json:"on_deactivate"`
	DryRun       bool            `json:"dry_run"`
}

// patchSCIMTargetRequest changes what is given: enabled, and scope_group,
// the group whose members alone it provisions ("" for everybody).
type patchSCIMTargetRequest struct {
	Enabled    *bool   `json:"enabled"`
	ScopeGroup *string `json:"scope_group"`
}

type syncRequest struct {
	Apply bool `json:"apply"`
}

const scimTargetRefusal = "write the organisation's people out to another system"

func (s *Server) listSCIMTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.SCIMTargets(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing provisioning targets", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]scimTargetView, 0, len(got))
	for _, t := range got {
		out = append(out, scimTargetView{ID: t.ID, Slug: t.Slug, Name: t.Name, Kind: t.Kind, BaseURL: t.BaseURL,
			OnDeactivate: t.OnDeactivate, ScopeGroup: t.ScopeGroup, DryRun: t.DryRun, Enabled: t.Enabled,
			Linked: t.Linked, ShouldBeGone: t.ShouldBeGone, CreatedAt: t.CreatedAt})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "targets": out})
}

func (s *Server) addSCIMTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addSCIMTargetRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	spec := provision.TargetSpec{Kind: req.Kind, Slug: req.Slug, Name: strings.TrimSpace(req.Name),
		BaseURL: strings.TrimSpace(req.BaseURL), Token: req.Token, Credentials: []byte(req.Credentials),
		Impersonate: strings.TrimSpace(req.Impersonate), Domain: strings.TrimSpace(req.TargetDomain),
		OnDeactivate: req.OnDeactivate, DryRun: req.DryRun}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target", "detail": err.Error()})
		return
	}
	// A SCIM target is sent a token that can create and delete accounts, so
	// one inside this engine's own network is refused here, as the dialer
	// would refuse it at the first sync.
	if spec.Kind == "scim" {
		if err := safedial.CheckURL(spec.BaseURL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_url", "detail": err.Error()})
			return
		}
	}
	if narrowedTokenRefused(w, r, scimTargetRefusal) {
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
		if err := provision.AddTarget(ctx, tx, s.root, orgID, spec); err != nil {
			return err
		}
		// Never the token or the credentials.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_target_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"slug": spec.Slug, "kind": spec.Kind, "base_url": spec.BaseURL,
				"on_deactivate": spec.OnDeactivate, "dry_run": spec.DryRun}})
	})
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	// Nothing is sent until it is synced.
	writeJSON(w, http.StatusCreated, map[string]any{"slug": spec.Slug, "kind": spec.Kind, "dry_run": spec.DryRun,
		"config_version": version})
}

func (s *Server) patchSCIMTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req patchSCIMTargetRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	if req.Enabled == nil && req.ScopeGroup == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change",
			"detail": "give enabled, scope_group or both"})
		return
	}
	if narrowedTokenRefused(w, r, scimTargetRefusal) {
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
			if err := store.SetSCIMTargetEnabled(ctx, tx, orgID, slug, *req.Enabled); err != nil {
				return err
			}
			out["enabled"], detail["enabled"] = *req.Enabled, *req.Enabled
		}
		if req.ScopeGroup != nil {
			group := strings.TrimSpace(*req.ScopeGroup)
			if err := store.SetSCIMTargetScope(ctx, tx, orgID, slug, group); err != nil {
				return err
			}
			out["scope_group"], detail["scope_group"] = group, group
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_target_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}

// preconditionHoldsNow checks If-Match before work that runs outside the
// write's transaction, a call to another system. Inside a batch the batch
// checked it, and holds the lock this would wait for.
func (s *Server) preconditionHoldsNow(ctx context.Context, pre precondition) error {
	if _, ok := inBatch(ctx); ok || !pre.present {
		return nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return checkPrecondition(ctx, tx, pre)
}

// orgExists answers for an organisation that does not exist, before work done
// outside a write's transaction; inside one, requireNamedOrg answers it.
func (s *Server) orgExists(w http.ResponseWriter, ctx context.Context, orgID string) bool {
	tx, err := s.db.Begin(ctx)
	if err == nil {
		err = requireNamedOrg(ctx, tx, orgID)
		_ = tx.Rollback(ctx)
	}
	switch {
	case writeOrgRefusal(w, err):
		return false
	case err != nil:
		s.log.Error("reading an organisation", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return false
	}
	return true
}

func (s *Server) provisionSCIMGroup(w http.ResponseWriter, r *http.Request) {
	s.changeSCIMGroup(w, r, true)
}

func (s *Server) deprovisionSCIMGroup(w http.ResponseWriter, r *http.Request) {
	s.changeSCIMGroup(w, r, false)
}

// changeSCIMGroup creates the group the path names at the target, or
// deletes it there, as `signari scim provision-group` and
// `deprovision-group` do. The local group is never touched.
func (s *Server) changeSCIMGroup(w http.ResponseWriter, r *http.Request, create bool) {
	ctx := r.Context()
	orgID, slug, group := r.PathValue("orgID"), r.PathValue("slug"), r.PathValue("group")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	if narrowedTokenRefused(w, r, scimTargetRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	if err := s.preconditionHoldsNow(ctx, pre); err != nil {
		if !writePreconditionFailure(w, err) {
			s.writeSCIMTargetFailure(w, err, orgID)
		}
		return
	}
	if !s.orgExists(w, ctx, orgID) {
		return
	}
	t, err := provision.TargetForGroups(ctx, s.db, s.root, orgID, slug)
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	hc, err := s.targetClient()
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	var remoteID string
	if create {
		remoteID, err = provision.ProvisionGroup(ctx, s.db, t, hc, group)
	} else {
		remoteID, err = provision.DeprovisionGroup(ctx, s.db, t, hc, group)
	}
	if errors.Is(err, provision.ErrGroupProvisioned) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "already_provisioned", "remote_id": remoteID,
			"detail": err.Error()})
		return
	}
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	kind := "admin.scim_group_deprovisioned"
	if create {
		kind = "admin.scim_group_provisioned"
	}
	// Unconditional: the precondition was checked before the call, and what
	// the target did has happened whatever moved since.
	version, err := s.mutate(ctx, func(tx pgx.Tx) error {
		if create {
			return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_group_provisioned",
				AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
				Detail: map[string]any{"slug": slug, "group": group, "remote_id": remoteID}})
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_group_deprovisioned",
			AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"slug": slug, "group": group, "remote_id": remoteID}})
	})
	if err != nil {
		s.log.Error("recording a group change at a target", "org_id", orgID, "event", kind, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "group": group, "remote_id": remoteID,
		"provisioned": create, "config_version": version})
}

// syncSCIMTarget converges the target on who should have an account there,
// as `signari scim sync` does: with apply false it answers what would change
// and sends nothing but the reads a group's members need.
func (s *Server) syncSCIMTarget(w http.ResponseWriter, r *http.Request) {
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
	if narrowedTokenRefused(w, r, scimTargetRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	if err := s.preconditionHoldsNow(ctx, pre); err != nil {
		if !writePreconditionFailure(w, err) {
			s.writeSCIMTargetFailure(w, err, orgID)
		}
		return
	}
	if !s.orgExists(w, ctx, orgID) {
		return
	}
	targets, err := store.LoadSCIMTargets(ctx, s.db, s.root, orgID, slug)
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	if len(targets) == 0 {
		// Only enabled targets load; say which this is.
		_, err := provision.TargetForGroups(ctx, s.db, s.root, orgID, slug)
		if err == nil {
			err = provision.ErrTargetUnknown
		}
		s.writeSCIMTargetFailure(w, err, orgID)
		return
	}
	hc, err := s.targetClient()
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	result, syncErr := provision.Sync(ctx, s.db, targets[0], hc, req.Apply)
	groups := make([]map[string]any, 0, len(result.Groups))
	for _, g := range result.Groups {
		groups = append(groups, map[string]any{"name": g.Name, "add": g.Add, "remove": g.Remove,
			"unreadable": g.Unreadable, "members_synced": g.MembersSynced})
	}
	failures := result.Failures
	if failures == nil {
		failures = []string{}
	}
	out := map[string]any{"slug": slug, "applied": req.Apply, "created": result.Created,
		"deactivated": result.Deactivated, "deleted": result.Deleted, "failed": result.Failed,
		"failures": failures, "groups": groups}
	if syncErr != nil {
		out["error_detail"] = syncErr.Error()
	}
	// Recorded whether or not every change succeeded: what reached the target
	// has happened. Unconditional, as above.
	version, err := s.mutate(ctx, func(tx pgx.Tx) error {
		detail := map[string]any{"slug": slug, "apply": req.Apply, "created": result.Created,
			"deactivated": result.Deactivated, "deleted": result.Deleted, "failed": result.Failed}
		if syncErr != nil {
			detail["error"] = syncErr.Error()
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_target_synced", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if err != nil {
		s.log.Error("recording a sync", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out["config_version"] = version
	status := http.StatusOK
	if syncErr != nil {
		// Part of the pass ran; the answer says how far.
		out["error"] = "sync_incomplete"
		status = http.StatusBadGateway
	}
	writeJSON(w, status, out)
}

// writeSCIMTargetFailure answers a refused or failed target operation, and
// reports whether it wrote anything.
func (s *Server) writeSCIMTargetFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, provision.ErrTargetInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target", "detail": err.Error()})
	case errors.Is(err, provision.ErrTargetExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
	case errors.Is(err, provision.ErrTargetUnknown), errors.Is(err, store.ErrSCIMTargetUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target_not_found"})
	case errors.Is(err, provision.ErrTargetDisabled), errors.Is(err, provision.ErrTargetNotSCIM),
		errors.Is(err, provision.ErrTargetDryRun):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "target_unavailable", "detail": err.Error()})
	case errors.Is(err, provision.ErrGroupUnknown), errors.Is(err, store.ErrScopeGroupUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
	case errors.Is(err, provision.ErrGroupNotProvisioned):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_provisioned"})
	default:
		// A target that would not do as asked is the target's failure, named.
		s.log.Error("operating a provisioning target", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "target_failed", "detail": err.Error()})
	}
	return true
}
