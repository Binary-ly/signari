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
	"signari.dev/engine/internal/scim"
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
	ID              string   `json:"id"`
	Slug            string   `json:"slug"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	BaseURL         string   `json:"base_url"`
	OnDeactivate    string   `json:"on_deactivate"`
	ScopeGroups     []string `json:"scope_groups"`
	DryRun          bool     `json:"dry_run"`
	Enabled         bool     `json:"enabled"`
	RecreateMissing bool     `json:"recreate_missing"`
	OAuthTokenURL   string   `json:"oauth_token_url"`
	OAuthClientID   string   `json:"oauth_client_id"`
	OAuthScope      string   `json:"oauth_scope"`
	OAuthClientAuth string   `json:"oauth_client_auth"`
	// OAuthGrant is client_credentials, authorization_code, or "" for a bearer
	// token; OAuthAuthorizeURL is where somebody signs in for the second, and
	// OAuthAuthorizedAt when somebody last did, null until then.
	OAuthGrant        string     `json:"oauth_grant"`
	OAuthAuthorizeURL string     `json:"oauth_authorize_url"`
	OAuthAuthorizedAt *time.Time `json:"oauth_authorized_at"`
	Compatibility     []string   `json:"compatibility"`
	Linked            int        `json:"linked"`
	ShouldBeGone      int        `json:"should_be_gone"`
	CreatedAt         time.Time  `json:"created_at"`
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
	// RecreateMissing is whether a sync gives somebody a new account when the
	// one linked to them is gone from the target.
	RecreateMissing bool `json:"recreate_missing"`
	// OAuthTokenURL and OAuthClientID have it authenticate by the client
	// credentials grant, token then being the client's secret.
	OAuthTokenURL string `json:"oauth_token_url"`
	OAuthClientID string `json:"oauth_client_id"`
	OAuthScope    string `json:"oauth_scope"`
	// OAuthClientAuth is client_secret_basic, the default, or client_secret_post
	// for a token endpoint that takes the secret only in the form.
	OAuthClientAuth string `json:"oauth_client_auth"`
	// OAuthAuthorizeURL has it take the authorization code grant from that client
	// instead: somebody signs in there before its first sync.
	OAuthAuthorizeURL string `json:"oauth_authorize_url"`
	// Compatibility names what it needs that the protocol does not say it should.
	Compatibility []string `json:"compatibility"`
}

// startSCIMAuthorizationRequest names where the target sends the person back.
type startSCIMAuthorizationRequest struct {
	RedirectURI string `json:"redirect_uri"`
}

// finishSCIMAuthorizationRequest is what the target sent back to that address.
type finishSCIMAuthorizationRequest struct {
	State string `json:"state"`
	Code  string `json:"code"`
}

// patchSCIMTargetRequest changes what is given: enabled, recreate_missing,
// compatibility, and scope_groups, the groups whose members alone it provisions
// ([] for everybody).
type patchSCIMTargetRequest struct {
	Enabled         *bool    `json:"enabled"`
	ScopeGroups     []string `json:"scope_groups"`
	RecreateMissing *bool    `json:"recreate_missing"`
	Compatibility   []string `json:"compatibility"`
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
			OnDeactivate: t.OnDeactivate, ScopeGroups: t.ScopeGroups, DryRun: t.DryRun, Enabled: t.Enabled,
			RecreateMissing: t.RecreateMissing, OAuthTokenURL: t.OAuthTokenURL, OAuthClientID: t.OAuthClientID,
			OAuthScope: t.OAuthScope, OAuthClientAuth: t.OAuthClientAuth, OAuthGrant: t.OAuthGrant(),
			OAuthAuthorizeURL: t.OAuthAuthorizeURL, OAuthAuthorizedAt: t.OAuthAuthorizedAt,
			Compatibility: t.Compatibility, Linked: t.Linked, ShouldBeGone: t.ShouldBeGone, CreatedAt: t.CreatedAt})
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
		OnDeactivate: req.OnDeactivate, DryRun: req.DryRun, RecreateMissing: req.RecreateMissing,
		OAuthTokenURL: strings.TrimSpace(req.OAuthTokenURL), OAuthClientID: strings.TrimSpace(req.OAuthClientID),
		OAuthScope: strings.TrimSpace(req.OAuthScope), OAuthClientAuth: strings.TrimSpace(req.OAuthClientAuth),
		OAuthAuthorizeURL: strings.TrimSpace(req.OAuthAuthorizeURL), Compatibility: req.Compatibility}
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
		// The client secret goes to the token URL, so it is held to the same.
		if spec.OAuthTokenURL != "" {
			if err := safedial.CheckURL(spec.OAuthTokenURL); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_url", "detail": err.Error()})
				return
			}
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
				"on_deactivate": spec.OnDeactivate, "dry_run": spec.DryRun, "recreate_missing": spec.RecreateMissing,
				"oauth_token_url": spec.OAuthTokenURL, "oauth_authorize_url": spec.OAuthAuthorizeURL}})
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
	if req.Enabled == nil && req.ScopeGroups == nil && req.RecreateMissing == nil && req.Compatibility == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change",
			"detail": "give enabled, scope_groups, recreate_missing or compatibility"})
		return
	}
	if err := scim.CheckCompatibility(req.Compatibility); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target", "detail": err.Error()})
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
		if req.ScopeGroups != nil {
			if err := store.SetSCIMTargetScope(ctx, tx, orgID, slug, req.ScopeGroups); err != nil {
				return err
			}
			out["scope_groups"], detail["scope_groups"] = req.ScopeGroups, req.ScopeGroups
		}
		if req.RecreateMissing != nil {
			if err := store.SetSCIMTargetRecreate(ctx, tx, orgID, slug, *req.RecreateMissing); err != nil {
				return err
			}
			out["recreate_missing"], detail["recreate_missing"] = *req.RecreateMissing, *req.RecreateMissing
		}
		if req.Compatibility != nil {
			if err := store.SetSCIMTargetCompatibility(ctx, tx, orgID, slug, req.Compatibility); err != nil {
				return err
			}
			out["compatibility"], detail["compatibility"] = req.Compatibility, req.Compatibility
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
		"recreated": result.Recreated, "deactivated": result.Deactivated, "deleted": result.Deleted,
		"failed": result.Failed, "failures": failures, "groups": groups}
	if syncErr != nil {
		out["error_detail"] = syncErr.Error()
	}
	// Recorded whether or not every change succeeded: what reached the target
	// has happened. Unconditional, as above.
	version, err := s.mutate(ctx, func(tx pgx.Tx) error {
		detail := map[string]any{"slug": slug, "apply": req.Apply, "created": result.Created,
			"recreated": result.Recreated, "deactivated": result.Deactivated, "deleted": result.Deleted,
			"failed": result.Failed}
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

// startSCIMAuthorization starts an authorization of a target that takes the
// authorization code grant, as `signari scim authorize` does: it answers where to
// send the person and the state their code comes back with, which the caller
// holds so it can tell its own redirect from somebody else's.
func (s *Server) startSCIMAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var req startSCIMAuthorizationRequest
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
	var started provision.Authorization
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if started, err = provision.BeginAuthorization(ctx, tx, s.root, orgID, slug,
			strings.TrimSpace(req.RedirectURI)); err != nil {
			return err
		}
		// Never the state: with a code it is what a refresh token is issued for.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_target_authorization_started",
			AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"slug": slug, "redirect_uri": strings.TrimSpace(req.RedirectURI),
				"expires_at": started.Until}})
	})
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"slug": slug, "authorization_url": started.URL,
		"state": started.State, "expires_at": started.Until, "config_version": version})
}

// finishSCIMAuthorization redeems the code a sign-in at the target sent back, and
// keeps the refresh token it was issued. The token endpoint is called outside the
// write's transaction, so If-Match is checked before the call and the token kept
// after it, as a sync does.
func (s *Server) finishSCIMAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var req finishSCIMAuthorizationRequest
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
	hc, err := s.targetClient()
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	grant, err := provision.ExchangeAuthorization(ctx, s.db, s.root, hc, orgID, slug, req.State, req.Code)
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	var at time.Time
	// Unconditional: the code is spent, and the token it was issued is the only one.
	version, err := s.mutate(ctx, func(tx pgx.Tx) error {
		var err error
		if at, err = grant.Keep(ctx, tx); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.scim_target_authorized", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"slug": slug}})
	})
	if s.writeSCIMTargetFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "authorized_at": at, "config_version": version})
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
	case errors.Is(err, provision.ErrTargetDisabled), errors.Is(err, provision.ErrTargetDryRun):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "target_unavailable", "detail": err.Error()})
	case errors.Is(err, provision.ErrGroupUnknown), errors.Is(err, store.ErrScopeGroupUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
	case errors.Is(err, provision.ErrGroupNotProvisioned):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_provisioned"})
	case errors.Is(err, store.ErrSCIMAuthorizationUnknown):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization_unknown", "detail": err.Error()})
	case errors.Is(err, store.ErrSCIMGrantChanged):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "grant_changed", "detail": err.Error()})
	default:
		// A target that would not do as asked is the target's failure, named.
		s.log.Error("operating a provisioning target", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "target_failed", "detail": err.Error()})
	}
	return true
}
