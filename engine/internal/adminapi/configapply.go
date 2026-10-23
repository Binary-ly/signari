package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/config"
	"signari.dev/engine/internal/store"
)

// Configuration as code (6.07), as `signari plan` and `signari apply` take a
// file: the groups, clients, SAML providers, RADIUS devices and protected
// hosts it declares are made so, in one transaction, and with prune anything
// of those kinds it does not declare is removed.
//
// A dry run answers the plan and the version it was computed against. An
// apply sent with that version as If-Match is refused if anything changed
// since, so what is applied is what was reviewed.
//
// A signing secret the apply mints, for a provider or a subscription it
// creates, is answered once under "minted". A file naming a secret by
// reference is refused: that is read where `signari apply` runs.

type applyConfigRequest struct {
	Document string `json:"document"`
	Prune    bool   `json:"prune"`
	DryRun   bool   `json:"dry_run"`
}

type configChangeView struct {
	Action      string `json:"action"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Detail      string `json:"detail"`
	Destructive bool   `json:"destructive"`
}

// errConfigScope is a plan that touches what the token's scopes do not cover.
var errConfigScope = errors.New("the plan changes what this token may not")

func (s *Server) applyConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req applyConfigRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	f, err := config.Parse([]byte(req.Document))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_config", "detail": err.Error()})
		return
	}
	if f.Org != "" && f.Org != orgID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "org_mismatch",
			"detail": "the file names organisation " + f.Org + ", not the one in the path"})
		return
	}
	// A secret named by reference is read on the machine the file is applied
	// from. Read here, it would be the server's environment and disk, sent or
	// signed with to a URL the caller chose.
	if refs := f.SecretReferences(); len(refs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret_reference",
			"detail": "the file names a secret by reference (" + strings.Join(refs, ", ") + "), which only " +
				"`signari apply` reads, on the machine it runs on; leave it out and one is minted and returned once"})
		return
	}
	if narrowedTokenRefused(w, r, "apply a configuration covering every application and group in the organisation") {
		return
	}
	if req.DryRun {
		s.planConfig(w, r, orgID, f, req.Prune)
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var plan *config.Plan
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if plan, err = config.BuildPlanWith(ctx, tx, orgID, f, req.Prune, config.Options{Root: s.root}); errors.Is(err,
			config.ErrRefused) {
			return fmt.Errorf("%w: %w", errConfigRefused, err)
		} else if err != nil {
			return err
		}
		if err := mayApply(ctx, tx, orgID, plan); err != nil {
			return err
		}
		if plan.Empty() {
			// Rolled back, so a file already in force moves no version and
			// breaks nobody's If-Match.
			return errNothingToApply
		}
		if err := config.Apply(ctx, tx, orgID, f, plan); err != nil {
			return fmt.Errorf("%w: %w", errConfigRefused, err)
		}
		create, update, del := plan.Counts()
		return audit.Write(ctx, tx, audit.Event{Type: "admin.config_applied", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"created": create, "updated": update, "deleted": del,
				"prune": req.Prune}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errConfigScope):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope", "detail": err.Error()})
		return
	case errors.Is(err, errConfigRefused):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config_refused", "detail": err.Error()})
		return
	case errors.Is(err, errNothingToApply):
		if version, err = store.CurrentConfigVersion(ctx, s.db); err == nil {
			setETag(w, version)
			writeJSON(w, http.StatusOK, planAnswer(plan, false, version))
			return
		}
		fallthrough
	case err != nil:
		s.log.Error("applying a configuration", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, planAnswer(plan, false, version))
}

// errNothingToApply is a file the deployment already matches.
var errNothingToApply = errors.New("the deployment already matches the file")

// errConfigRefused is a plan the configuration layer would not carry out:
// a client another organisation registered, a scope nobody declared.
var errConfigRefused = errors.New("the configuration was not applied")

// planConfig answers what an apply would change, writing nothing.
func (s *Server) planConfig(w http.ResponseWriter, r *http.Request, orgID string, f *config.File, prune bool) {
	ctx := r.Context()
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.log.Error("planning a configuration", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The version first, in the same snapshot as the plan: an apply sent with
	// it as If-Match fails if anything moved after this read.
	version, err := store.CurrentConfigVersion(ctx, tx)
	if err == nil {
		err = requireNamedOrg(ctx, tx, orgID)
	}
	var plan *config.Plan
	if err == nil {
		plan, err = config.BuildPlanWith(ctx, tx, orgID, f, prune, config.Options{Root: s.root})
	}
	switch {
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, config.ErrRefused):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config_refused", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("planning a configuration", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, planAnswer(plan, true, version))
}

func planAnswer(plan *config.Plan, dryRun bool, version int64) map[string]any {
	changes := make([]configChangeView, 0, len(plan.Changes))
	for _, c := range plan.Changes {
		changes = append(changes, configChangeView{Action: c.Action, Kind: c.Kind, Name: c.Name, Detail: c.Detail,
			Destructive: c.Destructive})
	}
	create, update, del := plan.Counts()
	out := map[string]any{"dry_run": dryRun, "changes": changes, "create": create, "update": update, "delete": del,
		"config_version": version}
	// The secrets the apply minted, the one time they are shown, as the
	// routes that register a provider or a subscription return theirs.
	if len(plan.Minted) > 0 {
		minted := make([]mintedSecretView, 0, len(plan.Minted))
		for _, m := range plan.Minted {
			minted = append(minted, mintedSecretView{Kind: m.Kind, Name: m.Name, Secret: m.Secret})
		}
		out["minted"] = minted
	}
	return out
}

type mintedSecretView struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// mayApply refuses a plan reaching past the token: clients need clients:write,
// groups groups:write, and the application administrators sign in to the
// Admin API through, or a group whose members may impersonate, needs
// privileged-users:write, as the routes that change them one at a time do.
func mayApply(ctx context.Context, tx pgx.Tx, orgID string, plan *config.Plan) error {
	p, ok := principalFrom(ctx)
	if !ok {
		return errConfigScope
	}
	for _, c := range plan.Changes {
		switch c.Kind {
		case "client":
			if !p.Can(ScopeClientsWrite) {
				return fmt.Errorf("%w: client %s needs %s", errConfigScope, c.Name, ScopeClientsWrite)
			}
			_, privileged, _, err := store.PrivilegedClient(ctx, tx, c.Name)
			if err != nil {
				return err
			}
			if privileged && !p.Can(ScopePrivilegedUsersWrite) {
				return fmt.Errorf("%w: client %s is where administrators sign in to the Admin API, and "+
					"changing it needs %s", errConfigScope, c.Name, ScopePrivilegedUsersWrite)
			}
		case "group":
			if !p.Can(ScopeGroupsWrite) {
				return fmt.Errorf("%w: group %s needs %s", errConfigScope, c.Name, ScopeGroupsWrite)
			}
			privileged, err := store.GroupMayImpersonate(ctx, tx, orgID, c.Name)
			if err != nil {
				return err
			}
			if privileged && !p.Can(ScopePrivilegedUsersWrite) {
				return fmt.Errorf("%w: members of group %s may impersonate others, and changing it needs %s",
					errConfigScope, c.Name, ScopePrivilegedUsersWrite)
			}
		}
	}
	return nil
}
