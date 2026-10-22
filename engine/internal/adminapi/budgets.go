package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// An organisation's budget (6.10): tokens its clients may be issued and
// sign-ins its pages may take, a minute. Read by anyone who may read the
// organisation; set by a deployment-wide caller only, since a tenant that set
// its own budget would have none.

type budgetsView struct {
	OrgID            string `json:"org_id"`
	TokensPerMinute  int    `json:"tokens_per_minute"`
	SignInsPerMinute int    `json:"sign_ins_per_minute"`
	// Whether each is the deployment's default rather than the organisation's own.
	TokensDefault  bool `json:"tokens_default"`
	SignInsDefault bool `json:"sign_ins_default"`
}

func viewBudgets(orgID string, b store.OrgBudgets) budgetsView {
	return budgetsView{OrgID: orgID, TokensPerMinute: b.Effective(store.BudgetTokens),
		SignInsPerMinute: b.Effective(store.BudgetSignIns),
		TokensDefault:    b.TokensPerMinute == nil, SignInsDefault: b.SignInsPerMinute == nil}
}

// putBudgetsRequest replaces both budgets; one left out, or null, is the
// deployment's default.
type putBudgetsRequest struct {
	TokensPerMinute  *int `json:"tokens_per_minute"`
	SignInsPerMinute *int `json:"sign_ins_per_minute"`
}

func (s *Server) getBudgets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	b, err := store.BudgetsOf(ctx, s.db, orgID)
	switch {
	case errors.Is(err, store.ErrOrganizationUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization_not_found"})
		return
	case err != nil:
		s.log.Error("reading an organisation's budgets", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, viewBudgets(orgID, b))
}

func (s *Server) putBudgets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putBudgetsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if err := requireOrg(ctx, ""); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_organisation",
			"detail": "only a deployment-wide token may set an organisation's budget"})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	want := store.OrgBudgets{TokensPerMinute: req.TokensPerMinute, SignInsPerMinute: req.SignInsPerMinute}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		was, err := store.BudgetsOf(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if err := store.SetBudgets(ctx, tx, orgID, want); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.organization_budgets_set",
			AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, Detail: map[string]any{
				"tokens_per_minute":   map[string]any{"from": was.TokensPerMinute, "to": want.TokensPerMinute},
				"sign_ins_per_minute": map[string]any{"from": was.SignInsPerMinute, "to": want.SignInsPerMinute},
			}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrOrgBudget):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_budget", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("setting an organisation's budgets", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	v := viewBudgets(orgID, want)
	writeJSON(w, http.StatusOK, map[string]any{"org_id": v.OrgID, "tokens_per_minute": v.TokensPerMinute,
		"sign_ins_per_minute": v.SignInsPerMinute, "tokens_default": v.TokensDefault,
		"sign_ins_default": v.SignInsDefault, "config_version": version})
}
