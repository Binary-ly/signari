package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Self-sign-up (6.07), as `signari signup enable|disable` sets it: which
// addresses may make an account themselves, which groups the account joins,
// whether it proves its address first and whether it waits for an
// administrator. Off is no rule, and only invitations and administrators make
// accounts.

type signupView struct {
	OrgID   string `json:"org_id"`
	Enabled bool   `json:"enabled"`
	// AllowedDomains is empty when AnyDomain is true.
	AllowedDomains       []string `json:"allowed_domains"`
	AnyDomain            bool     `json:"any_domain"`
	DefaultGroups        []string `json:"default_groups"`
	RequireVerifiedEmail bool     `json:"require_verified_email"`
	RequireApproval      bool     `json:"require_approval"`
}

// putSignupRequest opens sign-up or replaces its rule. An empty domain list is
// refused unless any_domain asks for every address by name, as `signup enable`
// asks for -domains '*': leaving a field off must not open an organisation to
// the internet.
type putSignupRequest struct {
	AllowedDomains []string `json:"allowed_domains"`
	AnyDomain      bool     `json:"any_domain"`
	DefaultGroups  []string `json:"default_groups"`
	// RequireVerifiedEmail is true unless set false, as the command's default.
	RequireVerifiedEmail *bool `json:"require_verified_email"`
	RequireApproval      bool  `json:"require_approval"`
}

func viewSignup(orgID string, r *store.SignupRule) signupView {
	v := signupView{OrgID: orgID, AllowedDomains: []string{}, DefaultGroups: []string{}}
	if r == nil {
		return v
	}
	v.Enabled, v.AnyDomain = true, len(r.AllowedDomains) == 0
	v.RequireVerifiedEmail, v.RequireApproval = r.RequireVerify, r.RequireApproval
	if r.AllowedDomains != nil {
		v.AllowedDomains = r.AllowedDomains
	}
	if r.DefaultGroups != nil {
		v.DefaultGroups = r.DefaultGroups
	}
	return v
}

func (s *Server) getSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	rule, err := store.LoadSignupRule(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading the sign-up rule", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, viewSignup(orgID, rule))
}

func (s *Server) putSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putSignupRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	domains := cleanList(req.AllowedDomains, true)
	switch {
	case req.AnyDomain && len(domains) > 0:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_rule",
			"detail": "any_domain admits every address; name domains or ask for any, not both"})
		return
	case !req.AnyDomain && len(domains) == 0:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_rule",
			"detail": "name the allowed_domains, or set any_domain to let anyone on the internet make an account"})
		return
	}
	rule := store.SignupRule{OrgID: orgID, AllowedDomains: domains, DefaultGroups: cleanList(req.DefaultGroups, false),
		RequireVerify: req.RequireVerifiedEmail == nil || *req.RequireVerifiedEmail, RequireApproval: req.RequireApproval}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		// The groups an account joins, among those this token may act on: one
		// narrowed to some could otherwise put every newcomer in another.
		var missing []string
		if err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(n ORDER BY n), '{}') FROM unnest($2::text[]) n
			WHERE NOT EXISTS (SELECT 1 FROM core.groups g WHERE g.org_id = $1::uuid AND g.name = n
			                    AND ($3::text[] IS NULL OR g.id::text = ANY($3::text[])))`,
			orgID, rule.DefaultGroups, groupFilter(ctx)).Scan(&missing); err != nil {
			return err
		}
		if len(missing) > 0 {
			return errUnknownGroups{missing}
		}
		if err := store.SetSignupRule(ctx, tx, rule); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.signup_rule_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"allowed_domains": rule.AllowedDomains, "any_domain": req.AnyDomain,
				"default_groups": rule.DefaultGroups, "require_verified_email": rule.RequireVerify,
				"require_approval": rule.RequireApproval}})
	})
	var unknown errUnknownGroups
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.As(err, &unknown):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_group", "detail": unknown.Error()})
		return
	case err != nil:
		s.log.Error("setting the sign-up rule", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	v := viewSignup(orgID, &rule)
	writeJSON(w, http.StatusOK, struct {
		signupView
		ConfigVersion int64 `json:"config_version"`
	}{v, version})
}

func (s *Server) deleteSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		was, err := store.RemoveSignupRule(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if !was {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.signup_rule_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "signup_off",
			"detail": "self-sign-up is already off"})
		return
	case err != nil:
		s.log.Error("closing sign-up", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}

// cleanList trims, drops empties and repeats, and lower-cases when asked.
func cleanList(in []string, lower bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if lower {
			v = strings.ToLower(v)
		}
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
