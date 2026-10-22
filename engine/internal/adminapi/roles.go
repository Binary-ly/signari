package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Administrative roles (6.01). A role is a named set of the scopes a stored
// token names, so it grants nothing a token could not already be given, and
// every check in this package applies to it unchanged. A binding (0191) gives
// one to a person or an application in one organisation, and is read on each
// of their requests, never carried in a token: removing one refuses the next
// request (ADR-007).
//
// A user-manager binding may name a group, and then reaches only that group's
// members (delegated administration). The narrowing is per scope: someone who
// is also an auditor reads everyone and changes only the group's members.
var Roles = map[string][]string{
	// Everything a stored token may hold, in the one organisation. Not
	// ScopeAll: creating organisations and suspending one stay with an
	// unscoped token, since a tenant that can do either has left its tenancy.
	"org-owner": {ScopeUsersWrite, ScopeClientsWrite, ScopeGroupsWrite, ScopeConfigRead,
		ScopeSubjectsErase, ScopeSubjectsExport, ScopeOrganizationsWrite, ScopeAuditRead,
		ScopePrivilegedUsersWrite, ScopeTokensWrite},
	// People: accounts, factors, sessions, consents, attributes, invitations.
	// Not their groups, which decide what applications they reach (groups:*).
	"user-manager": {ScopeUsersWrite},
	// Applications, and the organisation's configuration they are read with.
	"app-manager": {ScopeClientsWrite, ScopeConfigRead},
	// Every read, and the trail.
	"auditor": {ScopeUsersRead, ScopeClientsRead, ScopeGroupsRead, ScopeConfigRead,
		ScopeAuditRead, ScopeTokensRead},
}

// roleScopes is a role's scopes with the reads its writes imply, so a
// narrowing on users:write narrows the users:read it carries too: otherwise a
// user manager delegated over one group would read every person.
func roleScopes(role string) []string {
	var out []string
	for _, s := range Roles[role] {
		out = append(out, s)
		for read, write := range impliedBy {
			if write == s {
				out = append(out, read)
			}
		}
	}
	return out
}

// rolePrincipal is the principal a person or an application acts as: the
// union of its bindings' scopes, narrowed to the members of its groups for
// each scope only delegated bindings grant.
func rolePrincipal(name, orgID string, bindings []store.RoleBinding, expires *time.Time) *Principal {
	orgWide := map[string]bool{}
	delegated := map[string][]string{}
	for _, b := range bindings {
		for _, sc := range roleScopes(b.Role) {
			if b.GroupID == "" {
				orgWide[sc] = true
			} else {
				delegated[sc] = append(delegated[sc], b.GroupID)
			}
		}
	}
	p := &Principal{Name: name, OrgID: orgID, ExpiresAt: expires}
	for sc := range orgWide {
		p.Scopes = append(p.Scopes, sc)
	}
	for sc, groups := range delegated {
		if orgWide[sc] {
			continue
		}
		p.Scopes = append(p.Scopes, sc)
		if p.UserGroups == nil {
			p.UserGroups = map[string][]string{}
		}
		p.UserGroups[sc] = groups
	}
	sort.Strings(p.Scopes)
	return p
}

// grantable reports whether p may give or take away role: only a principal
// that holds every scope of it, over everything the role reaches, may. A
// token that could grant a role wider than itself would be every scope the
// role names, the rule 6.04 holds a minted token to.
func grantable(p *Principal, role string) error {
	for _, sc := range roleScopes(role) {
		switch {
		case !p.Can(sc):
			return fmt.Errorf("the %s role includes %s, which this caller does not hold", role, sc)
		case p.UserGroups[sc] != nil:
			return fmt.Errorf("the %s role reaches every member of the organisation with %s, and this "+
				"caller reaches only some", role, sc)
		case (sc == ScopeClientsRead || sc == ScopeClientsWrite) && p.ClientIDs != nil:
			return fmt.Errorf("the %s role reaches every application, and this caller only some", role)
		case (sc == ScopeGroupsRead || sc == ScopeGroupsWrite) && p.GroupIDs != nil:
			return fmt.Errorf("the %s role reaches every group, and this caller only some", role)
		}
	}
	return nil
}

// roleBindingView is a binding as the API shows it.
type roleBindingView struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	Role      string `json:"role"`
	UserID    string `json:"user_id,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	GroupID   string `json:"group_id,omitempty"`
	CreatedAt string `json:"created_at"`
}

func bindingView(b store.RoleBinding) roleBindingView {
	return roleBindingView{ID: b.ID, OrgID: b.OrgID, Role: b.Role, UserID: b.UserID,
		ClientID: b.ClientID, GroupID: b.GroupID, CreatedAt: b.CreatedAt}
}

type grantRoleRequest struct {
	Role     string `json:"role"`
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	GroupID  string `json:"group_id"`
}

func (s *Server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	bindings, err := store.RoleBindings(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing role bindings", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]roleBindingView, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, bindingView(b))
	}
	s.writeList(w, r, map[string]any{"role_bindings": out})
}

func (s *Server) grantRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	p, _ := principalFrom(ctx)
	var req grantRoleRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if _, known := Roles[req.Role]; !known {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_role",
			"detail": fmt.Sprintf("a role is one of %s", roleNames())})
		return
	}
	if err := grantable(p, req.Role); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wider_than_caller", "detail": err.Error()})
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
		if id, err = store.GrantRole(ctx, tx, store.RoleBinding{OrgID: orgID, Role: req.Role,
			UserID: req.UserID, ClientID: req.ClientID, GroupID: req.GroupID}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.role_granted", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			SubjectID: req.UserID, ClientID: req.ClientID,
			Detail: map[string]any{"binding_id": id, "role": req.Role, "group_id": req.GroupID},
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrRoleSubject), errors.Is(err, store.ErrRoleNotDelegated):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrRoleSubjectElsewhere):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrRoleHeld):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("granting a role", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "config_version": version})
}

func (s *Server) revokeRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	bindingID := r.PathValue("bindingID")
	p, _ := principalFrom(ctx)
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		// Held to the role it takes away as to one it gives: a narrow token
		// that could remove an owner's binding could lock the owner out.
		b, err := store.RoleBindingOf(ctx, tx, orgID, bindingID)
		if err != nil {
			return err
		}
		if err := grantable(p, b.Role); err != nil {
			return &widerError{err}
		}
		if _, err := store.RevokeRole(ctx, tx, orgID, bindingID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.role_revoked", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			SubjectID: b.UserID, ClientID: b.ClientID,
			Detail: map[string]any{"binding_id": b.ID, "role": b.Role, "group_id": b.GroupID},
		})
	})
	var wide *widerError
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.As(err, &wide):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wider_than_caller", "detail": wide.Error()})
		return
	case errors.Is(err, store.ErrRoleBindingUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	case err != nil:
		s.log.Error("revoking a role", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}

func roleNames() []string {
	out := make([]string, 0, len(Roles))
	for r := range Roles {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
