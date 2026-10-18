package adminapi

import (
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Privileged subjects: the lesser credential must not reach the greater.
//
// A member of a group that may impersonate can act as anyone in their
// organisation. Before this, a token holding only users:write could change such
// a member's e-mail address, remove their factors, set their attributes or
// delete them, and a token holding only groups:write could add its own operator
// to such a group. Each was a way for the lesser credential to become the
// greater one, or to remove it. may_impersonate itself was never settable here
// (see groups.go); membership was, and membership is what grants it.
//
// So a write on a privileged user, or on a group that confers the privilege,
// needs privileged-users:write as well as the route's own scope. "Privileged"
// has one definition, store.PrivilegedUser, which BeginImpersonation also uses
// to refuse impersonating these people.
//
// # What is not covered, and why
//
// Ending sessions stays with users:write. It only withdraws access, and the
// token an incident responder holds must be able to sign a compromised
// administrator out without first finding a more powerful credential.
//
// # Where the check runs
//
// Before the handler and outside its transaction. A concurrent change could
// make the target privileged between the check and the write. Doing that needs
// this scope, though, so the holder of a lesser token cannot use the race.

// privilegedTarget names what a route writes on.
type privilegedTarget int

const (
	// targetUser is the user named by {userID}, or by {subjectID} for erasure.
	targetUser privilegedTarget = iota
	// targetGroup is the group named by {groupID}. Membership routes name a user
	// too, but they are writes on the group: adding an administrator to an
	// ordinary group grants nothing that groups:write does not already decide.
	targetGroup
)

// requirePrivileged refuses a write on a privileged target from a token that
// lacks ScopePrivilegedUsersWrite.
func (s *Server) requirePrivileged(target privilegedTarget, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		p, ok := principalFrom(ctx)
		if !ok {
			// Registered without auth(). Fail closed, as requireOrg does.
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		if p.Can(ScopePrivilegedUsersWrite) {
			next(w, r)
			return
		}

		var id, orgID string
		var privileged, found bool
		var err error
		if target == targetGroup {
			id = r.PathValue("groupID")
			orgID, privileged, found, err = store.PrivilegedGroup(ctx, s.db, id)
		} else {
			id = r.PathValue("userID")
			if id == "" {
				id = r.PathValue("subjectID")
			}
			orgID, privileged, found, err = store.PrivilegedUser(ctx, s.db, id)
		}
		if err != nil {
			s.log.Error("checking whether a target is privileged", "id", id, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		// Not found, or in another organisation: the handler refuses either in
		// its own words. Answering here would tell a token scoped to one tenant
		// which ids in another belong to administrators.
		if !found || !privileged || p.MayActOn(orgID) != nil {
			next(w, r)
			return
		}

		kind := "user"
		if target == targetGroup {
			kind = "group"
		}
		s.log.Info("admin request refused: privileged target", "token", p.Name,
			"method", r.Method, "path", r.URL.Path)
		s.auditRefusal(r, audit.Event{
			Type: "admin.privileged_refused", AdminTokenID: p.TokenID, OrgID: orgID,
			Detail: map[string]any{"target": kind, "id": id, "method": r.Method,
				"route": r.Pattern},
		})
		detail := "this user may impersonate others; changing them needs " +
			ScopePrivilegedUsersWrite
		if target == targetGroup {
			detail = "members of this group may impersonate others; changing it or " +
				"its membership needs " + ScopePrivilegedUsersWrite
		}
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "privileged_target", "detail": detail,
		})
	}
}

// auditRefusal records a refused request in a transaction of its own, because
// a refusal has no write for the record to travel with.
func (s *Server) auditRefusal(r *http.Request, e audit.Event) {
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.log.Error("recording a refusal", "type", e.Type, "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := audit.Write(ctx, tx, e); err != nil {
		s.log.Error("recording a refusal", "type", e.Type, "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("recording a refusal", "type", e.Type, "err", err)
	}
}
