package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// Groups: the unit an operator actually administers.
//
// A group decides which applications a person can reach (`client_group_release`)
// and, through the policy file, what they may do once there. Before this it could
// only be managed from the CLI on the box, which meant any console or automation
// wanting to add somebody to a team needed either a shell or a direct database
// connection -- and ADR-004 exists to make the second impossible.
//
// # may_impersonate is NOT settable here, deliberately
//
// `core.groups.may_impersonate` grants members the ability to act as other
// users. Exposing it on this API would mean a `groups:write` token could grant
// itself impersonation by adding its own operator to a group it just flagged --
// a privilege escalation reachable with the lesser of the two credentials.
//
// It stays a CLI operation, where the person running it is on the host and the
// action is in the shell history. A group created here always has it false, and
// updating a group never changes it. That is a real capability gap against the
// CLI, and it is the correct one to have.

type groupSummary struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	// MayImpersonate is REPORTED so an operator can see which groups carry it,
	// and cannot be SET. Read and write are deliberately asymmetric here.
	MayImpersonate bool   `json:"may_impersonate"`
	CreatedAt      string `json:"created_at"`
}

const groupColumns = `id::text, org_id::text, name, display_name,
	coalesce(description, ''), may_impersonate,
	to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USOF')`

func scanGroup(row pgx.Row, g *groupSummary) error {
	return row.Scan(&g.ID, &g.OrgID, &g.Name, &g.DisplayName, &g.Description,
		&g.MayImpersonate, &g.CreatedAt)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit, cursor := pageParams(r)

	rows, err := s.db.Query(ctx, `
		SELECT `+groupColumns+`
		  FROM core.groups
		 WHERE ($1 = '' OR id::text > $1)
		   AND ($2::uuid IS NULL OR org_id = $2::uuid)
		 ORDER BY id
		 LIMIT $3`, cursor, orgFilter(ctx), limit+1)
	if err != nil {
		s.log.Error("listing groups", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()

	out := make([]groupSummary, 0, limit)
	for rows.Next() {
		var g groupSummary
		if err := scanGroup(rows, &g); err != nil {
			s.log.Error("scanning a group", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing groups", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	s.writeList(w, r, map[string]any{"groups": out, "next_cursor": next})
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := r.PathValue("groupID")
	if err := requireGroup(ctx, groupID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var g groupSummary
	err := scanGroup(s.db.QueryRow(ctx,
		`SELECT `+groupColumns+` FROM core.groups WHERE id = $1::uuid`,
		groupID), &g)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_group_id", "detail": "the group id must be a UUID",
		})
		return
	}
	if err := requireOrg(ctx, g.OrgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	s.writeList(w, r, g)
}

type createGroupRequest struct {
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req createGroupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || req.OrgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing_field", "detail": "org_id and name are required",
		})
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Name
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var id string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		// The boundary, before the insert: a token scoped to one organisation
		// must not create a group in another.
		if err := requireOrg(ctx, req.OrgID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO core.groups (org_id, name, display_name, description)
			VALUES ($1::uuid, $2, $3, nullif($4, ''))
			RETURNING id::text`,
			req.OrgID, req.Name, req.DisplayName, req.Description).Scan(&id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.group_created", AdminTokenID: TokenIDFrom(ctx), OrgID: req.OrgID,
			Detail: map[string]any{"group_id": id, "name": req.Name},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case err != nil && strings.Contains(err.Error(), "groups_org_name"):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "already_exists", "detail": "a group with that name exists in this organisation",
		})
		return
	case err != nil:
		s.log.Error("creating a group", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "config_version": version})
}

type patchGroupRequest struct {
	DisplayName *string `json:"display_name"`
	Description *string `json:"description"`
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := r.PathValue("groupID")
	if err := requireGroup(ctx, groupID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	var req patchGroupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.DisplayName == nil && req.Description == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "nothing_to_change",
			"detail": "no supported field present. may_impersonate is deliberately not " +
				"settable here; it is a CLI operation",
		})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.groups WHERE id = $1::uuid`, groupID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE core.groups
			   SET display_name = coalesce($2, display_name),
			       description  = coalesce($3, description),
			       updated_at   = now()
			 WHERE id = $1::uuid`, groupID, req.DisplayName, req.Description); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.group_updated", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"group_id": groupID},
		})
	})
	s.finishGroupWrite(w, r, groupID, version, err, http.StatusOK,
		map[string]any{"id": groupID, "config_version": version})
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
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

	var members int
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.groups WHERE id = $1::uuid`, groupID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		// Counted before the delete, for the audit record. "How many people lost
		// access" is the question asked afterwards, and the rows are gone by then.
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM core.group_members WHERE group_id = $1::uuid`,
			groupID).Scan(&members); err != nil {
			return err
		}
		// Real deletion, not a flag: ADR-005 refuses soft deletes, because a
		// `deleted_at` column means every access check must remember to exclude it
		// and forgetting once grants access through a group somebody deleted.
		if _, err := tx.Exec(ctx,
			`DELETE FROM core.group_members WHERE group_id = $1::uuid`, groupID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM core.groups WHERE id = $1::uuid`, groupID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.group_deleted", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"group_id": groupID, "members_removed": members},
		})
	})
	s.finishGroupWrite(w, r, groupID, version, err, http.StatusOK,
		map[string]any{"id": groupID, "members_removed": members, "config_version": version})
}

// finishGroupWrite maps the shared error cases for the group write handlers.
//
// One place, so a handler added later cannot answer a precondition failure with
// a 500 by forgetting a case -- which is exactly the drift the route-walking
// tests exist to catch.
func (s *Server) finishGroupWrite(w http.ResponseWriter, r *http.Request, groupID string,
	version int64, err error, okCode int, body map[string]any) {

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
		return
	case err != nil:
		s.log.Error("writing a group", "group_id", groupID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, okCode, body)
}

// Membership.

func (s *Server) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := r.PathValue("groupID")
	// Membership is who reaches which applications. A token restricted to one
	// group must not be able to read another's roster.
	if err := requireGroup(ctx, groupID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	limit, cursor := pageParams(r)

	var orgID string
	if err := s.db.QueryRow(ctx,
		`SELECT org_id::text FROM core.groups WHERE id = $1::uuid`, groupID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_group_id"})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	rows, err := s.db.Query(ctx, `
		SELECT u.id::text, u.org_id::text, coalesce(u.email, ''), coalesce(u.username, ''),
		       u.status, to_char(u.created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
		  FROM core.group_members m
		  JOIN core.users u ON u.id = m.user_id
		 WHERE m.group_id = $1::uuid AND ($2 = '' OR u.id::text > $2)
		 ORDER BY u.id
		 LIMIT $3`, groupID, cursor, limit+1)
	if err != nil {
		s.log.Error("listing group members", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()

	out := make([]userSummary, 0, limit)
	for rows.Next() {
		var u userSummary
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Username, &u.Status,
			&u.CreatedAt); err != nil {
			s.log.Error("scanning a member", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing group members", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	s.writeList(w, r, map[string]any{"members": out, "next_cursor": next})
}

func (s *Server) addGroupMember(w http.ResponseWriter, r *http.Request) {
	s.changeMembership(w, r, true)
}

func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	s.changeMembership(w, r, false)
}

// changeMembership adds or removes one member.
//
// Both directions in one function because the checks are identical and the
// asymmetry that matters -- adding grants access, removing withdraws it -- is
// entirely in the audit record and the SQL. Two functions would be two places to
// forget the organisation check.
func (s *Server) changeMembership(w http.ResponseWriter, r *http.Request, add bool) {
	ctx := r.Context()
	groupID, userID := r.PathValue("groupID"), r.PathValue("userID")
	// Adding somebody to a group grants them whatever that group reaches, so
	// this is the membership check that matters most.
	if err := requireGroup(ctx, groupID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	changed := false
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var groupOrg string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.groups WHERE id = $1::uuid`, groupID).Scan(&groupOrg); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, groupOrg); err != nil {
			return err
		}

		var userOrg string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&userOrg); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		// Both sides, and this is the check that matters. A group in one
		// organisation must not be able to take a member from another: the group
		// decides application access, so a cross-organisation membership is a
		// tenancy breach that looks like an ordinary administrative action.
		if !strings.EqualFold(userOrg, groupOrg) {
			return errCrossOrgMembership
		}

		if add {
			tag, err := tx.Exec(ctx, `
				INSERT INTO core.group_members (group_id, user_id, org_id)
				VALUES ($1::uuid, $2::uuid, $3::uuid)
				ON CONFLICT (group_id, user_id) DO NOTHING`, groupID, userID, groupOrg)
			if err != nil {
				return err
			}
			changed = tag.RowsAffected() > 0
		} else {
			tag, err := tx.Exec(ctx,
				`DELETE FROM core.group_members WHERE group_id = $1::uuid AND user_id = $2::uuid`,
				groupID, userID)
			if err != nil {
				return err
			}
			changed = tag.RowsAffected() > 0
		}

		evt := "admin.group_member_removed"
		if add {
			evt = "admin.group_member_added"
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: evt, AdminTokenID: TokenIDFrom(ctx), OrgID: groupOrg, SubjectID: userID,
			Detail: map[string]any{"group_id": groupID, "changed": changed},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrgMembership):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "cross_organisation_membership",
			"detail": "the user and the group belong to different organisations; a " +
				"group decides application access, so this would cross a tenant boundary",
		})
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "group_or_user_not_found",
		})
		return
	case err != nil:
		s.log.Error("changing group membership", "group_id", groupID, "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	// `changed` distinguishes a real change from a no-op, so an automation loop
	// can tell whether it did anything without diffing before and after.
	writeJSON(w, http.StatusOK, map[string]any{
		"group_id": groupID, "user_id": userID, "member": add,
		"changed": changed, "config_version": version,
	})
}

// errCrossOrgMembership is a user and group in different organisations.
//
// Distinct from errCrossOrg, which is about the TOKEN's reach. This one is about
// the two records, and it is a 400 rather than a 403: the caller may act on both
// organisations and is still asking for something incoherent.
var errCrossOrgMembership = errors.New("the user and the group are in different organisations")
