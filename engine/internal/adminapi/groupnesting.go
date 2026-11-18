package adminapi

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Groups inside groups (11.09). PUT /admin/groups/{groupID}/member-groups/{memberGroupID}
// makes the second a member of the first, so everybody in it is in that group and every
// group above it, as PUT .../members/{userID} makes a person one. {groupID} is the group
// whose membership changes, so the privileged-target check falls on it, and on whatever
// it is inside: a group inside one that may impersonate needs privileged-users:write to
// gain members by either route.
//
// # Only an organisation-wide caller
//
// A nesting changes who is in every group above it, which reaches people the caller
// never names: a token narrowed to some groups would hand their members to a group it
// cannot see, and a role delegated over a group reaches whoever is in it, so a nesting
// would widen the reach of every delegate over the groups above. So a token limited to
// named applications, groups or attributes, and a person whose groups:write comes from a
// delegated role, are refused both directions, and nobody's reach grows except by an
// organisation-wide decision.

type memberGroupView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	AddedAt string `json:"added_at"`
}

func (s *Server) listMemberGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := r.PathValue("groupID")
	if err := requireGroup(ctx, groupID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var orgID string
	if err := s.db.QueryRow(ctx,
		`SELECT org_id::text FROM core.groups WHERE id = $1::uuid`, groupID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
			return
		}
		s.log.Error("reading a group", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	// Made by hand, one at a time, so there are few: the list is whole, in the
	// index's order, and a token narrowed to some groups sees only those.
	rows, err := s.db.Query(ctx, `
		SELECT c.id::text, c.name, to_char(n.added_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM')
		  FROM core.group_parents n
		  JOIN core.groups c ON c.id = n.group_id
		 WHERE n.parent_id = $1::uuid AND ($2::text[] IS NULL OR c.id::text = ANY($2::text[]))
		 ORDER BY n.parent_id, n.group_id`, groupID, groupFilter(ctx))
	if err != nil {
		s.log.Error("listing member groups", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (memberGroupView, error) {
		var v memberGroupView
		err := row.Scan(&v.ID, &v.Name, &v.AddedAt)
		return v, err
	})
	if err != nil {
		s.log.Error("listing member groups", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if out == nil {
		out = []memberGroupView{}
	}
	s.writeList(w, r, map[string]any{"member_groups": out})
}

func (s *Server) addMemberGroup(w http.ResponseWriter, r *http.Request) {
	s.changeNesting(w, r, true)
}

func (s *Server) removeMemberGroup(w http.ResponseWriter, r *http.Request) {
	s.changeNesting(w, r, false)
}

// changeNesting puts {memberGroupID} inside {groupID}, or takes it out.
func (s *Server) changeNesting(w http.ResponseWriter, r *http.Request, add bool) {
	ctx := r.Context()
	parentID, groupID := r.PathValue("groupID"), r.PathValue("memberGroupID")
	if narrowedTokenRefused(w, r, "nest groups: a nesting changes who is in every group above it, "+
		"which reaches people the token does not name") {
		return
	}
	if p, ok := principalFrom(ctx); !ok || len(p.UserGroups) > 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_objects",
			"detail": "a role delegated over groups cannot nest groups: a nesting widens the reach of " +
				"every role delegated over the groups above it"})
		return
	}
	// Both groups, as every handler naming a group asks, though a token narrowed
	// to any has already been refused above.
	for _, id := range []string{parentID, groupID} {
		if err := requireGroup(ctx, id); err != nil {
			writeCrossOrg(w, err)
			return
		}
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	changed := false
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		orgs := map[string]string{}
		for _, id := range []string{parentID, groupID} {
			var org string
			if err := tx.QueryRow(ctx, `SELECT org_id::text FROM core.groups WHERE id = $1::uuid`, id).Scan(&org); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return errNotFound
				}
				return err
			}
			if err := requireOrg(ctx, org); err != nil {
				return err
			}
			orgs[id] = org
		}
		if orgs[parentID] != orgs[groupID] {
			return errCrossOrgMembership
		}
		var err error
		if add {
			changed, err = store.NestGroup(ctx, tx, orgs[parentID], groupID, parentID, "")
		} else {
			changed, err = store.UnnestGroup(ctx, tx, orgs[parentID], groupID, parentID)
		}
		if err != nil {
			return err
		}
		evt := "admin.group_unnested"
		if add {
			evt = "admin.group_nested"
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: evt, AdminTokenID: TokenIDFrom(ctx), OrgID: orgs[parentID],
			Detail: map[string]any{"group_id": parentID, "member_group_id": groupID, "changed": changed},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrNestingLoop):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "nesting_loop",
			"detail": "the group is already above the one it would be put in, or is that group, " +
				"so this would put a group inside itself"})
		return
	case errors.Is(err, errCrossOrgMembership):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cross_organisation_membership",
			"detail": "the two groups belong to different organisations; a group decides application " +
				"access, so this would cross a tenant boundary"})
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound), errors.Is(err, store.ErrNestingGroupUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group_not_found"})
		return
	case err != nil:
		s.log.Error("changing a nesting", "group_id", parentID, "member_group_id", groupID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"group_id": parentID, "member_group_id": groupID, "member": add,
		"changed": changed, "config_version": version,
	})
}
