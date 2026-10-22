package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Invitations over the Admin API (5.18): making one, listing them, revoking
// one. They were the CLI's alone, and the link was printed for the operator to
// pass on by hand; `send` mails it instead, through the outbox, minted as it
// goes out (store.MintInvitationToken), so the API never sees it either.
//
// An invitation that names groups grants their membership to whoever accepts
// it, so it is held to what adding a member is held to: each group must be one
// the token may act on, and a group whose members may impersonate needs
// privileged-users:write.

type createInvitationRequest struct {
	OrgID            string   `json:"org_id"`
	Email            string   `json:"email"`
	Groups           []string `json:"groups"`
	ExpiresInSeconds int      `json:"expires_in_seconds"`
	Send             bool     `json:"send"`
}

type invitationView struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email,omitempty"`
	Groups    []string  `json:"groups"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedBy    string    `json:"used_by,omitempty"`
}

// errInvitationGroup is a named group the token may not grant, with why.
type errInvitationGroup struct {
	status       int
	code, detail string
}

func (e *errInvitationGroup) Error() string { return e.detail }

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req createInvitationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.OrgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing_field", "detail": "org_id is required",
		})
		return
	}
	ttl := time.Duration(req.ExpiresInSeconds) * time.Second
	if req.ExpiresInSeconds < 0 || ttl > store.MaxInvitationTTL {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_field", "detail": "expires_in_seconds is at most 90 days",
		})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	p, _ := principalFrom(ctx)
	var id, token, issuer string
	var expires time.Time
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, req.OrgID); err != nil {
			return err
		}
		// A role delegated over groups invites only into them, and into at
		// least one, so it reaches who it invites (6.01).
		reach := reachFilter(ctx, ScopeUsersWrite)
		if reach != nil && len(req.Groups) == 0 {
			return errDelegatedCreate
		}
		for _, name := range req.Groups {
			var groupID string
			var mayImpersonate bool
			// Among the groups this token may act on, so one narrowed to
			// some is told of no others, as if they did not exist.
			err := tx.QueryRow(ctx, `SELECT id::text, may_impersonate FROM core.groups
				WHERE org_id = $1::uuid AND name = $2
				  AND ($3::text[] IS NULL OR id::text = ANY($3::text[]))`,
				req.OrgID, name, groupFilter(ctx)).Scan(&groupID, &mayImpersonate)
			if errors.Is(err, pgx.ErrNoRows) {
				return &errInvitationGroup{http.StatusBadRequest, "no_such_group",
					"no group named " + name + " in that organisation; the account would be made without it"}
			}
			if err != nil {
				return err
			}
			if reach != nil && !slices.Contains(reach, groupID) {
				return errDelegatedCreate
			}
			if mayImpersonate && !p.Can(ScopePrivilegedUsersWrite) {
				return &errInvitationGroup{http.StatusForbidden, "privileged_target",
					"members of " + name + " may impersonate others; inviting into it needs " +
						ScopePrivilegedUsersWrite}
			}
		}
		var err error
		id, token, expires, err = store.NewInvitation(ctx, tx, store.InvitationSpec{
			OrgID: req.OrgID, Email: req.Email, Groups: req.Groups, TTL: ttl, Send: req.Send,
		})
		if err != nil {
			return err
		}
		// The link is the organisation's own issuer's.
		if err := tx.QueryRow(ctx, `SELECT i.issuer FROM core.organizations o
			JOIN core.instances i ON i.id = o.instance_id WHERE o.id = $1::uuid`, req.OrgID).Scan(&issuer); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.invitation_created", AdminTokenID: TokenIDFrom(ctx), OrgID: req.OrgID,
			Detail: map[string]any{"invitation": id, "bound": strings.TrimSpace(req.Email) != "",
				"groups": req.Groups, "sent": req.Send, "via": "admin_api"},
		})
	})
	var group *errInvitationGroup
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.As(err, &group):
		writeJSON(w, group.status, map[string]string{"error": group.code, "detail": group.detail})
		return
	case errors.Is(err, store.ErrInvitationSendNeedsAddress):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_field", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("creating an invitation", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out := map[string]any{"id": id, "org_id": req.OrgID, "expires_at": expires, "sent": req.Send}
	if token != "" {
		// Once: only its hash is kept.
		out["link"] = strings.TrimRight(issuer, "/") + "/signup?invite=" + token
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit, cursor := pageParams(r)
	rows, err := s.db.Query(ctx, `
		SELECT id::text, org_id::text, COALESCE(email, ''), grant_groups, created_at, expires_at,
		       CASE WHEN used_at IS NOT NULL THEN 'used' WHEN revoked_at IS NOT NULL THEN 'revoked'
		            WHEN expires_at <= now() THEN 'expired' ELSE 'open' END,
		       COALESCE(used_by::text, '')
		  FROM core.invitations
		 WHERE ($1 = '' OR id::text > $1)
		   AND ($2::uuid IS NULL OR org_id = $2::uuid)
		   AND ($4 = '' OR org_id::text = $4)
		   -- A role delegated over groups sees the invitations into them (6.01),
		   -- and a token narrowed to named groups the invitations into those,
		   -- as it may make only those (0.26): it listed every one.
		   AND ($5::uuid[] IS NULL OR EXISTS (SELECT 1 FROM core.groups g
		        WHERE g.id = ANY($5::uuid[]) AND g.org_id = core.invitations.org_id
		          AND g.name = ANY(core.invitations.grant_groups)))
		   AND ($6::uuid[] IS NULL OR EXISTS (SELECT 1 FROM core.groups g
		        WHERE g.id = ANY($6::uuid[]) AND g.org_id = core.invitations.org_id
		          AND g.name = ANY(core.invitations.grant_groups)))
		 ORDER BY id
		 LIMIT $3`, cursor, orgFilter(ctx), limit+1, r.URL.Query().Get("org_id"),
		reachFilter(ctx, ScopeUsersRead), groupFilter(ctx))
	if err != nil {
		s.log.Error("listing invitations", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()
	out := make([]invitationView, 0, limit)
	for rows.Next() {
		var v invitationView
		if err := rows.Scan(&v.ID, &v.OrgID, &v.Email, &v.Groups, &v.CreatedAt, &v.ExpiresAt, &v.State, &v.UsedBy); err != nil {
			s.log.Error("scanning an invitation", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing invitations", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	s.writeList(w, r, map[string]any{"invitations": out, "next_cursor": next})
}

func (s *Server) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("invitationID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx, `SELECT org_id::text FROM core.invitations WHERE id = $1::uuid`, id).
			Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return store.ErrInvitationNotRevocable
			}
			return err
		}
		// Another organisation's invitation answers as one that does not
		// exist: refusing it by name would say it does.
		if err := requireOrg(ctx, orgID); err != nil {
			return store.ErrInvitationNotRevocable
		}
		// Nor one into none of a delegated role's groups (6.01), or of the
		// groups a token is narrowed to (0.26), the invitations each may list.
		for _, groups := range [][]string{reachFilter(ctx, ScopeUsersWrite), groupFilter(ctx)} {
			if groups == nil {
				continue
			}
			var ours bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.invitations i JOIN core.groups g
				  ON g.org_id = i.org_id AND g.name = ANY(i.grant_groups)
				 WHERE i.id = $1::uuid AND g.id = ANY($2::uuid[]))`, id, groups).Scan(&ours); err != nil {
				return err
			}
			if !ours {
				return store.ErrInvitationNotRevocable
			}
		}
		return store.RevokeInvitationIn(ctx, tx, orgID, id, audit.Event{AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"via": "admin_api"}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrInvitationNotRevocable):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found",
			"detail": "no open invitation with that id"})
		return
	case err != nil:
		s.log.Error("revoking an invitation", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	w.WriteHeader(http.StatusNoContent)
}
