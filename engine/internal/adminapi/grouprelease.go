package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Which groups an application is told of (6.07), as `signari group release`
// decides it: the `groups` claim is an allow-list, so an application with no
// release is told nothing of the organisation's structure, and one released
// every group is told every group a person is in.

type groupReleaseView struct {
	ClientID string `json:"client_id"`
	// Released is false when the application is told of no group.
	Released bool `json:"released"`
	// OnlyGroups narrows a release to these groups; empty is every group.
	OnlyGroups []string `json:"only_groups"`
}

type putGroupReleaseRequest struct {
	OnlyGroups []string `json:"only_groups"`
}

// errUnknownGroups names groups a release asked for that the organisation
// does not have: released, a typo would tell the application nothing and say
// so to nobody.
type errUnknownGroups struct{ names []string }

func (e errUnknownGroups) Error() string {
	return "no group named " + strings.Join(e.names, ", ") + " in the application's organisation"
}

func (s *Server) getGroupRelease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var orgID string
	err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.clients WHERE client_id = $1`, clientID).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	}
	if err != nil {
		s.log.Error("reading a client's organisation", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	only, released, err := store.GroupReleaseOf(ctx, s.db, clientID)
	if err != nil {
		s.log.Error("reading a group release", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if only == nil {
		only = []string{}
	}
	s.writeList(w, r, groupReleaseView{ClientID: clientID, Released: released, OnlyGroups: only})
}

func (s *Server) putGroupRelease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var req putGroupReleaseRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	only := []string{}
	seen := map[string]bool{}
	for _, g := range req.OnlyGroups {
		if g = strings.TrimSpace(g); g != "" && !seen[g] {
			seen[g] = true
			only = append(only, g)
		}
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		orgID, err := clientOrg(ctx, tx, clientID)
		if err != nil {
			return err
		}
		// A token narrowed to some groups may release those, and not every
		// group, which is the others' too.
		if groupFilter(ctx) != nil && len(only) == 0 {
			return errReleaseEveryGroup
		}
		// Among the groups this token may act on, so one narrowed to some is
		// told of no others, as if they did not exist.
		var missing []string
		if err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(n ORDER BY n), '{}') FROM unnest($2::text[]) n
			WHERE NOT EXISTS (SELECT 1 FROM core.groups g WHERE g.org_id = $1::uuid AND g.name = n
			                    AND ($3::text[] IS NULL OR g.id::text = ANY($3::text[])))`,
			orgID, only, groupFilter(ctx)).Scan(&missing); err != nil {
			return err
		}
		if len(missing) > 0 {
			return errUnknownGroups{missing}
		}
		if err := store.ReleaseGroupsToClient(ctx, tx, orgID, clientID, only); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.group_release_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: clientID, Detail: map[string]any{"only_groups": only, "every_group": len(only) == 0}})
	})
	var unknown errUnknownGroups
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.As(err, &unknown):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_group", "detail": unknown.Error()})
		return
	case errors.Is(err, errReleaseEveryGroup):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_groups",
			"detail": "a token narrowed to some groups may release those, not every group"})
		return
	case err != nil:
		s.log.Error("releasing groups to a client", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"client_id": clientID, "released": true,
		"only_groups": only, "config_version": version})
}

func (s *Server) deleteGroupRelease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		orgID, err := clientOrg(ctx, tx, clientID)
		if err != nil {
			return err
		}
		stopped, err := store.StopGroupRelease(ctx, tx, clientID)
		if err != nil {
			return err
		}
		if !stopped {
			return errReleaseAbsent
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.group_release_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: clientID})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case errors.Is(err, errReleaseAbsent):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_released",
			"detail": "the application is told of no group already"})
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case err != nil:
		s.log.Error("stopping a group release", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}

var (
	errReleaseAbsent     = errors.New("no group release")
	errReleaseEveryGroup = errors.New("a narrowed token releasing every group")
)

// clientOrg is the organisation of an application, read in the transaction
// that changes it, refused when outside the token's.
func clientOrg(ctx context.Context, tx pgx.Tx, clientID string) (string, error) {
	var orgID string
	err := tx.QueryRow(ctx, `SELECT org_id::text FROM core.clients WHERE client_id = $1`, clientID).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errNotFound
	}
	if err != nil {
		return "", err
	}
	return orgID, requireOrg(ctx, orgID)
}
