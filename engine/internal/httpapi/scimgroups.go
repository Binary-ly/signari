package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// handleSCIMGroups is the collection: list, filter and create.
func (s *Server) handleSCIMGroups(w http.ResponseWriter, r *http.Request) {
	src, err := s.scimAuth(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.scimListGroups(w, r, src)
	case http.MethodPost:
		s.scimCreateGroup(w, r, src)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request, src *store.SCIMSource) {
	q := r.URL.Query()

	// startIndex is ONE-based in SCIM, as it is for /Users.
	start := 1
	if v := q.Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			start = n
		}
	}
	count := scimDefaultPageSize
	if v := q.Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			// RFC 7644 §3.4.2.4, Table 6: "A negative value SHALL be interpreted
			// as \"0\"", and "A value of \"0\" indicates that no resource results
			// are to be returned except for \"totalResults\"".
			//
			// This used to require n >= 0 to assign, so a negative count fell
			// through to the DEFAULT page size -- a client asking for nothing was
			// sent a hundred records. Wrong in the direction that returns more
			// data than was asked for, which is the wrong direction for a
			// provisioning API to be wrong in.
			if n < 0 {
				n = 0
			}
			count = n
		}
	}
	if count > scimMaxPageSize {
		count = scimMaxPageSize
	}

	displayName, err := scim.ParseDisplayNameFilter(q.Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return
	}

	groups, total, err := store.ListSCIMGroups(r.Context(), s.db, src, displayName, start, count)
	if err != nil {
		s.log.Error("listing SCIM groups", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "unavailable")
		return
	}
	resources := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		resources = append(resources, scimGroupResource(g))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"itemsPerPage": len(resources),
		"startIndex":   start,
		"Resources":    resources,
	})
}

// inboundGroup is a SCIM Group as an upstream sends it.
type inboundGroup struct {
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
	// rawMembers distinguishes "no members key" from "members: []". A create
	// with no members says nothing about membership; one with an empty list says
	// there is none, and collapsing them makes an emptied group un-emptiable.
	rawMembers json.RawMessage
}

func (g *inboundGroup) memberIDs() []string {
	if g.rawMembers == nil {
		return nil
	}
	out := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		if m.Value != "" {
			out = append(out, m.Value)
		}
	}
	return out
}

func decodeInboundGroup(w http.ResponseWriter, r *http.Request) (*inboundGroup, error) {
	var probe map[string]json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&probe); err != nil {
		return nil, err
	}
	blob, err := json.Marshal(probe)
	if err != nil {
		return nil, err
	}
	var g inboundGroup
	if err := json.Unmarshal(blob, &g); err != nil {
		return nil, err
	}
	g.rawMembers = probe["members"]
	return &g, nil
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request, src *store.SCIMSource) {
	ctx := r.Context()
	in, err := decodeInboundGroup(w, r)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "body is not SCIM JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required")
		return
	}
	// externalId is the only thing matched on, for the same reason as users: a
	// rename must not look like a deletion plus a creation, which would revoke
	// everything the group granted.
	if strings.TrimSpace(in.ExternalID) == "" {
		writeSCIMError(w, http.StatusBadRequest,
			"externalId is required: it is the only identifier stable across a "+
				"rename, and matching on displayName instead turns renaming a group "+
				"into revoking everything it granted")
		return
	}

	g, err := store.UpsertSCIMGroup(ctx, s.db, src, in.ExternalID, in.DisplayName, in.memberIDs())
	if err != nil {
		s.writeSCIMGroupError(w, err, "creating a SCIM group")
		return
	}
	s.auditDetached(ctx, audit.Event{
		Type: "scim.group_provisioned", OrgID: src.OrgID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{"source": src.Slug, "external_id": g.ExternalID,
			"group": g.Name, "members": len(g.Members)},
	})
	writeSCIM(w, http.StatusCreated, scimGroupResource(g))
}

// handleSCIMGroup is one resource: get, replace, patch and delete.
func (s *Server) handleSCIMGroup(w http.ResponseWriter, r *http.Request) {
	src, err := s.scimAuth(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeSCIMError(w, http.StatusNotFound, "no such group")
		return
	}
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		g, gerr := store.GetSCIMGroup(ctx, s.db, src, id)
		if gerr != nil {
			writeSCIMError(w, http.StatusNotFound, "no such group")
			return
		}
		writeSCIM(w, http.StatusOK, scimGroupResource(g))

	case http.MethodPut:
		in, derr := decodeInboundGroup(w, r)
		if derr != nil {
			writeSCIMError(w, http.StatusBadRequest, "body is not SCIM JSON")
			return
		}
		existing, gerr := store.GetSCIMGroup(ctx, s.db, src, id)
		if gerr != nil {
			writeSCIMError(w, http.StatusNotFound, "no such group")
			return
		}
		// PUT replaces the resource, so an absent `members` means "no members"
		// rather than "leave them alone" -- that is what distinguishes PUT from
		// PATCH, and treating them alike makes a full replace unable to empty a
		// group.
		members := in.memberIDs()
		if members == nil {
			members = []string{}
		}
		name := in.DisplayName
		if strings.TrimSpace(name) == "" {
			name = existing.DisplayName
		}
		g, uerr := store.UpsertSCIMGroup(ctx, s.db, src, existing.ExternalID, name, members)
		if uerr != nil {
			s.writeSCIMGroupError(w, uerr, "replacing a SCIM group")
			return
		}
		s.auditGroupChange(ctx, src, g, "scim.group_replaced")
		writeSCIM(w, http.StatusOK, scimGroupResource(g))

	case http.MethodPatch:
		s.scimPatchGroup(w, r, src, id)

	case http.MethodDelete:
		g, derr := store.DeleteSCIMGroup(ctx, s.db, src, id)
		if derr != nil {
			if errors.Is(derr, pgx.ErrNoRows) {
				// Already gone is the outcome the upstream wanted. 204 rather
				// than 404, so a retried deprovisioning does not look like a
				// permanent failure.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			s.log.Error("deleting a SCIM group", "err", derr)
			writeSCIMError(w, http.StatusInternalServerError, "unavailable")
			return
		}
		s.auditGroupChange(ctx, src, g, "scim.group_deprovisioned")
		w.WriteHeader(http.StatusNoContent)

	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request,
	src *store.SCIMSource, id string) {

	ctx := r.Context()
	var req scim.PatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "body is not SCIM JSON")
		return
	}
	patch, err := scim.ApplyGroupPatch(req)
	if errors.Is(err, scim.ErrTooManyOperations) {
		writeSCIMErrorType(w, http.StatusBadRequest, "tooMany", err.Error())
		return
	}
	if err != nil {
		// A PATCH we cannot read is an ERROR, never a silent 200. This is the
		// whole point of the group half: a misread removal is never retried.
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(patch.Unsupported) > 0 {
		s.log.Warn("SCIM group patch contained paths this engine does not store",
			"paths", strings.Join(patch.Unsupported, ","), "source", src.Slug)
	}

	g, err := store.PatchSCIMGroup(ctx, s.db, src, id, patch)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeSCIMError(w, http.StatusNotFound, "no such group")
			return
		}
		s.writeSCIMGroupError(w, err, "patching a SCIM group")
		return
	}
	s.auditDetached(ctx, audit.Event{
		Type: "scim.group_membership_changed", OrgID: src.OrgID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{"source": src.Slug, "group": g.Name,
			"added": len(patch.AddMembers), "removed": len(patch.RemoveMembers),
			"replaced": patch.ReplaceMembers != nil, "members": len(g.Members)},
	})
	writeSCIM(w, http.StatusOK, scimGroupResource(g))
}

// writeSCIMGroupError maps a store error to the status an upstream acts on.
func (s *Server) writeSCIMGroupError(w http.ResponseWriter, err error, what string) {
	var conflict *store.SCIMConflictError
	if errors.As(err, &conflict) {
		// 409 uniqueness is what stops an upstream retrying forever.
		w.Header().Set("Content-Type", scimContentType)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			"scimType": "uniqueness",
			"detail":   conflict.Error(),
			"status":   "409",
		})
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeSCIMError(w, http.StatusNotFound, "no such group")
		return
	}
	// A member naming a user this source has not provisioned is the upstream's
	// mistake and is fixable at their end, so it is a 400 with the reason rather
	// than a 500 they will retry unchanged.
	if strings.Contains(err.Error(), "not a user provisioned by this source") ||
		strings.Contains(err.Error(), "usable in a group name") ||
		strings.Contains(err.Error(), "not a usable group name") {
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Error(what, "err", err)
	writeSCIMError(w, http.StatusInternalServerError, "unavailable")
}

func (s *Server) auditGroupChange(ctx context.Context, src *store.SCIMSource,
	g store.SCIMGroup, event string) {

	s.auditDetached(ctx, audit.Event{
		Type: event, OrgID: src.OrgID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"source": src.Slug, "external_id": g.ExternalID,
			"group": g.Name, "members": len(g.Members)},
	})
}

// scimGroupResource renders a group in the shape SCIM clients expect.
func scimGroupResource(g store.SCIMGroup) map[string]any {
	members := make([]map[string]any, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, map[string]any{
			"value":   m.ResourceID,
			"display": m.DisplayName,
			"$ref":    fmt.Sprintf("/scim/v2/Users/%s", m.ResourceID),
		})
	}
	return map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"id":          g.ResourceID,
		"externalId":  g.ExternalID,
		"displayName": g.DisplayName,
		"members":     members,
		"meta": map[string]any{
			"resourceType": "Group",
			"created":      g.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": g.UpdatedAt.UTC().Format(time.RFC3339),
			"location":     fmt.Sprintf("/scim/v2/Groups/%s", g.ResourceID),
		},
	}
}
