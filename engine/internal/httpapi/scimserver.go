package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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

const scimContentType = "application/scim+json"

// scimAuth resolves the bearer token to a source.
//
// Compared in constant time against a stored hash. A token that can create and
// deactivate every user in an organisation is a password, and comparing it with
// == leaks its prefix to anybody willing to time the responses.
func (s *Server) scimAuth(r *http.Request) (*store.SCIMSource, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return nil, errors.New("no bearer token")
	}
	token := strings.TrimSpace(h[len("bearer "):])
	if token == "" {
		return nil, errors.New("empty bearer token")
	}
	sum := sha256.Sum256([]byte(token))

	src, err := store.FindSCIMSourceByToken(r.Context(), s.db, sum[:])
	if err != nil {
		return nil, err
	}
	// Another instance's source provisions that instance's directory, at its
	// own host (6.12).
	if !s.ownedBy(r.Context(), s.db, src.OrgID, "scim source") {
		return nil, errors.New("the token belongs to another instance")
	}
	// Belt and braces: the lookup is already by hash, and comparing again means
	// a future change to that query cannot quietly turn it into a prefix match.
	if subtle.ConstantTimeCompare(src.TokenHash, sum[:]) != 1 {
		return nil, errors.New("token mismatch")
	}
	return src, nil
}

func writeSCIMErrorType(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"scimType": scimType,
		"detail":   detail,
		"status":   strconv.Itoa(status),
	})
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  strconv.Itoa(status),
	})
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// handleSCIMServiceProviderConfig describes what this server can actually do.
func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if _, err := s.scimAuth(r); err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Every "supported" here is a claim an upstream will act on. False for
	// anything not implemented, so nothing tries and fails.
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": scimMaxPageSize},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "OAuth Bearer Token",
			"description": "Authentication using the token issued by `signari scim-source add`",
		}},
	})
}

// handleSCIMResourceTypes lists what can be provisioned.
//
// Groups entered this list only when /Groups was implemented, per the rule this
// project holds everywhere: an upstream that reads a resource type here will try
// to sync it, so advertising one that 404s produces failures the operator cannot
// act on.
func (s *Server) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	if _, err := s.scimAuth(r); err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !discoveryQueryOK(w, r) {
		return
	}
	// Built as a slice and counted, rather than a count written beside it. The
	// two drifting apart is a real failure mode -- an upstream that reads
	// totalResults 1 and receives two resources syncs one of them -- and it is
	// the kind of drift no test notices, because both halves look right on their
	// own.
	types := []map[string]any{{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":       "User",
		"name":     "User",
		"endpoint": "/Users",
		"schema":   "urn:ietf:params:scim:schemas:core:2.0:User",
	}, {
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":       "Group",
		"name":     "Group",
		"endpoint": "/Groups",
		"schema":   "urn:ietf:params:scim:schemas:core:2.0:Group",
	}}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(types),
		"itemsPerPage": len(types),
		"startIndex":   1,
		"Resources":    types,
	})
}

const (
	scimDefaultPageSize = 100
	scimMaxPageSize     = 200
)

// handleSCIMUsers is the collection: list, filter and create.
func (s *Server) handleSCIMUsers(w http.ResponseWriter, r *http.Request) {
	src, err := s.scimAuth(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.scimListUsers(w, r, src)
	case http.MethodPost:
		s.scimCreateUser(w, r, src)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request, src *store.SCIMSource) {
	ctx := r.Context()
	q := r.URL.Query()

	// startIndex is ONE-based in SCIM. Treating it as zero-based silently skips
	// the first user of every page, which an upstream reports as "some users did
	// not sync" and nobody can reproduce.
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

	userName, err := scim.ParseUserNameFilter(q.Get("filter"))
	if err != nil {
		// RFC 7644 Table 9 (specs/rfc7644.txt:3821): invalidFilter, for "the
		// specified attribute and filter comparison combination is not
		// supported". Only `userName eq` is, until the full grammar (7.10); a
		// bare 400 left a client unable to tell that from a broken request.
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}

	users, total, err := store.ListSCIMUsers(ctx, s.db, src.ID, userName, start, count)
	if err != nil {
		s.log.Error("listing SCIM users", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "unavailable")
		return
	}

	resources := make([]map[string]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, scimUserResource(u))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"itemsPerPage": len(resources),
		"startIndex":   start,
		"Resources":    resources,
	})
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request, src *store.SCIMSource) {
	ctx := r.Context()
	var raw scim.InboundUser
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&raw); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "body is not SCIM JSON: "+err.Error())
		return
	}
	in := raw.Resolved()
	if strings.TrimSpace(in.UserName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required")
		return
	}
	// externalId is the upstream's immutable identifier and the only thing this
	// engine matches on. Without it a rename is indistinguishable from a
	// departure plus an arrival.
	if strings.TrimSpace(in.ExternalID) == "" {
		writeSCIMError(w, http.StatusBadRequest,
			"externalId is required: it is the only identifier stable across a "+
				"rename, and matching on userName or email instead turns a marriage "+
				"into a deactivated account and a new one")
		return
	}

	created, err := store.UpsertSCIMUser(ctx, s.db, src, in)
	if err != nil {
		if s.scimForbidden(w, r, src, err) {
			return
		}
		var conflict *store.SCIMConflictError
		if errors.As(err, &conflict) {
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
		s.log.Error("creating a SCIM user", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "unavailable")
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "scim.user_provisioned", OrgID: src.OrgID, SubjectID: created.UserID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"source": src.Slug, "external_id": in.ExternalID},
	})
	writeSCIM(w, http.StatusCreated, scimUserResource(created))
}

// handleSCIMUser is one resource: get, replace, patch and delete.
func (s *Server) handleSCIMUser(w http.ResponseWriter, r *http.Request) {
	src, err := s.scimAuth(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeSCIMError(w, http.StatusNotFound, "no such user")
		return
	}

	switch r.Method {
	case http.MethodGet:
		u, gerr := store.GetSCIMUser(r.Context(), s.db, src.ID, id)
		if gerr != nil {
			writeSCIMError(w, http.StatusNotFound, "no such user")
			return
		}
		writeSCIM(w, http.StatusOK, scimUserResource(u))

	case http.MethodPut:
		s.scimReplaceUser(w, r, src, id)

	case http.MethodPatch:
		s.scimPatchUser(w, r, src, id)

	case http.MethodDelete:
		s.scimDeleteUser(w, r, src, id)

	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request,
	src *store.SCIMSource, id string) {

	ctx := r.Context()
	var raw scim.InboundUser
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&raw); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "body is not SCIM JSON")
		return
	}
	in := raw.Resolved()

	u, err := store.ReplaceSCIMUser(ctx, s.db, src, id, in)
	if err != nil {
		if s.scimForbidden(w, r, src, err) {
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			writeSCIMError(w, http.StatusNotFound, "no such user")
			return
		}
		s.log.Error("replacing a SCIM user", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "unavailable")
		return
	}
	s.auditSCIMChange(ctx, src, u, "scim.user_replaced")
	writeSCIM(w, http.StatusOK, scimUserResource(u))
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request,
	src *store.SCIMSource, id string) {

	ctx := r.Context()
	var req scim.PatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "body is not SCIM JSON")
		return
	}

	patch, err := scim.ApplyUserPatch(req)
	if errors.Is(err, scim.ErrTooManyOperations) {
		writeSCIMErrorType(w, http.StatusBadRequest, "tooMany", err.Error())
		return
	}
	if err != nil {
		// A PATCH we cannot read is an ERROR, never a silent 200. An upstream
		// that receives 200 records the deactivation as done.
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(patch.Unsupported) > 0 {
		// Logged, not failed: the operation may well have changed something else
		// we did apply, and refusing the whole request would block the sync.
		s.log.Warn("SCIM patch contained paths this engine does not store",
			"paths", strings.Join(patch.Unsupported, ","), "source", src.Slug)
	}

	u, err := store.PatchSCIMUser(ctx, s.db, src, id, patch)
	if err != nil {
		if s.scimForbidden(w, r, src, err) {
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			writeSCIMError(w, http.StatusNotFound, "no such user")
			return
		}
		s.log.Error("patching a SCIM user", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "unavailable")
		return
	}
	s.auditSCIMChange(ctx, src, u, "scim.user_patched")
	writeSCIM(w, http.StatusOK, scimUserResource(u))
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request,
	src *store.SCIMSource, id string) {

	ctx := r.Context()
	u, err := store.DeleteSCIMUser(ctx, s.db, src, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Already gone is the outcome the upstream wanted. 204 rather than
			// 404 so a retried deprovisioning does not look like a failure
			// forever.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.log.Error("deleting a SCIM user", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "unavailable")
		return
	}
	if u.Kept {
		// Deactivated rather than deleted: the person may act as others.
		s.auditDetached(ctx, audit.Event{
			Type: "scim.privileged_kept", OrgID: src.OrgID, SubjectID: u.UserID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"source": src.Slug, "external_id": u.ExternalID},
		})
	}
	s.auditSCIMChange(ctx, src, u, "scim.user_deprovisioned")
	w.WriteHeader(http.StatusNoContent)
}

// scimForbidden answers a change the source may not make (store.SCIMForbiddenError)
// with 403, records the attempt, and reports whether it did. An upstream
// retries a 500 forever; it stops on a 4xx.
func (s *Server) scimForbidden(w http.ResponseWriter, r *http.Request,
	src *store.SCIMSource, err error) bool {
	var forbidden *store.SCIMForbiddenError
	if !errors.As(err, &forbidden) {
		return false
	}
	s.auditDetached(r.Context(), audit.Event{
		Type: "scim.privileged_refused", OrgID: src.OrgID,
		CorrelationID: correlationID(r.Context()),
		Detail:        map[string]any{"source": src.Slug, "method": r.Method, "path": r.URL.Path},
	})
	writeSCIMError(w, http.StatusForbidden, forbidden.Error())
	return true
}

// auditSCIMChange records a provisioning change against the person it affected.
func (s *Server) auditSCIMChange(ctx context.Context, src *store.SCIMSource,
	u store.SCIMUser, event string) {

	s.auditDetached(ctx, audit.Event{
		Type: event, OrgID: src.OrgID, SubjectID: u.UserID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"source": src.Slug, "external_id": u.ExternalID, "active": u.Active,
		},
	})
}

// scimUserResource renders a user in the shape SCIM clients expect.
func scimUserResource(u store.SCIMUser) map[string]any {
	res := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":          u.ResourceID,
		"externalId":  u.ExternalID,
		"userName":    u.UserName,
		"active":      u.Active,
		"displayName": u.DisplayName,
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": u.UpdatedAt.UTC().Format(time.RFC3339),
			"location":     fmt.Sprintf("/scim/v2/Users/%s", u.ResourceID),
		},
	}
	if u.Email != "" {
		res["emails"] = []map[string]any{{"value": u.Email, "primary": true}}
	}
	return res
}
