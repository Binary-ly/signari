package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
)

// One organisation letting another hand out relations on what it owns (11.11).
//
// Only a deployment-wide caller makes or takes away a delegation: no tenant reaches
// across on its own say. Under one, a token of the grantee writes the owner's
// relations through this engine, and only these routes, for its own people, and
// reads back only what it handed out. The owner's decisions read its own table, so
// nothing about a decision crosses a tenant.

type relationDelegationView struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	GranteeOrgID string    `json:"grantee_org_id"`
	Object       string    `json:"object"`
	Relations    []string  `json:"relations"`
	CreatedAt    time.Time `json:"created_at"`
}

func viewDelegation(d store.RelationDelegation) relationDelegationView {
	return relationDelegationView{ID: d.ID, OrgID: d.OrgID, GranteeOrgID: d.GranteeOrgID,
		Object: d.ObjectType + ":" + d.ObjectID, Relations: d.Relations, CreatedAt: d.CreatedAt}
}

// createRelationDelegationRequest lets grantee_org_id hand out relations on object,
// a type:id, or type:* for every object of the type.
type createRelationDelegationRequest struct {
	GranteeOrgID string   `json:"grantee_org_id"`
	Object       string   `json:"object"`
	Relations    []string `json:"relations"`
}

var relationName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

var errSameOrganisation = errors.New("an organisation already holds what it owns")

func (s *Server) listRelationDelegations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.RelationDelegationsOf(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing relation delegations", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]relationDelegationView, 0, len(got))
	for _, d := range got {
		out = append(out, viewDelegation(d))
	}
	s.writeList(w, r, map[string]any{"delegations": out})
}

func (s *Server) createRelationDelegation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req createRelationDelegationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	// First: what follows answers differently for an organisation that exists.
	if !deploymentWide(w, ctx) {
		return
	}
	otyp, oid, ok := authzen.ParseRef(strings.TrimSpace(req.Object))
	if !ok || len(req.Relations) == 0 || len(req.Relations) > 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_delegation",
			"detail": "give object as type:id or type:*, and one to 32 relations"})
		return
	}
	for _, name := range req.Relations {
		if !relationName.MatchString(name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_delegation",
				"detail": "a relation is lower case: " + name})
			return
		}
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	d := store.RelationDelegation{OrgID: orgID, GranteeOrgID: req.GranteeOrgID, ObjectType: otyp,
		ObjectID: oid, Relations: req.Relations}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := requireNamedOrg(ctx, tx, req.GranteeOrgID); err != nil {
			return err
		}
		if orgID == req.GranteeOrgID {
			return errSameOrganisation
		}
		id, err := store.NewRelationDelegation(ctx, tx, d)
		if err != nil {
			return err
		}
		d.ID = id
		return audit.Write(ctx, tx, audit.Event{Type: "admin.relation_delegated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"delegation_id": id, "grantee_org_id": req.GranteeOrgID,
				"object": req.Object, "relations": req.Relations}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errSameOrganisation):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_delegation", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("delegating relations", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	d.CreatedAt = time.Now().UTC()
	writeJSON(w, http.StatusCreated, struct {
		relationDelegationView
		ConfigVersion int64 `json:"config_version"`
	}{viewDelegation(d), version})
}

func (s *Server) deleteRelationDelegation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, id := r.PathValue("orgID"), r.PathValue("delegationID")
	if !deploymentWide(w, ctx) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		d, err := store.RelationDelegationByID(ctx, tx, id)
		if err != nil {
			return err
		}
		if d == nil || d.OrgID != orgID {
			return errNotFound
		}
		if _, err := store.RemoveRelationDelegation(ctx, tx, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.relation_undelegated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"delegation_id": id, "grantee_org_id": d.GranteeOrgID}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "delegation_not_found"})
		return
	case err != nil:
		s.log.Error("removing a delegation", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}

// delegationOfSide finds a delegation orgID is a side of, and answers for itself
// when there is none, the same for one that exists and is another pair's.
func (s *Server) delegationOfSide(w http.ResponseWriter, r *http.Request) (*store.RelationDelegation, bool) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	d, err := store.RelationDelegationByID(ctx, s.db, r.PathValue("delegationID"))
	if err != nil {
		s.log.Error("reading a delegation", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return nil, false
	}
	if d == nil || (d.OrgID != orgID && d.GranteeOrgID != orgID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "delegation_not_found"})
		return nil, false
	}
	return d, true
}

func (s *Server) listDelegatedRelations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := requireOrg(ctx, r.PathValue("orgID")); err != nil {
		writeCrossOrg(w, err)
		return
	}
	d, ok := s.delegationOfSide(w, r)
	if !ok {
		return
	}
	got, err := store.DelegatedRelations(ctx, s.db, *d)
	if err != nil {
		s.log.Error("listing delegated relations", "delegation_id", d.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]relationView, 0, len(got))
	for _, rel := range got {
		out = append(out, relationView{Subject: rel.SubjectType + ":" + rel.SubjectID, Relation: rel.Relation,
			Object: rel.ObjectType + ":" + rel.ObjectID, ExpiresAt: rel.ExpiresAt})
	}
	s.writeList(w, r, map[string]any{"relations": out})
}

func (s *Server) grantDelegatedRelation(w http.ResponseWriter, r *http.Request) {
	var req relationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	s.changeDelegatedRelation(w, r, req, true)
}

func (s *Server) revokeDelegatedRelation(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.changeDelegatedRelation(w, r, relationRequest{Subject: q.Get("subject"), Relation: q.Get("relation"),
		Object: q.Get("object")}, false)
}

// changeDelegatedRelation is the grantee's side, and only the grantee's: the owner
// has its own routes, and a delegation hands nothing the other way.
func (s *Server) changeDelegatedRelation(w http.ResponseWriter, r *http.Request, req relationRequest, grant bool) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	styp, sid, sok := authzen.ParseRef(strings.TrimSpace(req.Subject))
	otyp, oid, ook := authzen.ParseRef(strings.TrimSpace(req.Object))
	relation := strings.TrimSpace(req.Relation)
	if !sok || !ook || relation == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_relation",
			"detail": "give subject and object as type:id, and a relation"})
		return
	}
	if expiryPassed(w, req.ExpiresAt) {
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	if narrowedTokenRefused(w, r, authzRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	rel := store.Relation{SubjectType: styp, SubjectID: sid, Relation: relation, ObjectType: otyp,
		ObjectID: oid, ExpiresAt: req.ExpiresAt}
	var theirs *store.RelationDelegation
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		d, err := store.RelationDelegationByID(ctx, tx, r.PathValue("delegationID"))
		if err != nil {
			return err
		}
		if d == nil || d.GranteeOrgID != orgID {
			return errNotFound
		}
		theirs = d
		detail := map[string]any{"delegation_id": d.ID, "grantee_org_id": d.GranteeOrgID,
			"relation": relation, "object": styp + ":" + sid + " " + otyp + ":" + oid}
		if grant {
			if err := store.GrantDelegated(ctx, tx, *d, rel); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Event{Type: "admin.delegated_relation_granted",
				AdminTokenID: TokenIDFrom(ctx), OrgID: d.OrgID, SubjectID: sid, Detail: detail})
		}
		removed, err := store.RevokeDelegated(ctx, tx, *d, rel)
		if err != nil {
			return err
		}
		if !removed {
			return errRelationNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.delegated_relation_revoked",
			AdminTokenID: TokenIDFrom(ctx), OrgID: d.OrgID, SubjectID: sid, Detail: detail})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "delegation_not_found"})
		return
	case errors.Is(err, store.ErrNotDelegated), errors.Is(err, store.ErrNotTheGrantees):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_delegation", "detail": err.Error()})
		return
	case errors.Is(err, errRelationNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "relation_not_found"})
		return
	case err != nil:
		s.log.Error("changing a delegated relation", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"subject": req.Subject, "relation": relation, "object": req.Object,
		"org_id": theirs.OrgID, "granted": grant, "config_version": version})
}
