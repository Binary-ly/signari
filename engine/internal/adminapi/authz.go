package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
)

// Fine-grained authorization (6.07), as `signari authz` configures it: the
// organisation's model, whose own tests run before it is stored, and the
// relations decisions are made from.

type putModelRequest struct {
	Source string `json:"source"`
}

// relationRequest names one tuple: subject and object as type:id.
type relationRequest struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

const authzRefusal = "change who may do what to everything in the organisation"

var errRelationNotFound = errors.New("no such relation")

func (s *Server) getAuthzModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	src, err := store.ModelSource(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading the authorization model", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// Empty: no model, and nothing is permitted.
	s.writeList(w, r, map[string]any{"org_id": orgID, "source": src})
}

func (s *Server) putAuthzModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putModelRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	// Parsing runs the model's own tests: one whose examples fail does not
	// load, so it cannot be stored and discovered wrong in production.
	m, err := authzen.ParseModel([]byte(req.Source))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_model", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, authzRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	actions := 0
	for _, t := range m.Types {
		actions += len(t.Permissions)
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.SaveModel(ctx, tx, orgID, req.Source, m, actingUser(r)); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.authorization_model_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"types": len(m.Types), "actions": actions, "tests": len(m.Tests)}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case err != nil:
		s.log.Error("storing the authorization model", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"org_id": orgID, "types": len(m.Types), "actions": actions,
		"tests_passed": len(m.Tests), "config_version": version})
}

// actingUser is the person a role principal acts as, recorded as who
// granted or changed; empty for a token.
func actingUser(r *http.Request) string {
	if p, ok := principalFrom(r.Context()); ok {
		return p.UserID
	}
	return ""
}

func (s *Server) grantRelation(w http.ResponseWriter, r *http.Request) {
	var req relationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	s.changeRelation(w, r, req, true)
}

// revokeRelation takes the tuple from the query, as a DELETE carries no body.
func (s *Server) revokeRelation(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.changeRelation(w, r, relationRequest{Subject: q.Get("subject"), Relation: q.Get("relation"),
		Object: q.Get("object")}, false)
}

// changeRelation grants or revokes one relation, as `signari authz grant` and
// `revoke` do. It takes effect on the next decision, which reads relations
// per request.
func (s *Server) changeRelation(w http.ResponseWriter, r *http.Request, req relationRequest, grant bool) {
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
	if narrowedTokenRefused(w, r, authzRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	rel := store.Relation{SubjectType: styp, SubjectID: sid, Relation: relation, ObjectType: otyp, ObjectID: oid}
	detail := map[string]any{"subject": styp + ":" + sid, "relation": relation, "object": otyp + ":" + oid}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if grant {
			if err := store.GrantRelation(ctx, tx, orgID, rel, actingUser(r)); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Event{Type: "admin.relation_granted", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: detail})
		}
		removed, err := store.RevokeRelation(ctx, tx, orgID, rel)
		if err != nil {
			return err
		}
		if !removed {
			return errRelationNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.relation_revoked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errRelationNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "relation_not_found"})
		return
	case err != nil:
		s.log.Error("changing a relation", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	detail["granted"], detail["config_version"] = grant, version
	writeJSON(w, http.StatusOK, detail)
}
