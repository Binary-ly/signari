package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// relationRequest names one tuple: subject and object as type:id. ExpiresAt, on a
// grant, is when it stops counting; absent, it stands until revoked.
type relationRequest struct {
	Subject   string     `json:"subject"`
	Relation  string     `json:"relation"`
	Object    string     `json:"object"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
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

// explainAuthz says how a question would come out on relations, as `signari authz
// check` does: which relations grant the action and whose grant answers it. A
// session and a provider have their say at the decision itself, so what they would
// be asked is returned as `requires` and not as part of `allowed`.
func (s *Server) explainAuthz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	q := r.URL.Query()
	styp, sid, sok := authzen.ParseRef(strings.TrimSpace(q.Get("subject")))
	otyp, oid, ook := authzen.ParseRef(strings.TrimSpace(q.Get("object")))
	action := strings.TrimSpace(q.Get("action"))
	if !sok || !ook || action == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_relation",
			"detail": "give subject and object as type:id, and an action"})
		return
	}
	model, err := store.LoadModel(ctx, s.db, orgID)
	if err == nil && model == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no_authorization_model"})
		return
	}
	var e store.Explanation
	defined := false
	if err == nil {
		e, defined, err = store.Explain(ctx, s.db, orgID, model, styp, sid, action, otyp, oid)
	}
	if err != nil {
		s.log.Error("explaining a decision", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	requires := ""
	if c, has := model.ConditionFor(otyp, action); has {
		requires = c.Condition.Summary()
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "allowed": e.Held != "", "defined": defined,
		"relation": e.Held, "via": e.Via, "relations": nonNilStrings(e.Relations), "groups": nonNilStrings(e.Groups),
		"requires": requires})
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

// relationView is one relation in a list.
type relationView struct {
	Subject   string     `json:"subject"`
	Relation  string     `json:"relation"`
	Object    string     `json:"object"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// listRelations pages through the live relations, by subject, object or relation
// when they are given. By id, so the next page does not depend on what has been
// written since: a person's rows are never skipped or shown twice while the
// application reading them goes on granting.
func (s *Server) listRelations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	if narrowedTokenRefused(w, r, "read who may do what to everything in the organisation") {
		return
	}
	q := r.URL.Query()
	filter := store.RelationFilter{Relation: q.Get("relation")}
	ref := func(raw string, typ, id *string) bool {
		if raw == "" {
			return true
		}
		var ok bool
		*typ, *id, ok = authzen.ParseRef(raw)
		return ok
	}
	if !ref(q.Get("subject"), &filter.SubjectType, &filter.SubjectID) ||
		!ref(q.Get("object"), &filter.ObjectType, &filter.ObjectID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_relation",
			"detail": "give subject and object as type:id"})
		return
	}
	limit, cursor := pageParams(r)
	var after int64
	if cursor != "" {
		var err error
		if after, err = strconv.ParseInt(cursor, 10, 64); err != nil || after <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_cursor",
				"detail": "give back the next_cursor of the page before"})
			return
		}
	}
	rows, next, err := store.PageRelations(ctx, s.db, orgID, filter, after, limit)
	if err != nil {
		s.log.Error("listing relations", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]relationView, 0, len(rows))
	for _, row := range rows {
		out = append(out, relationView{Subject: row.Subject, Relation: row.Relation, Object: row.Object,
			ExpiresAt: row.ExpiresAt})
	}
	nextCursor := ""
	if next != 0 {
		nextCursor = strconv.FormatInt(next, 10)
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "relations": out, "next_cursor": nextCursor})
}

// revokeRelation takes the tuple from the query, as a DELETE carries no body.
func (s *Server) revokeRelation(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.changeRelation(w, r, relationRequest{Subject: q.Get("subject"), Relation: q.Get("relation"),
		Object: q.Get("object")}, false)
}

// expiryPassed refuses a grant that would have ended before it was made, and
// answers for itself: it would read as done and grant nothing.
func expiryPassed(w http.ResponseWriter, at *time.Time) bool {
	if at == nil || at.After(time.Now()) {
		return false
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_expiry",
		"detail": "expires_at has passed, so this would grant nothing"})
	return true
}

// relationRecord is what the trail keeps of a relation: what the response says,
// but a person by their id, and never the address a grant may name them by. The
// trail outlives an erasure, so anything personal written there survives it. An
// address nobody here holds is left out; a group or a service is not a person.
// It answers the record and the person the relation is held by.
func relationRecord(ctx context.Context, q store.Querier, orgID string, rel store.Relation,
	detail map[string]any) (map[string]any, string, error) {
	recorded := maps.Clone(detail)
	if rel.ObjectType == "user" {
		delete(recorded, "object")
		recorded["object_type"] = rel.ObjectType
		onWhom, err := store.ResolveSubject(ctx, q, orgID, rel.ObjectID)
		if err != nil {
			return nil, "", err
		}
		if onWhom != "" {
			recorded["object"] = "user:" + onWhom
		}
	}
	if rel.SubjectType != "user" {
		return recorded, "", nil
	}
	delete(recorded, "subject")
	recorded["subject_type"] = rel.SubjectType
	person, err := store.ResolveSubject(ctx, q, orgID, rel.SubjectID)
	return recorded, person, err
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
	if expiryPassed(w, req.ExpiresAt) {
		return
	}
	if narrowedTokenRefused(w, r, authzRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	rel := store.Relation{SubjectType: styp, SubjectID: sid, Relation: relation, ObjectType: otyp, ObjectID: oid,
		ExpiresAt: req.ExpiresAt}
	detail := map[string]any{"subject": styp + ":" + sid, "relation": relation, "object": otyp + ":" + oid}
	if req.ExpiresAt != nil {
		detail["expires_at"] = req.ExpiresAt.UTC()
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		recorded, person, err := relationRecord(ctx, tx, orgID, rel, detail)
		if err != nil {
			return err
		}
		if grant {
			if err := store.GrantRelation(ctx, tx, orgID, rel, actingUser(r)); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Event{Type: "admin.relation_granted", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, SubjectID: person, Detail: recorded})
		}
		removed, err := store.RevokeRelation(ctx, tx, orgID, rel)
		if err != nil {
			return err
		}
		if !removed {
			return errRelationNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.relation_revoked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: person, Detail: recorded})
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
