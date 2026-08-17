package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
)

// The OpenID AuthZEN Authorization API 1.0 endpoints.
//
//	POST /access/v1/evaluation
//	POST /access/v1/evaluations
//	POST /access/v1/search/subject
//	POST /access/v1/search/resource
//	POST /access/v1/search/action
//
// # A denial is 200
//
// {"decision": false} with a 200. NOT 403. The HTTP status says whether the
// request was processed; the body says what the answer was. A PDP that returns
// 403 for "no" is indistinguishable from one refusing to talk to the caller at
// all, and a client cannot tell an authorization decision from its own
// credentials having expired -- so it retries, or worse, treats the failure as
// a transport error and falls back to allowing.
//
// # Why the caller is not asked about the subject
//
// A standalone PDP is told about the subject by the application, because it has
// no other source. This one reads groups, factors and posture from the session
// it issued. An application cannot inflate them, because it is not asked -- and
// that is the difference between a decision about a person and a decision about
// a claim.

// authzEvaluate answers one question.
func (s *Server) handleAuthzEvaluate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, ok := s.authzCaller(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		authzError(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	var req authzen.Request
	if err := authzen.Decode(body, &req); err != nil {
		authzError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := req.Validate(); err != nil {
		// 400, not a denial. "No" and "that question was malformed" are
		// different answers, and a PDP that returns false for both teaches
		// callers that a denial might just mean they sent the wrong shape.
		authzError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp, err := s.decide(ctx, orgID, req)
	if err != nil {
		s.log.Error("evaluating an authorization request", "err", err,
			"correlation_id", correlationID(ctx))
		authzError(w, http.StatusInternalServerError, "the decision could not be made")
		return
	}
	echoRequestID(w, r)
	writeJSONResponse(w, http.StatusOK, resp)
}

// handleAuthzEvaluations answers a batch.
func (s *Server) handleAuthzEvaluations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, ok := s.authzCaller(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		authzError(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	var batch authzen.Evaluations
	if err := authzen.Decode(body, &batch); err != nil {
		authzError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(batch.Evaluations) == 0 {
		authzError(w, http.StatusBadRequest, "the batch contains no evaluations")
		return
	}
	// Bounded. An unbounded batch is a way to make one request cost a thousand
	// database round trips, which is a denial of service with a JSON array in
	// front of it.
	const maxBatch = 256
	if len(batch.Evaluations) > maxBatch {
		authzError(w, http.StatusBadRequest,
			"a batch may contain at most 256 evaluations")
		return
	}

	semantic := authzen.ExecuteAll
	if batch.Options != nil && batch.Options.Semantic != "" {
		switch batch.Options.Semantic {
		case authzen.ExecuteAll, authzen.DenyOnFirstDeny, authzen.PermitOnFirstPermit:
			semantic = batch.Options.Semantic
		default:
			authzError(w, http.StatusBadRequest,
				"evaluations_semantic must be execute_all, deny_on_first_deny "+
					"or permit_on_first_permit")
			return
		}
	}

	out := make([]authzen.Response, 0, len(batch.Evaluations))
	for _, e := range batch.Evaluations {
		merged := e.Merge(batch)
		if err := merged.Validate(); err != nil {
			// One malformed entry does not fail the batch: the others are
			// answerable, and refusing all of them hides which one was wrong.
			out = append(out, authzen.Response{
				Decision: false,
				Context:  authzen.Reasons(err.Error(), "The request could not be evaluated."),
			})
			continue
		}
		resp, err := s.decide(ctx, orgID, merged)
		if err != nil {
			s.log.Error("evaluating a batch entry", "err", err,
				"correlation_id", correlationID(ctx))
			out = append(out, authzen.Response{
				Decision: false,
				Context: authzen.Reasons("the decision could not be made",
					"The request could not be evaluated."),
			})
			continue
		}
		out = append(out, resp)

		// Short-circuit AFTER appending, so the entry that decided the batch is
		// in the response. Stopping before it would return a list whose last
		// answer is missing -- the one the caller most needs.
		if semantic == authzen.DenyOnFirstDeny && !resp.Decision {
			break
		}
		if semantic == authzen.PermitOnFirstPermit && resp.Decision {
			break
		}
	}
	echoRequestID(w, r)
	writeJSONResponse(w, http.StatusOK, authzen.EvaluationsResponse{Evaluations: out})
}

// decide is the single evaluation path. Both endpoints use it, so a batch and a
// single question can never disagree about the same request.
func (s *Server) decide(ctx context.Context, orgID string, req authzen.Request) (
	authzen.Response, error) {

	model, err := store.LoadModel(ctx, s.db, orgID)
	if err != nil {
		return authzen.Response{}, err
	}
	if model == nil {
		// No model means nothing is permitted. Denying rather than allowing:
		// an unconfigured authorization layer that says yes is worse than no
		// authorization layer at all, because the application believes it has one.
		return authzen.Response{
			Decision: false,
			Context: authzen.Reasons(
				"this organisation has no authorization model; run `signari authz model set`",
				"Access is not configured."),
		}, nil
	}

	relations, defined := model.RelationsFor(req.Resource.Type, req.Action.Name)
	if !defined {
		return authzen.Response{
			Decision: false,
			Context: authzen.Reasons(
				"the model defines no action \""+req.Action.Name+"\" on "+req.Resource.Type,
				"That action is not available."),
		}, nil
	}

	// Facts from OUR records, never from the request body.
	userID, err := store.ResolveSubject(ctx, s.db, orgID, req.Subject.ID)
	if err != nil {
		return authzen.Response{}, err
	}
	var facts authzen.Facts
	if userID != "" {
		sid := sessionFromContext(req.Context)
		facts, err = store.SubjectFacts(ctx, s.db, orgID, userID, sid)
		if err != nil {
			return authzen.Response{}, err
		}
	}
	if facts.Now.IsZero() {
		// Even when the subject is not one of our users, the clock is ours.
		facts.Now = time.Now()
	}
	// The caller-asserted half, kept separate all the way through. A policy
	// file says which of its requirements read these, so an auditor can see
	// which survive a compromised relying party without asking anybody.
	facts.ResourceProps = req.Resource.Properties
	facts.IP = ipFromContext(req.Context)

	// The relation lookup uses the subject as GIVEN, so relations can be held
	// by things that are not users in our directory -- a service account, a
	// machine. Resolving to a user id only affects the facts.
	held, err := store.HoldsAny(ctx, s.db, orgID, req.Subject.Type, req.Subject.ID,
		relations, req.Resource.Type, req.Resource.ID, facts.Groups)
	if err != nil {
		return authzen.Response{}, err
	}
	if held == "" && userID != "" && userID != req.Subject.ID {
		// Asked by email, stored by id, or the other way round. Both are tried
		// rather than requiring the caller to know which form we keep.
		held, err = store.HoldsAny(ctx, s.db, orgID, req.Subject.Type, userID,
			relations, req.Resource.Type, req.Resource.ID, facts.Groups)
		if err != nil {
			return authzen.Response{}, err
		}
	}
	if held == "" {
		return authzen.Response{
			Decision: false,
			Context: authzen.Reasons(
				"the subject holds none of "+joinNames(relations)+" on "+
					authzen.Ref(req.Resource.Type, req.Resource.ID),
				"You do not have access to this."),
		}, nil
	}

	// The condition, which is the part a relation graph cannot express.
	if cond, has := model.ConditionFor(req.Resource.Type, req.Action.Name); has {
		if !cond.SatisfiedBy(facts) {
			need := cond.Unmet(facts)
			why := "the action requires " + need + ", which this request did not show"
			if !facts.FromSession && (cond.MFA || cond.DeviceManaged || cond.DeviceCompliant) {
				// The condition is about a session, and none was named -- or the
				// one named is not this subject's live session. Refused rather
				// than guessed: a rule demanding a second factor must not be
				// satisfied by the absence of evidence.
				why = "the action requires " + need + ", and no live session for " +
					"this subject was named, so nothing could be shown -- pass " +
					"the session's sid in `context`"
			}
			return authzen.Response{
				Decision: false,
				Context: authzen.Reasons(
					"the subject holds "+held+" but "+why,
					"You need to sign in again with additional verification."),
			}, nil
		}
	}

	return authzen.Response{
		Decision: true,
		Context:  map[string]any{"relation": held},
	}, nil
}

// handleAuthzSearchResource answers "what may this subject act on".
func (s *Server) handleAuthzSearchResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, ok := s.authzCaller(w, r)
	if !ok {
		return
	}
	req, ok := decodeSearch(w, r)
	if !ok {
		return
	}
	if req.Subject == nil || req.Subject.ID == "" || req.Action == nil ||
		req.Action.Name == "" || req.Resource == nil || req.Resource.Type == "" {
		authzError(w, http.StatusBadRequest,
			"subject.id, action.name and resource.type are required")
		return
	}

	model, err := store.LoadModel(ctx, s.db, orgID)
	if err != nil || model == nil {
		s.searchUnavailable(w, r, err)
		return
	}
	relations, defined := model.RelationsFor(req.Resource.Type, req.Action.Name)
	if !defined {
		echoRequestID(w, r)
		writeJSONResponse(w, http.StatusOK, authzen.SearchResponse{Results: []authzen.Item{}})
		return
	}

	facts := s.factsFor(ctx, orgID, req.Subject.ID, req.Context)
	limit := 0
	if req.Page != nil {
		limit = req.Page.Limit
	}
	ids, err := store.ObjectsWith(ctx, s.db, orgID, req.Subject.Type, req.Subject.ID,
		relations, req.Resource.Type, facts.Groups, limit)
	if err != nil {
		s.log.Error("searching resources", "err", err)
		authzError(w, http.StatusInternalServerError, "the search could not be run")
		return
	}
	items := make([]authzen.Item, 0, len(ids))
	for _, id := range ids {
		items = append(items, authzen.Item{Type: req.Resource.Type, ID: id})
	}
	echoRequestID(w, r)
	writeJSONResponse(w, http.StatusOK, authzen.SearchResponse{
		Results: items,
		Page:    &authzen.PageResponse{Count: len(items)},
	})
}

// handleAuthzSearchSubject answers "who may act on this".
func (s *Server) handleAuthzSearchSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, ok := s.authzCaller(w, r)
	if !ok {
		return
	}
	req, ok := decodeSearch(w, r)
	if !ok {
		return
	}
	if req.Resource == nil || req.Resource.Type == "" || req.Resource.ID == "" ||
		req.Action == nil || req.Action.Name == "" {
		authzError(w, http.StatusBadRequest,
			"resource.type, resource.id and action.name are required")
		return
	}

	model, err := store.LoadModel(ctx, s.db, orgID)
	if err != nil || model == nil {
		s.searchUnavailable(w, r, err)
		return
	}
	relations, defined := model.RelationsFor(req.Resource.Type, req.Action.Name)
	if !defined {
		echoRequestID(w, r)
		writeJSONResponse(w, http.StatusOK, authzen.SearchResponse{Results: []authzen.Item{}})
		return
	}
	limit := 0
	if req.Page != nil {
		limit = req.Page.Limit
	}
	ids, err := store.SubjectsWith(ctx, s.db, orgID, relations,
		req.Resource.Type, req.Resource.ID, limit)
	if err != nil {
		s.log.Error("searching subjects", "err", err)
		authzError(w, http.StatusInternalServerError, "the search could not be run")
		return
	}
	items := make([]authzen.Item, 0, len(ids))
	for _, id := range ids {
		items = append(items, authzen.Item{Type: "user", ID: id})
	}
	echoRequestID(w, r)
	writeJSONResponse(w, http.StatusOK, authzen.SearchResponse{
		Results: items,
		Page:    &authzen.PageResponse{Count: len(items)},
	})
}

// handleAuthzSearchAction answers "what may this subject do to this".
func (s *Server) handleAuthzSearchAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, ok := s.authzCaller(w, r)
	if !ok {
		return
	}
	req, ok := decodeSearch(w, r)
	if !ok {
		return
	}
	if req.Subject == nil || req.Subject.ID == "" || req.Resource == nil ||
		req.Resource.Type == "" {
		authzError(w, http.StatusBadRequest, "subject.id and resource.type are required")
		return
	}

	model, err := store.LoadModel(ctx, s.db, orgID)
	if err != nil || model == nil {
		s.searchUnavailable(w, r, err)
		return
	}
	t, known := model.Types[req.Resource.Type]
	if !known {
		echoRequestID(w, r)
		writeJSONResponse(w, http.StatusOK, authzen.SearchResponse{Results: []authzen.Item{}})
		return
	}

	// Each candidate action goes through `decide`, so the answer here and the
	// answer to a direct evaluation of the same triple cannot differ. Two code
	// paths would eventually disagree, and the one nobody tested is the one an
	// application would rely on.
	var items []authzen.Item
	for action := range t.Permissions {
		resp, err := s.decide(ctx, orgID, authzen.Request{
			Subject:  *req.Subject,
			Resource: *req.Resource,
			Action:   authzen.Action{Name: action},
			Context:  req.Context,
		})
		if err != nil {
			s.log.Error("searching actions", "err", err)
			authzError(w, http.StatusInternalServerError, "the search could not be run")
			return
		}
		if resp.Decision {
			// `name`, not `id`: the specification's action results carry a name
			// alone (section 8.6.2), and a client looking for it finds nothing
			// if we send an id.
			items = append(items, authzen.Item{Name: action})
		}
	}
	sortItems(items)
	if items == nil {
		items = []authzen.Item{}
	}
	echoRequestID(w, r)
	writeJSONResponse(w, http.StatusOK, authzen.SearchResponse{
		Results: items,
		Page:    &authzen.PageResponse{Count: len(items)},
	})
}

// factsFor is the shared subject lookup for the search endpoints.
func (s *Server) factsFor(ctx context.Context, orgID, subjectID string,
	reqCtx map[string]any) authzen.Facts {

	userID, err := store.ResolveSubject(ctx, s.db, orgID, subjectID)
	if err != nil || userID == "" {
		return authzen.Facts{}
	}
	facts, err := store.SubjectFacts(ctx, s.db, orgID, userID, sessionFromContext(reqCtx))
	if err != nil {
		return authzen.Facts{}
	}
	return facts
}

func (s *Server) searchUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		s.log.Error("loading the authorization model", "err", err)
		authzError(w, http.StatusInternalServerError, "the model could not be loaded")
		return
	}
	// No model: an empty result, not an error. "Nothing" is the honest answer
	// when nothing has been granted.
	echoRequestID(w, r)
	writeJSONResponse(w, http.StatusOK, authzen.SearchResponse{Results: []authzen.Item{}})
}

func decodeSearch(w http.ResponseWriter, r *http.Request) (authzen.SearchRequest, bool) {
	var req authzen.SearchRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		authzError(w, http.StatusBadRequest, "the request body could not be read")
		return req, false
	}
	if err := authzen.Decode(body, &req); err != nil {
		authzError(w, http.StatusBadRequest, err.Error())
		return req, false
	}
	return req, true
}

// sessionFromContext reads the sid a caller supplied, if any.
//
// The caller may name a session but cannot describe it. What that session
// proved is read from our own row -- naming one it does not own gets the facts
// of a session that does not match, which is to say none.
func sessionFromContext(ctx map[string]any) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx["sid"].(string); ok {
		return v
	}
	if v, ok := ctx["session_id"].(string); ok {
		return v
	}
	return ""
}

// ipFromContext reads the address the caller says the request came from.
//
// Asserted, not observed: the PDP is being asked about somebody else's request,
// so there is no connection to read it from. Policies that use it say so, under
// `asserted:`.
func ipFromContext(ctx map[string]any) string {
	if ctx == nil {
		return ""
	}
	for _, k := range []string{"ip", "ip_address", "remote_addr"} {
		if v, ok := ctx[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// echoRequestID returns X-Request-ID, which the specification requires when the
// caller sent one.
func echoRequestID(w http.ResponseWriter, r *http.Request) {
	if id := r.Header.Get("X-Request-ID"); id != "" && len(id) <= 200 {
		w.Header().Set("X-Request-ID", id)
	}
}

func authzError(w http.ResponseWriter, code int, msg string) {
	writeJSONResponse(w, code, map[string]any{"error": msg})
}

func writeJSONResponse(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return "any relation"
	case 1:
		return names[0]
	}
	out := ""
	for i, n := range names {
		switch {
		case i == 0:
			out = n
		case i == len(names)-1:
			out += " or " + n
		default:
			out += ", " + n
		}
	}
	return out
}

func sortItems(items []authzen.Item) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Name < items[j-1].Name; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// authzCaller authenticates the application asking, and tells us which
// organisation it may ask about.
//
// A `pdp` outpost token. Reusing outposts rather than inventing a credential
// type means issuance, rate limiting, enable/disable and revocation are the
// ones that already exist and are already tested -- a second credential type is
// a second set of those to get wrong.
//
// The organisation comes from the TOKEN, never from the request. A body-supplied
// org id is a body-supplied answer to "whose data may I ask about".
func (s *Server) authzCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	orgID, kind, _, ok := s.outpostAuth(w, r)
	if !ok {
		return "", false
	}
	if kind != "pdp" {
		// A token issued for something else is refused rather than accepted.
		// An LDAP outpost's token reaching the authorization API would let
		// whatever holds it ask about every relation in the organisation.
		writeError(w, http.StatusForbidden, "forbidden",
			"this token was issued for a "+kind+" outpost; the authorization API "+
				"needs one issued for a pdp outpost")
		return "", false
	}
	return orgID, true
}
