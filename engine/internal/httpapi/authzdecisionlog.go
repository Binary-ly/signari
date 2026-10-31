package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/authzen"
)

// ParseDecisionLogRate reads SIGNARI_AUTHZ_DECISION_LOG, the share of decisions
// recorded. Absent, none are: a decision can be asked for thousands of times a
// second, and each recorded one is a link in the audit chain.
func ParseDecisionLogRate(value string) (float64, error) {
	if value == "" {
		return 0, nil
	}
	rate, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(rate) || rate < 0 || rate > 1 {
		return 0, fmt.Errorf("SIGNARI_AUTHZ_DECISION_LOG must be a share between 0 and 1, not %q", value)
	}
	return rate, nil
}

// SetDecisionLogRate sets the share of authorization decisions recorded.
func (s *Server) SetDecisionLogRate(rate float64) { s.decisionLogRate = rate }

// note records a decision when this one falls in the sample, so it reaches the
// audit trail and whatever sink is streaming it. Evaluations only: a search is
// a walk over candidates, and the same walk recorded would drown what it sampled.
//
// A person is recorded by id and never by the address the caller may have asked
// about them with: the trail outlives an erasure, so anything personal written
// there survives it. An address nobody here holds is left out for the same reason.
func (e *evaluation) note(ctx context.Context, req authzen.Request, resp authzen.Response) {
	if !sampled(e.s.decisionLogRate) {
		return
	}
	detail := map[string]any{"decision": resp.Decision, "action": req.Action.Name,
		"resource_type": req.Resource.Type, "subject_type": req.Subject.Type}
	if req.Resource.Type != "user" {
		detail["resource"] = authzen.Ref(req.Resource.Type, req.Resource.ID)
	}
	event := audit.Event{Type: "authz.decision", OrgID: e.orgID, CorrelationID: correlationID(ctx), Detail: detail}
	who, err := e.subject(ctx, req.Subject.ID, sessionFromContext(req.Context))
	if err != nil {
		e.s.log.Error("recording an authorization decision", "err", err, "correlation_id", correlationID(ctx))
		return
	}
	event.SubjectID = who.userID
	if req.Subject.Type != "user" {
		detail["subject"] = authzen.Ref(req.Subject.Type, req.Subject.ID)
	}
	e.s.auditDetached(ctx, event)
}

// sampled decides one decision's fate. From the system's generator only so that
// this file adds nothing to the weak-randomness findings to read through.
func sampled(rate float64) bool {
	if rate <= 0 {
		return false
	}
	if rate >= 1 {
		return true
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false
	}
	return float64(binary.BigEndian.Uint64(b[:]))/math.MaxUint64 < rate
}
