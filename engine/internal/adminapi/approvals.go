package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// A second person for the highest-value changes (ASVS 5.0.0 V2.3.5,
// specs/asvs-5.0.0.txt:1570-1573; store/approvals.go, migration 0296).
//
// An organisation names in approvals_required the kinds that wait: an erasure,
// which cannot be undone, and granting the org-owner role, which is every other
// permission at once. Such a request is kept and answered 202 with the
// approval's id. Somebody else who may make the request approves it, and the
// request is then replayed through the router as theirs: their token, their
// scopes, their organisation, the privileged-target checks and the audit
// record are the approver's, as if they had sent it, and the approval records
// both. So an approval cannot reach further than its approver could alone.
//
// Relaxing approvals_required waits too whenever it takes a kind away, or one
// token could turn the rule off and then act alone. What a database operator
// does with `signari` on the host is theirs: the Admin API is what this holds.

// approvalScope is the scope each kind's request takes, which turning one down
// needs as well (the one who asked may always withdraw it).
var approvalScope = map[string]string{
	store.ApprovalSubjectErasure: ScopeSubjectsErase,
	store.ApprovalOwnerGrant:     ScopeOrganizationsWrite,
	store.ApprovalsRelaxed:       ScopeOrganizationsWrite,
}

var errMayNotReject = errors.New("turning a request down takes the scope it needs, unless you asked for it")

// approvedKey marks a replayed request as approved, for its kind's gate to let
// through. A context value, so no caller can send it.
type approvedKey struct{}

type approvedRequest struct{ id, kind string }

// approverKey names who asked or decided: one person, or one token. A person
// signed in to the console is the person, whichever binding gave them the
// role; a token is itself.
func approverKey(p *Principal) string {
	switch {
	case p == nil:
		return ""
	case p.BreakGlass:
		return "break-glass"
	case p.UserID != "":
		return "user:" + p.UserID
	}
	return "token:" + p.TokenID
}

// approvalGate keeps a request of a kind orgID makes wait, and answers 202, or
// reports false for the handler to go on: the kind is not one that waits, or
// this is the approved replay. body is the request's body as received, kept to
// be replayed; pre is held as the write would have been.
func (s *Server) approvalGate(w http.ResponseWriter, r *http.Request, pre precondition, orgID, kind,
	summary string, body []byte) bool {

	ctx := r.Context()
	if a, ok := ctx.Value(approvedKey{}).(approvedRequest); ok && a.kind == kind {
		return false
	}
	// Nothing kept for an organisation the caller may not act on: the
	// handler's own refusal says so.
	if orgID == "" || requireOrg(ctx, orgID) != nil {
		return false
	}
	if kind != store.ApprovalsRelaxed {
		required, err := store.ApprovalsRequired(ctx, s.db, orgID)
		if err != nil {
			s.log.Error("reading what waits for approval", "org_id", orgID, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return true
		}
		if !slices.Contains(required, kind) {
			return false
		}
	}
	p, _ := principalFrom(ctx)
	var id string
	var expires time.Time
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		id, expires, err = store.RequestApproval(ctx, tx, store.Approval{OrgID: orgID, Kind: kind,
			Method: r.Method, Path: r.URL.RequestURI(), Body: body, Summary: summary,
			RequestedBy: approverKey(p), RequestedName: p.Name})
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.approval_requested", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"approval_id": id, "kind": kind, "summary": summary}})
	})
	if err != nil && writePreconditionFailure(w, err) {
		return true
	}
	if err != nil {
		s.log.Error("keeping a request for approval", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return true
	}
	setETag(w, version)
	writeJSON(w, http.StatusAccepted, map[string]any{"approval_id": id, "status": "pending", "kind": kind,
		"expires_at": expires.UTC().Format(time.RFC3339), "config_version": version,
		"detail": "this organisation has this change wait for a second person: somebody else who may make it " +
			"approves it with POST /admin/approvals/" + id + "/approve"})
	return true
}

// approveRequest claims the approval, replays the request as the approver, and
// records what it answered. Three steps, none holding a transaction across the
// replay, which takes connections of its own.
func (s *Server) approveRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("approvalID")
	p, _ := principalFrom(ctx)
	if !s.approvalInReach(w, r, id) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var a store.Approval
	_, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		a, err = store.ClaimApproval(ctx, tx, id, approverKey(p))
		return err
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrApprovalNotPending):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval_not_pending",
			"detail": "no such approval is waiting: it was decided, is being decided, or expired"})
		return
	case errors.Is(err, store.ErrApprovalSelf):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "approval_by_requester",
			"detail": store.ErrApprovalSelf.Error()})
		return
	case err != nil:
		s.log.Error("claiming an approval", "approval_id", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// The request as it came, as the approver: their Authorization, the
	// console's operator if there is one, the stored body, and no If-Match,
	// which named the version before it waited.
	sub, err := http.NewRequestWithContext(context.WithValue(ctx, approvedKey{}, approvedRequest{a.ID, a.Kind}),
		a.Method, a.Path, bytes.NewReader(a.Body))
	rec := &recorder{header: http.Header{}}
	if err == nil {
		sub.Header.Set("Authorization", r.Header.Get("Authorization"))
		if op := r.Header.Get(OperatorHeader); op != "" {
			sub.Header.Set(OperatorHeader, op)
		}
		if len(a.Body) > 0 {
			sub.Header.Set("Content-Type", "application/json")
			sub.ContentLength = int64(len(a.Body))
		}
		s.mux.Load().ServeHTTP(rec, sub)
	} else {
		rec.code = http.StatusInternalServerError
	}
	if rec.code == 0 {
		rec.code = http.StatusOK
	}

	version, ferr := s.mutate(ctx, func(tx pgx.Tx) error {
		if err := store.FinishApproval(ctx, tx, a.ID, approverKey(p), p.Name, rec.code); err != nil {
			return err
		}
		typ := "admin.approval_granted"
		if rec.code >= 300 {
			typ = "admin.approval_failed"
		}
		return audit.Write(ctx, tx, audit.Event{Type: typ, AdminTokenID: TokenIDFrom(ctx), OrgID: a.OrgID,
			Detail: map[string]any{"approval_id": a.ID, "kind": a.Kind, "requested_by": a.RequestedName,
				"result_status": rec.code}})
	})
	if ferr != nil {
		s.log.Error("recording an approval", "approval_id", a.ID, "err", ferr)
	}
	setETag(w, version)
	// 200 for a change made, whatever its own success was (201 for a grant,
	// say), which result_status carries; the change's own refusal otherwise,
	// and the request goes back to pending: an approver who could not make the
	// change has not used it up.
	code, status := http.StatusOK, "approved"
	if rec.code >= 300 {
		code, status = rec.code, "pending"
	}
	writeJSON(w, code, map[string]any{"approval_id": a.ID, "status": status, "result_status": rec.code,
		"result": json.RawMessage(nonEmptyJSON(rec.body.Bytes())), "config_version": version})
}

// rejectRequest turns one down, the one who asked withdrawing it included.
func (s *Server) rejectRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("approvalID")
	p, _ := principalFrom(ctx)
	if !s.approvalInReach(w, r, id) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		a, err := store.PendingApproval(ctx, tx, id)
		if err != nil {
			return err
		}
		// The one who asked, withdrawing it, or somebody who could have made
		// the change: anybody else turning requests down would be a way to stop
		// every erasure while holding no right to make one.
		if a.RequestedBy != approverKey(p) && !p.Can(approvalScope[a.Kind]) {
			return errMayNotReject
		}
		if err := store.RejectApproval(ctx, tx, id, approverKey(p), p.Name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.approval_rejected", AdminTokenID: TokenIDFrom(ctx),
			OrgID: a.OrgID, Detail: map[string]any{"approval_id": a.ID, "kind": a.Kind,
				"requested_by": a.RequestedName}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrApprovalNotPending):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval_not_pending",
			"detail": "no such approval is waiting: it was decided, is being decided, or expired"})
		return
	case errors.Is(err, errMayNotReject):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope",
			"detail": errMayNotReject.Error()})
		return
	case err != nil:
		s.log.Error("rejecting an approval", "approval_id", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"approval_id": id, "status": "rejected", "config_version": version})
}

// approvalInReach answers for an approval outside the caller's organisation,
// as for any other object there: the same answer whether it exists or not.
func (s *Server) approvalInReach(w http.ResponseWriter, r *http.Request, id string) bool {
	org, err := store.ApprovalOrg(r.Context(), s.db, id)
	if errors.Is(err, store.ErrApprovalNotPending) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval_not_pending",
			"detail": "no such approval is waiting: it was decided, is being decided, or expired"})
		return false
	}
	if err != nil {
		s.log.Error("finding an approval", "approval_id", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return false
	}
	if err := requireOrg(r.Context(), org); err != nil {
		writeCrossOrg(w, err)
		return false
	}
	return true
}

type approvalView struct {
	ID            string  `json:"id"`
	Kind          string  `json:"kind"`
	Method        string  `json:"method"`
	Path          string  `json:"path"`
	Summary       string  `json:"summary"`
	RequestedBy   string  `json:"requested_by"`
	RequestedAt   string  `json:"requested_at"`
	ExpiresAt     string  `json:"expires_at"`
	Status        string  `json:"status"`
	DecidedBy     string  `json:"decided_by,omitempty"`
	DecidedAt     *string `json:"decided_at,omitempty"`
	ResultStatus  *int    `json:"result_status,omitempty"`
	RequestedByMe bool    `json:"requested_by_me"`
}

// listApprovals is an organisation's approvals, newest first, without bodies.
func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.ListApprovals(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing approvals", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	p, _ := principalFrom(ctx)
	me := approverKey(p)
	out := make([]approvalView, 0, len(got))
	for _, a := range got {
		v := approvalView{ID: a.ID, Kind: a.Kind, Method: a.Method, Path: a.Path, Summary: a.Summary,
			RequestedBy: a.RequestedName, RequestedAt: a.RequestedAt.UTC().Format(time.RFC3339),
			ExpiresAt: a.ExpiresAt.UTC().Format(time.RFC3339), Status: a.Status, DecidedBy: a.DecidedName,
			ResultStatus: a.ResultStatus, RequestedByMe: a.RequestedBy == me}
		if a.DecidedAt != nil {
			at := a.DecidedAt.UTC().Format(time.RFC3339)
			v.DecidedAt = &at
		}
		out = append(out, v)
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "approvals": out})
}
