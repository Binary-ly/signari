package httpapi

import (
	"context"
	"net/http"
	"strings"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/store"
)

// /account/delete: a person deleting their own account (5.07).
//
// Deletion was an operator's act only -- `signari erase subject` and the Admin
// API -- so somebody who wanted to leave had to ask, and the flow language's
// `unenrolment` designation had nothing to drive. Now the organisation's
// unenrolment flow decides: its proving stage is the sign-in that reached the
// page, which must be recent and may not be an impersonation (the same gate
// every change to the account passes), and each proof counts only for itself,
// as at sign-in; `deny` closes self-service deletion; `done` erases the person
// exactly as the Admin API does: the key their data is sealed under destroyed,
// every session ended with each relying party sent a back-channel logout, the
// account and everything keyed by it deleted. The person types their address
// or username to confirm, so a stray click on a page that is already open
// deletes nothing.

// unenrolmentSettledStages are the proving stages an unenrolment passes from
// the session's own sign-in, each only by its own proof. With the cases
// walkUnenrolment acts on they are flow.Drivable(flow.Unenrolment), and
// TestEveryStageAFlowCanUseIsDriven holds the two to the same set.
var unenrolmentSettledStages = map[flow.StageName]string{
	flow.StagePassword:  "a password sign-in",
	flow.StagePasskey:   "a passkey sign-in",
	flow.StageKerberos:  "a Kerberos sign-in",
	flow.StageFederated: "a provider's sign-in",
	flow.StageEmailOTP:  "a sign-in by emailed code",
}

// unenrolmentFacts answers what an unenrolment flow may branch on: which way
// the person signed in. TestEveryConditionAFlowCanUseIsAnswered compares these
// with flow.Answered(flow.Unenrolment).
func unenrolmentFacts(amr []string) flow.State {
	p := primaryProof(amr)
	return flow.State{
		string(flow.CondProvedByPassword):  p == flow.StagePassword,
		string(flow.CondProvedByPasskey):   p == flow.StagePasskey,
		string(flow.CondProvedByKerberos):  p == flow.StageKerberos,
		string(flow.CondProvedByFederated): p == flow.StageFederated,
		string(flow.CondProvedByEmail):     p == flow.StageEmailOTP,
	}
}

// walkUnenrolment reports whether the organisation's unenrolment flow lets this
// sign-in delete the account. It fails closed: no flow, a stage it cannot run,
// a proof other than the one the session holds, or `deny` all refuse.
func (s *Server) walkUnenrolment(ctx context.Context, orgID string, amr []string) bool {
	fl := s.flowFor(ctx, s.db, orgID, flow.Unenrolment)
	if fl == nil {
		return false
	}
	for _, stage := range fl.Plan(unenrolmentFacts(amr)) {
		switch stage {
		case flow.StageDeny:
			return false
		case flow.StageDone:
			return true
		default:
			if _, settled := unenrolmentSettledStages[stage]; !settled || primaryProof(amr) != stage {
				return false
			}
		}
	}
	return false
}

// sessionAMR is what a session's sign-in proved.
func (s *Server) sessionAMR(ctx context.Context, sid string) ([]string, error) {
	var amr []string
	err := s.db.QueryRow(ctx, `SELECT COALESCE(amr, '{}') FROM core.sessions WHERE sid = $1`, sid).Scan(&amr)
	return amr, err
}

// accountIdentifiers are what the person may type to confirm: their address
// and their username.
func (s *Server) accountIdentifiers(ctx context.Context, userID string) (email, username string, err error) {
	err = s.db.QueryRow(ctx, `SELECT COALESCE(email, ''), COALESCE(username, '') FROM core.users
		WHERE id = $1::uuid`, userID).Scan(&email, &username)
	return email, username, err
}

// handleAccountDelete shows the page.
func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/delete"), http.StatusSeeOther)
		return
	}
	amr, err := s.sessionAMR(ctx, sid)
	if err != nil {
		s.log.Error("reading the session's sign-in", "err", err)
	}
	s.renderAccountDelete(w, r, userID, !s.walkUnenrolment(ctx, orgID, amr), "")
}

func (s *Server) renderAccountDelete(w http.ResponseWriter, r *http.Request, userID string, closed bool, errMsg string) {
	email, username, err := s.accountIdentifiers(r.Context(), userID)
	if err != nil {
		s.log.Error("reading the account's identifiers", "err", err)
	}
	confirm := email
	if confirm == "" {
		confirm = username
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "accountdelete", map[string]any{
		"Closed": closed, "Confirm": confirm, "Error": errMsg, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleAccountDeletePost erases the account.
func (s *Server) handleAccountDeletePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/delete"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; reload and try again")
		return
	}
	// A recent sign-in, never an impersonation: an administrator acting as
	// somebody must not be able to delete them from their own page.
	if s.credentialChangeRefused(w, r, sid, "/account/delete", false) {
		return
	}
	amr, err := s.sessionAMR(ctx, sid)
	if err != nil {
		s.log.Error("reading the session's sign-in", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if !s.walkUnenrolment(ctx, orgID, amr) {
		s.renderAccountDelete(w, r, userID, true, "")
		return
	}
	email, username, err := s.accountIdentifiers(ctx, userID)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	typed := strings.TrimSpace(r.PostForm.Get("confirm"))
	if typed == "" || !(strings.EqualFold(typed, email) || strings.EqualFold(typed, username)) {
		s.renderAccountDelete(w, r, userID, false, s.tr(r).Text("error.accountdelete.confirm"))
		return
	}
	// Read before the account goes: the language for the last message.
	tr := s.notifierFor(ctx, userID)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rep, err := store.EraseSubject(ctx, tx, userID, true)
	if err != nil {
		s.log.Error("erasing an account at its owner's request", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	// In the erasure's transaction, as the Admin API's is: an erasure with no
	// record is indistinguishable from data loss. Counts only -- nothing that
	// names the person.
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "account.deleted", OrgID: orgID, SubjectID: userID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"by": "owner", "key_shredded": rep.KeyHeld,
			"sessions_ended": rep.SessionsEnded, "logout_notices": rep.NoticesQueued},
	}); err != nil {
		s.log.Error("auditing an account deletion", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	// One last message to the address it had, after the commit: whoever did
	// this may not have been the account's holder, and they are the one who
	// must hear it. Nothing is kept to send it again.
	if email != "" {
		if err := s.mailer.Send(ctx, mail.Message{To: email, Subject: tr.Text("mail.accountdeleted.subject"),
			Body: tr.Text("mail.accountdeleted.body")}); err != nil {
			s.log.Warn("telling a deleted account's address it was deleted", "err", err)
		}
	}
	s.clearSessionCookie(w)
	csrf, _ := s.csrfToken(w, r)
	s.renderPage(w, r, "accountdelete", map[string]any{"Deleted": true, "CSRF": csrf, "CSRFField": csrfFormField})
}
