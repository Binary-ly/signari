package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// /account/export: a person downloading everything kept about them (5.08).
//
// The same document `signari export subject` and the Admin API give an
// operator (store.ExportSubject). Behind the gate every change to the account
// passes -- a recent sign-in, never an impersonation -- because the file is all
// of it at once: a session somebody else picked up should not be able to walk
// off with the account's history. Recorded, and the holder told on every
// channel, for the same reason. A POST from the page, never a GET, so a link
// cannot start one.

// handleAccountExport shows the page.
func (s *Server) handleAccountExport(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := s.currentSession(r); !ok {
		http.Redirect(w, r, parkLogin("/account/export"), http.StatusSeeOther)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "accountexport", map[string]any{"CSRF": csrf, "CSRFField": csrfFormField})
}

// handleAccountExportPost sends the file.
func (s *Server) handleAccountExportPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/export"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; reload and try again")
		return
	}
	if s.credentialChangeRefused(w, r, sid, "/account/export", false) {
		return
	}

	// One snapshot, so the sections agree with each other.
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	exp, err := store.ExportSubject(ctx, tx, userID, s.root)
	_ = tx.Rollback(ctx)
	if err != nil {
		s.log.Error("exporting an account for its owner", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	body, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// Recorded before a byte is sent, in a transaction of its own (see
	// store.ExportSubject): no export leaves without its record.
	atx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = atx.Rollback(ctx) }()
	if err := audit.Write(ctx, atx, audit.Event{
		Type: "account.exported", OrgID: orgID, SubjectID: userID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"by": "owner", "rows": exp.Rows()},
	}); err != nil {
		s.log.Error("auditing an account export", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if err := atx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	tr := s.notifierFor(ctx, userID)
	if err := s.notifyAccount(ctx, userID, tr.Text("mail.accountexported.subject"),
		tr.Text("mail.accountexported.body"), tr.Text("sms.accountexported")); err != nil {
		s.log.Error("telling the holder their data was downloaded", "err", err, "user_id", userID)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="account-`+exp.ExportedAt.Format("2006-01-02")+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
