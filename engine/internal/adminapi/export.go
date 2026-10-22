package adminapi

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// exportSubject returns everything kept about one person (5.08): the document a
// person downloads from /account/export, for an operator answering their
// request for it. A read, so it moves no configuration version, but recorded:
// who was handed a person's data is what an inquiry into a disclosure asks.
func (s *Server) exportSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subjectID, ok := store.CanonicalUUID(r.PathValue("subjectID"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_subject"})
		return
	}

	// The organisation first, before anything is read: a token scoped to one
	// organisation exports only its people, and a subject with no account left
	// names no organisation, so only an unscoped token may export one.
	var orgID string
	err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`, subjectID).Scan(&orgID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.log.Error("exporting a subject", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	exp, err := store.ExportSubject(ctx, tx, subjectID, s.root)
	_ = tx.Rollback(ctx)
	switch {
	case errors.Is(err, store.ErrSubjectUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "unknown_subject", "detail": "that identifier has neither a subject key nor an account",
		})
		return
	case err != nil:
		s.log.Error("exporting a subject", "err", err, "subject", subjectID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Recorded before it is sent, in a transaction of its own: see
	// store.ExportSubject on why not in the snapshot.
	actor := ""
	if p, ok := principalFrom(ctx); ok {
		actor = p.Name
	}
	atx, err := s.db.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer func() { _ = atx.Rollback(ctx) }()
	if err := audit.Write(ctx, atx, audit.Event{
		Type: "admin.subject_exported", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, SubjectID: subjectID,
		Detail: map[string]any{"via": "admin_api", "actor": actor, "rows": exp.Rows()},
	}); err != nil {
		s.log.Error("auditing a subject export", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := atx.Commit(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, exp)
}
