package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

type eraseSubjectRequest struct {
	// ConfirmSubjectID must repeat the identifier in the path.
	//
	// Not a boolean. A `{"confirm": true}` is satisfied by any request body a
	// client sends by habit, and by a request replayed against a different path.
	// Requiring the identifier means the confirmation names WHICH subject, which
	// is the only mistake this endpoint can make that nobody can undo.
	ConfirmSubjectID string `json:"confirm_subject_id"`
	// Deactivate says what should happen to a still-active account. See
	// store.EraseSubject for why an active one is refused without it.
	Deactivate bool `json:"deactivate"`
}

// eraseSubject crypto-shreds a subject.
func (s *Server) eraseSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subjectID := r.PathValue("subjectID")

	var req eraseSubjectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.ConfirmSubjectID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "confirmation_required",
			"detail": "erasure is permanent. Repeat the subject identifier in " +
				"confirm_subject_id to proceed",
		})
		return
	}
	if req.ConfirmSubjectID != subjectID {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "confirmation_mismatch",
			"detail": "confirm_subject_id does not match the subject in the path, so " +
				"this would have erased a different subject than the one confirmed",
		})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rep, err := store.EraseSubject(ctx, tx, subjectID, req.Deactivate)
	switch {
	case errors.Is(err, store.ErrSubjectUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":  "unknown_subject",
			"detail": "no subject key exists for that identifier, so there is nothing to destroy",
		})
		return
	case errors.Is(err, store.ErrAlreadyErased):
		// 409 rather than 200. The caller asked for a state change that did not
		// happen; reporting success would make a repeated request indistinguishable
		// from a first one, and "when was this erased" is an audit question.
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":  "already_erased",
			"detail": "that subject was already erased; the earlier erasure stands",
		})
		return
	case errors.Is(err, store.ErrSubjectStillActive):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "account_still_active",
			"detail": "an erased subject can never hold a key again, so an active " +
				"account whose key is destroyed fails permanently. Deactivate it " +
				"first, or send deactivate: true",
		})
		return
	case err != nil:
		s.log.Error("erasing a subject", "err", err, "subject", subjectID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Audited BEFORE the commit, inside the same transaction, so the record and
	// the destruction cannot diverge. An erasure with no audit entry is
	// indistinguishable from data loss.
	actor := ""
	if p, ok := principalFrom(ctx); ok {
		actor = p.Name
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.subject_erased", AdminTokenID: TokenIDFrom(ctx),
		OrgID: rep.OrgID, SubjectID: subjectID,
		Detail: map[string]any{
			"deactivated":      rep.Deactivated,
			"totp_credentials": rep.TOTPCredentials,
			"account_found":    rep.AccountFound,
			"actor":            actor,
		},
	}); err != nil {
		// Refused rather than logged and continued. An erasure with no audit
		// record is indistinguishable from data loss, and the whole reason the
		// subject_keys row survives is to be able to show that this happened.
		s.log.Error("auditing an erasure", "err", err, "subject", subjectID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	if err := tx.Commit(ctx); err != nil {
		s.log.Error("committing an erasure", "err", err, "subject", subjectID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.log.Warn("subject erased", "subject", subjectID, "actor", actor,
		"deactivated", rep.Deactivated)

	writeJSON(w, http.StatusOK, map[string]any{
		"subject_id":       subjectID,
		"erased":           true,
		"deactivated":      rep.Deactivated,
		"totp_credentials": rep.TOTPCredentials,
	})
}
