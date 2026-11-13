package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"

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
	// Read whole first, so an erasure that waits for a second person is kept
	// as it came (approvals.go): the subject's id and whether to deactivate.
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil || json.Unmarshal(raw, &req) != nil {
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

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	// An erasure cannot be undone: where the subject's organisation says so, a
	// second person approves it (V2.3.5). A subject with no account left names
	// no organisation, and is erased by an unscoped token as before.
	var subjectOrg string
	if err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`,
		store.ExactUUIDOrNil(subjectID)).Scan(&subjectOrg); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.log.Error("finding the subject's organisation", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if s.approvalGate(w, r, pre, subjectOrg, store.ApprovalSubjectErasure,
		fmt.Sprintf("erase subject %s (deactivate: %t)", subjectID, req.Deactivate), raw) {
		return
	}

	// Routed through mutateIf, and that is a FIX rather than tidying.
	//
	// This handler used to open its own transaction and commit it directly, so an
	// erasure -- which destroys a subject's data-encryption key and, with
	// `deactivate: true`, ends their account -- never bumped core.config_version.
	// That is precisely the failure this package's own doc comment describes: the
	// write is durable and INVISIBLE, and running engine nodes carry on with the
	// previous configuration until some unrelated write happens to bump the
	// version for it.
	//
	// It was the only mutating handler not using the shared helper, which is how
	// it drifted. A test now walks every mutating route and fails if any of them
	// leaves the version unchanged.
	var rep *store.ErasureReport
	actor := ""
	if p, ok := principalFrom(ctx); ok {
		actor = p.Name
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var eerr error
		rep, eerr = store.EraseSubject(ctx, tx, subjectID, req.Deactivate)
		if eerr != nil {
			return eerr
		}
		// Audited INSIDE the same transaction, so the record and the destruction
		// cannot diverge. An erasure with no audit entry is indistinguishable from
		// data loss, and the surviving subject_keys row exists to show it happened.
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.subject_erased", AdminTokenID: TokenIDFrom(ctx),
			OrgID: rep.OrgID, SubjectID: subjectID,
			Detail: map[string]any{
				"deactivated":      rep.Deactivated,
				"totp_credentials": rep.TOTPCredentials,
				"account_found":    rep.AccountFound,
				"key_shredded":     rep.KeyHeld,
				"account_deleted":  rep.AccountDeleted,
				"sessions_ended":   rep.SessionsEnded,
				"actor":            actor,
			},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrSubjectUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":  "unknown_subject",
			"detail": "that identifier has neither a subject key nor an account",
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
			"detail": "erasing a person removes their account and signs them out " +
				"everywhere; an active one is not ended by omission. Deactivate it " +
				"first, or send deactivate: true",
		})
		return
	case err != nil:
		s.log.Error("erasing a subject", "err", err, "subject", subjectID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	setETag(w, version)
	s.log.Warn("subject erased", "subject", subjectID, "actor", actor,
		"deactivated", rep.Deactivated, "config_version", version)

	writeJSON(w, http.StatusOK, map[string]any{
		"subject_id":       subjectID,
		"erased":           true,
		"deactivated":      rep.Deactivated,
		"key_shredded":     rep.KeyHeld,
		"account_deleted":  rep.AccountDeleted,
		"sessions_ended":   rep.SessionsEnded,
		"notices_queued":   rep.NoticesQueued,
		"totp_credentials": rep.TOTPCredentials,
		"config_version":   version,
	})
}
