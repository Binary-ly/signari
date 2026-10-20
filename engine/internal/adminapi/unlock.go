package adminapi

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// unlockUser clears what wrong guesses charged to one person (4.06): the
// password step's growing delay, the sign-in form's per-account budget under
// each name they sign in with, and the second-factor step's. The delay decays
// by itself within the hour; this is for the person on the telephone who
// cannot wait, and nothing let an administrator do it.
//
// Not a way past anything: the next wrong password is charged as before, and
// the per-address budgets, which belong to whoever is guessing, are left.
func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")
	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	var cleared int
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		n, err := store.UnlockAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		cleared = n
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.user_unlocked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID, Detail: map[string]any{"counts_cleared": n},
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	case err != nil:
		s.log.Error("unlocking a user", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": userID, "counts_cleared": cleared, "config_version": version,
	})
}
