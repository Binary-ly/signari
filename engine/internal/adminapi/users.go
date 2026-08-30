package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// User administration.
//
// These live in the ENGINE, not the console, for a reason that is easy to get
// backwards: the console has no privilege on schema `core` at all (ADR-004), so
// it could not write a user even if it tried. But the deeper reason is that two
// of these operations have consequences the console cannot be trusted to
// remember:
//
//   - Setting a password requires the engine's Argon2 parameters. A hash written
//     with different settings is a credential the login path may not accept.
//   - DEACTIVATING A USER MUST END THEIR SESSIONS. A "deactivated" account whose
//     browser session keeps working is the most common way this operation is
//     implemented wrongly, and it is invisible until someone tests it.

type createUserRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	OrgID    string `json:"org_id"`
	// Password is optional. A user created without one cannot sign in with a
	// password and must use recovery -- which is the correct shape for inviting
	// somebody rather than choosing a password on their behalf.
	Password string `json:"password"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Username = strings.TrimSpace(req.Username)

	if req.OrgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "org_id_required",
			"detail": "a user must belong to an organisation; without one, row-level " +
				"security would make them invisible to every console",
		})
		return
	}
	if err := requireOrg(r.Context(), req.OrgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	if req.Email == "" && req.Username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "identifier_required", "detail": "email or username is required",
		})
		return
	}
	if req.Email != "" {
		if _, err := mail.ParseAddress(req.Email); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_email", "detail": err.Error(),
			})
			return
		}
	}
	// Length is checked, complexity is not. Composition rules push people toward
	// predictable patterns; NIST 800-63B dropped them for that reason.
	if req.Password != "" {
		// The same gate the sign-in paths use. A password an administrator sets
		// is a password somebody will sign in with, and holding it to a lower
		// standard makes this endpoint the way round the policy.
		if _, err := s.pwPolicy.Check(ctx, req.Password, req.Email, nil, s.hasher); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}

	var userID string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		// The 64-byte user_handle is generated HERE and never derived from the
		// email. WebAuthn requires it to be opaque: a handle derived from an
		// address would leak that address to any authenticator holding a
		// credential, and could never change if the address did.
		err := tx.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, username, user_handle, status)
			VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''),
			        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
			               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
			        'active')
			RETURNING id::text`, req.OrgID, req.Email, req.Username).Scan(&userID)
		if err != nil {
			return err
		}

		if req.Password != "" {
			hash, herr := s.hasher.Hash(ctx, req.Password)
			if herr != nil {
				return fmt.Errorf("hashing the password: %w", herr)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, is_current)
				VALUES ($1::uuid, $2::uuid, $3, 'argon2id', true)`,
				userID, req.OrgID, hash); err != nil {
				return err
			}
		}

		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.user_created", AdminTokenID: TokenIDFrom(ctx), OrgID: req.OrgID, SubjectID: userID,
			Detail: map[string]any{"has_password": req.Password != ""},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case err != nil && strings.Contains(err.Error(), "users_org_email_key"),
		err != nil && strings.Contains(err.Error(), "users_org_username_key"):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "already_exists", "detail": "that email or username is taken in this organisation",
		})
		return
	case err != nil:
		s.log.Error("creating user", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)

	s.log.Info("user created", "user_id", userID, "org_id", req.OrgID, "config_version", version)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": userID, "config_version": version,
	})
}

type patchUserRequest struct {
	// Pointers so absent and false stay distinguishable -- a PATCH that does not
	// mention `active` must not deactivate the account.
	Active   *bool   `json:"active"`
	Password *string `json:"password"`
	// RequirePasswordChange makes the next sign-in ask for a new password
	// before a session exists. This is what makes "set a temporary password"
	// mean anything.
	RequirePasswordChange *bool `json:"require_password_change"`
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")

	var req patchUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Active == nil && req.Password == nil && req.RequirePasswordChange == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "nothing_to_change", "detail": "no supported field present",
		})
		return
	}
	if req.Password != nil {
		previous, perr := store.RecentPasswordHashes(ctx, s.db, userID, s.pwPolicy.HistoryDepth)
		if perr != nil {
			s.log.Error("reading password history", "err", perr)
		}
		identity, _ := store.EmailForUser(ctx, s.db, userID)
		if _, err := s.pwPolicy.Check(ctx, *req.Password, identity, previous, s.hasher); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}

	var orgID string
	var sessionsEnded int
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
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

		if req.Active != nil {
			status := "active"
			if !*req.Active {
				status = "deactivated"
			}
			if _, err := tx.Exec(ctx,
				`UPDATE core.users SET status = $2, updated_at = now() WHERE id = $1::uuid`,
				userID, status); err != nil {
				return err
			}

			// THE part that is usually missed. Setting a status flag does not sign
			// anyone out: their cookie keeps working until it expires, so a
			// "deactivated" account can keep using every application it was signed
			// in to. Termination goes through the single path so relying parties
			// are told as well.
			if !*req.Active {
				term, err := store.TerminateSessions(ctx, tx, "", userID, store.ReasonUserDeactivated)
				if err != nil {
					return fmt.Errorf("ending sessions for the deactivated user: %w", err)
				}
				if term != nil {
					sessionsEnded = term.Sessions
				}
			}
		}

		if req.Password != nil {
			// Recorded BEFORE it is replaced -- afterwards would file the new
			// password as a previous one and refuse it at the next change.
			if s.pwPolicy.HistoryDepth > 0 {
				if rerr := store.RetirePassword(ctx, tx, userID, orgID); rerr != nil {
					s.log.Error("recording the retired password", "err", rerr)
				}
			}
			hash, herr := s.hasher.Hash(ctx, *req.Password)
			if herr != nil {
				return fmt.Errorf("hashing the password: %w", herr)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, is_current)
				VALUES ($1::uuid, $2::uuid, $3, 'argon2id', true)
				ON CONFLICT (user_id) DO UPDATE SET
					hash = EXCLUDED.hash, algorithm = 'argon2id', is_current = true,
					failed_attempts = 0, throttled_until = NULL, updated_at = now(),
					-- Cleared with the password they belonged to. A stale
					-- must_change would ask the user to replace a password an
					-- administrator has just deliberately set for them.
					must_change = false, must_change_reason = NULL,
					last_breach_check = NULL`,
				userID, orgID, hash); err != nil {
				return err
			}
			// An administrator setting a password is a credential change, and every
			// existing session predates it. Ending them is the difference between
			// "the password changed" and "the account is under control again".
			term, err := store.TerminateSessions(ctx, tx, "", userID, store.ReasonPasswordChange)
			if err != nil {
				return fmt.Errorf("ending sessions after a password change: %w", err)
			}
			if term != nil {
				sessionsEnded += term.Sessions
			}
		}
		// AFTER the password write, which clears the flag: an administrator
		// setting a temporary password and requiring it be changed must end up
		// with the flag set, and the two orders give opposite answers.
		if req.RequirePasswordChange != nil && *req.RequirePasswordChange {
			// A message KEY, not a sentence: this is written now and rendered on
			// a page that may be in another language later. See
			// httpapi.renderChangeReason.
			if err := store.RequirePasswordChange(ctx, tx, userID,
				"reason.administrator"); err != nil {
				return fmt.Errorf("requiring a password change: %w", err)
			}
		}

		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.user_updated", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{
				"active_set":     req.Active != nil,
				"password_set":   req.Password != nil,
				"must_change":    req.RequirePasswordChange != nil && *req.RequirePasswordChange,
				"sessions_ended": sessionsEnded,
			},
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
		s.log.Error("patching user", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)

	s.log.Info("user updated", "user_id", userID, "sessions_ended", sessionsEnded,
		"config_version", version)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": userID, "sessions_ended": sessionsEnded, "config_version": version,
	})
}

// deleteUser removes a person and everything they hold.
//
// # Sessions are TERMINATED before the row goes, not cascaded away
//
// This is the whole difficulty of the operation and it is invisible if you only
// read the schema. Forty foreign keys point at core.users and every one is
// CASCADE or SET NULL, so `DELETE FROM core.users` succeeds on its own and
// takes the sessions with it. It also tells nobody.
//
// A session row disappearing is not a logout. The applications the person
// reached hold their own sessions, and they find out only because this server
// sends a back-channel logout notice to each. Cascading the rows away destroys
// the list of who to notify before anything is notified, so the person stays
// signed in to every relying party they had reached -- with the account they
// were signed in as no longer existing -- until each application's own session
// expires on its own schedule.
//
// So store.TerminateSessions runs FIRST, inside the same transaction: it
// snapshots the relying parties, queues a notice for each, and only then does
// the DELETE remove what it snapshotted. Both commit together, so there is no
// state where the notices are queued and the user survives, or the user is gone
// and the notices were never raised.
//
// store.ReasonUserDeleted rather than ReasonAdminRevoke, because the reason
// reaches the notice and "your account was deleted" and "an administrator ended
// your session" are different events to the receiving application.
//
// # Real deletion (ADR-005)
//
// No `deleted_at`. A soft delete means every hot-path query must remember `AND
// deleted_at IS NULL`, and forgetting once authenticates somebody who was
// deleted. Deactivation already exists for the reversible case and is a
// different operation with a different verb.
//
// core.audit_events has NO foreign key to core.users, so the trail describing
// what this person did outlives them. That is deliberate and it is the reason
// deletion can be real: erasing the account does not erase the record.
//
// Erasure of personal data is a separate operation, POST
// /admin/subjects/{id}/erase, because "remove this account" and "make this
// person unidentifiable in the record" are different requests and conflating
// them means one of the two is always wrong.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var ended, notified, tokens int
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

		// Counted before the cascade. "How much did this revoke" is asked
		// afterwards, by which time the rows are gone.
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM core.access_tokens WHERE user_id = $1::uuid`,
			userID).Scan(&tokens); err != nil {
			return err
		}

		term, err := store.TerminateSessions(ctx, tx, "", userID, store.ReasonUserDeleted)
		if err != nil {
			return err
		}
		if term != nil {
			ended, notified = term.Sessions, term.Notices
		}

		if _, err := tx.Exec(ctx,
			`DELETE FROM core.users WHERE id = $1::uuid`, userID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.user_deleted", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{
				"sessions_ended": ended,
				"notices_queued": notified,
				"tokens_revoked": tokens,
			},
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
		s.log.Error("deleting a user", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	s.log.Warn("user deleted", "user_id", userID, "sessions_ended", ended,
		"tokens_revoked", tokens, "config_version", version)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": userID, "sessions_ended": ended, "notices_queued": notified,
		"tokens_revoked": tokens, "config_version": version,
	})
}
