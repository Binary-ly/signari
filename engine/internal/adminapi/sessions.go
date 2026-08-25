package adminapi

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Sessions: seeing who is signed in, and ending it.
//
// This is the operation an operator reaches for during an incident -- somebody's
// laptop is gone, a token leaked, an account is behaving oddly -- and until now
// it existed only as a CLI verb on the host. An incident response that requires
// SSH is one that happens slower than it needs to.
//
// # Revocation goes through store.TerminateSessions, never a direct UPDATE
//
// Setting `revoked_at` by hand would end the session in this database and tell
// nobody. TerminateSessions snapshots the relying parties first and queues a
// back-channel logout for each, so the applications the person is signed in to
// find out. A revocation the applications never hear about leaves them signed in
// everywhere that matters while the identity provider reports success -- which is
// the failure this codebase has a single termination path to prevent.
//
// # No credential material, and no raw addresses
//
// The listing reports the user agent and whether an address is on file, never the
// address itself. `core.sessions.ip_hash` is a hash for exactly that reason, and
// an admin API that reverses that decision by returning it would undo a
// deliberate one.

type sessionSummary struct {
	SID       string   `json:"sid"`
	UserID    string   `json:"user_id"`
	OrgID     string   `json:"org_id"`
	ACR       string   `json:"acr"`
	AMR       []string `json:"amr"`
	AuthTime  string   `json:"auth_time"`
	NotAfter  string   `json:"not_after"`
	UserAgent string   `json:"user_agent"`
	// HasAddress reports whether an address hash is recorded, without returning
	// it. Enough to tell two sessions apart in a list; not enough to locate
	// anybody.
	HasAddress bool   `json:"has_address"`
	CreatedAt  string `json:"created_at"`
}

// listUserSessions returns the LIVE sessions for one user.
//
// Live only. A revoked or expired session is not something an operator can act
// on, and including them would bury the two that matter under a month of
// history.
func (s *Server) listUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")

	var orgID string
	if err := s.db.QueryRow(ctx,
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_user_id", "detail": "the user id must be a UUID",
		})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	rows, err := s.db.Query(ctx, `
		SELECT sid, user_id::text, org_id::text, acr, amr,
		       to_char(auth_time, 'YYYY-MM-DD"T"HH24:MI:SS.USOF'),
		       to_char(not_after, 'YYYY-MM-DD"T"HH24:MI:SS.USOF'),
		       coalesce(user_agent, ''), (ip_hash IS NOT NULL),
		       to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
		  FROM core.sessions
		 WHERE user_id = $1::uuid AND revoked_at IS NULL AND not_after > now()
		 ORDER BY created_at DESC
		 LIMIT $2`, userID, maxPageSize)
	if err != nil {
		s.log.Error("listing sessions", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()

	out := make([]sessionSummary, 0, 8)
	for rows.Next() {
		var ss sessionSummary
		if err := rows.Scan(&ss.SID, &ss.UserID, &ss.OrgID, &ss.ACR, &ss.AMR,
			&ss.AuthTime, &ss.NotAfter, &ss.UserAgent, &ss.HasAddress,
			&ss.CreatedAt); err != nil {
			s.log.Error("scanning a session", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, ss)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing sessions", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, map[string]any{"sessions": out})
}

// revokeUserSessions ends every live session for one user.
//
// The incident-response lever. Everything the person is signed in to is told,
// because termination goes through the one path that queues the notices.
func (s *Server) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var ended, notified int
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
		term, err := store.TerminateSessions(ctx, tx, "", userID, store.ReasonAdminRevoke)
		if err != nil {
			return err
		}
		if term != nil {
			ended, notified = term.Sessions, term.Notices
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.sessions_revoked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{"sessions_ended": ended, "notices_queued": notified},
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
		s.log.Error("revoking sessions", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	s.log.Warn("all sessions revoked for a user", "user_id", userID,
		"sessions_ended", ended, "config_version", version)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": userID, "sessions_ended": ended, "notices_queued": notified,
		"config_version": version,
	})
}

// revokeSession ends ONE session.
//
// The narrower lever: a single stolen device, without signing the person out of
// everything else they are legitimately using.
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid := r.PathValue("sid")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var ended, notified int
	var userID string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text, user_id::text FROM core.sessions WHERE sid = $1`,
			sid).Scan(&orgID, &userID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		term, err := store.TerminateSessions(ctx, tx, sid, "", store.ReasonAdminRevoke)
		if err != nil {
			return err
		}
		if term != nil {
			ended, notified = term.Sessions, term.Notices
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.session_revoked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{"sid": sid, "notices_queued": notified},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session_not_found"})
		return
	case err != nil:
		s.log.Error("revoking a session", "sid", sid, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"sid": sid, "user_id": userID, "sessions_ended": ended,
		"notices_queued": notified, "config_version": version,
	})
}
