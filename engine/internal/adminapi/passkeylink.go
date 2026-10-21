package adminapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// linkRefused is an account a passkey link cannot be sent for.
type linkRefused string

func (e linkRefused) Error() string { return string(e) }

// issuePasskeyLink emails a person a single-use link to register a passkey
// with no session (migration 0176): a new starter with no password, or
// somebody whose only way in is lost. The answer names the link and when it
// ends, never its token, which is minted as the email is sent; the
// administrator who issues it cannot use it, only the address's holder can.
func (s *Server) issuePasskeyLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")

	var req struct {
		// TTLSeconds is how long it works, from a minute to seven days; 0 is a day.
		TTLSeconds int64 `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil &&
		!errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "detail": err.Error()})
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if req.TTLSeconds != 0 && (ttl < time.Minute || ttl > store.MaxPasskeyLinkTTL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_ttl", "detail": "ttl_seconds is from 60 to 604800, or 0 for a day",
		})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var link store.PasskeyLink
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID, status, email string
		if err := tx.QueryRow(ctx, `SELECT org_id::text, status, COALESCE(email, '')
			FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID, &status, &email); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		// Refused rather than queued to fail: a link nobody can receive, or for
		// an account that cannot sign in, would be reported issued and do nothing.
		switch {
		case status != "active":
			return linkRefused("the account is not active")
		case email == "":
			return linkRefused("the account has no email address to send the link to")
		}
		var err error
		if link, err = store.IssuePasskeyLink(ctx, tx, userID, orgID, ttl); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.passkey_link_issued", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{"link_id": link.ID, "expires_at": link.ExpiresAt.UTC().Format(time.RFC3339)},
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
	case errors.As(err, new(linkRefused)):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot_send_link", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("issuing a passkey link", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": userID, "link_id": link.ID,
		"expires_at":     link.ExpiresAt.UTC().Format(time.RFC3339),
		"config_version": version,
	})
}
