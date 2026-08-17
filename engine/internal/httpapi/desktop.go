package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Signing in to a desktop: a Windows credential provider, a PAM module, a kiosk.
//
// # Why this endpoint exists
//
// A native login dialog cannot render our web pages. The user types a username,
// a password and — where policy demands one — a second factor, into a box the
// operating system drew, and something has to answer yes or no in a single
// exchange.
//
// The ordinary flow cannot do that: it is a sequence of pages with a signed
// pending token between them, which is right for a browser and impossible for
// Winlogon.
//
// # What Signari ships and what it does not
//
// This endpoint. The Windows side is a Credential Provider — a COM DLL,
// registered with Winlogon, written in C++ and code-signed — and a Go identity
// engine does not ship one. Saying otherwise would be the kind of claim this
// project exists to avoid making.
//
// What is here is the half that belongs to an identity provider, and it is the
// half a PAM module needs too: `pam_exec` calling this is a working Linux
// desktop login today.
//
// # Why it is not simply the outpost endpoint
//
// Because it verifies a SECOND FACTOR. A token that can do that is worth more
// than one that can only check a bind, so it is a separate outpost kind and an
// LDAP token is refused for it.

// handleDesktopVerify authenticates a desktop login in one exchange.
func (s *Server) handleDesktopVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, kind, name, ok := s.outpostAuth(w, r)
	if !ok {
		return
	}
	if kind != "desktop" {
		writeError(w, http.StatusForbidden, "wrong_kind",
			"this token was issued for a "+kind+" outpost. Desktop login verifies a "+
				"second factor as well as a password, so it needs a token issued for it")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		// Code is the second factor, when one was asked for.
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	body.Username = strings.TrimSpace(body.Username)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	refuse := func(reason string) {
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID,
			CorrelationID: correlationID(ctx),
			Detail: map[string]any{
				"via": "desktop", "outpost": name, "reason": reason,
			},
		})
		// One answer for every reason, as everywhere else: an outpost sits
		// somewhere less trusted, and distinguishing "no such user" from "wrong
		// password" there is a user-enumeration endpoint.
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication refused")
	}

	userID, err := store.FindLocalUserByEmail(ctx, tx, orgID, body.Username)
	if err != nil || userID == "" {
		refuse("no such user")
		return
	}
	if body.Password == "" {
		refuse("no password")
		return
	}

	var stored string
	if err := tx.QueryRow(ctx, `
		SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`,
		userID).Scan(&stored); err != nil {
		refuse("no password credential")
		return
	}
	if _, verr := s.hasher.Verify(ctx, stored, body.Password); verr != nil {
		refuse("wrong password")
		return
	}

	amr := []string{"pwd"}

	// Whether a second factor is needed is decided by the same machinery as
	// everywhere else, so a policy demanding MFA cannot be sidestepped by
	// signing in at a desktop instead of a browser.
	needsMFA, err := store.HasSecondFactor(ctx, s.db, userID)
	if err != nil {
		s.log.Error("checking enrolled factors", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if needsMFA {
		if body.Code == "" {
			// Asked for, rather than refused: the dialog should show a second box
			// and try again, which it cannot know to do from a plain refusal.
			writeJSON(w, http.StatusOK, map[string]any{
				"result": "second_factor_required",
				"prompt": "Enter the code from your authenticator",
			})
			return
		}
		factors, verified, verr := s.verifySecondFactor(ctx, tx, userID, body.Code)
		if verr != nil {
			s.log.Error("verifying a desktop second factor", "err", verr)
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		if !verified {
			refuse("wrong second factor")
			return
		}
		amr = append(amr, factors...)
	}

	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "desktop.login", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"outpost": name, "amr": amr},
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"result": "authenticated",
		"user":   body.Username,
		"amr":    amr,
	})
}
