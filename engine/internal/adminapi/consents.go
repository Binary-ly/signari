package adminapi

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// A person's consents and grants, over the Admin API (6.08). An administrator
// helping somebody whose application is acting oddly could neither see what
// it had been given nor take it away: only the person could, from
// /account/connected. Taking it away goes through the same path that page
// does, store.DisconnectApp, which withdraws the consent and revokes the
// refresh grants in one transaction, so the application is asked again and
// can no longer refresh.

type consentView struct {
	ClientID     string     `json:"client_id"`
	DisplayName  string     `json:"display_name"`
	Scopes       []string   `json:"scopes"`
	GrantedAt    time.Time  `json:"granted_at"`
	ActiveTokens int        `json:"active_refresh_grants"`
	OfflineUntil *time.Time `json:"offline_until"`
}

// consentUser reads a person's organisation and holds the caller to it.
func (s *Server) consentUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctx := r.Context()
	userID := r.PathValue("userID")
	var orgID string
	if err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id::text = $1`, userID).
		Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return "", false
		}
		s.log.Error("reading a user for their consents", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return "", false
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return "", false
	}
	return orgID, true
}

// listUserConsents is what /account/connected shows the person: each
// application they have consented to or that holds a live grant.
func (s *Server) listUserConsents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.consentUser(w, r); !ok {
		return
	}
	userID := r.PathValue("userID")
	apps, err := store.ConnectedApps(r.Context(), s.db, userID)
	if err != nil {
		s.log.Error("listing a user's consents", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// A token narrowed to named clients sees only those, as its other reads do.
	only := clientFilter(r.Context())
	out := make([]consentView, 0, len(apps))
	for _, a := range apps {
		if only != nil && !slices.Contains(only, a.ClientID) {
			continue
		}
		out = append(out, consentView{ClientID: a.ClientID, DisplayName: a.DisplayName, Scopes: a.Scopes,
			GrantedAt: a.GrantedAt.UTC(), ActiveTokens: a.ActiveTokens, OfflineUntil: utcOrNil(a.OfflineUntil)})
	}
	s.writeList(w, r, map[string]any{"user_id": userID, "consents": out})
}

// revokeUserConsent withdraws a person's consent to one application and
// revokes its refresh grants, as the person can from /account/connected.
func (s *Server) revokeUserConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, ok := s.consentUser(w, r)
	if !ok {
		return
	}
	userID, clientID := r.PathValue("userID"), r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	var revoked int64
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		if revoked, err = store.DisconnectApp(ctx, tx, userID, clientID,
			"an administrator withdrew the consent"); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.consent_revoked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID, ClientID: clientID,
			Detail: map[string]any{"refresh_grants_revoked": revoked}})
	})
	if err != nil && writePreconditionFailure(w, err) {
		return
	}
	if err != nil {
		s.log.Error("revoking a consent", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "client_id": clientID,
		"refresh_grants_revoked": revoked, "config_version": version})
}

func utcOrNil(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
