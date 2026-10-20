package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/store"
)

// Remembering a device after a second factor (migration 0168).
//
// Offered on the code page when the organisation sets a number of days, and
// chosen by ticking a box. The browser keeps a random token; the database keeps
// its hash, checked at every sign-in, so forgetting a device -- here, by
// signing out everywhere, or by the organisation turning the feature off -- is
// in force at the next one.
//
// What it skips is the flow's `mfa` stage, and only where nobody requires more:
// a client asking for multi-factor, or with a floor of it, is asked for the
// factor whatever the device. The session says what was proved -- the password
// -- so it is single-factor, and a requirement for more is met by asking, not
// by a device that proved nothing this time. Skipping it there instead would
// leave the step-up asking for what the device then skips, for ever.

// DeviceCookieName carries a remembered device's token.
const DeviceCookieName = "__Host-signari_device"

// rememberThisDevice records the device the browser is on for userID, in tx,
// and sets its cookie. It does nothing unless the person asked and the
// organisation offers it.
//
// In the sign-in's own transaction, so a sign-in that is refused remembers
// nothing. One held by a prompt or a password change abandons the transaction,
// and the device is not remembered; the person can tick the box next time.
func (s *Server) rememberThisDevice(ctx context.Context, w http.ResponseWriter, r *http.Request,
	tx pgx.Tx, userID, orgID string) {
	if r.PostForm.Get("remember") != "1" {
		return
	}
	token, err := newSID()
	if err != nil {
		s.log.Error("making a remembered device's token", "err", err)
		return
	}
	ua, _ := s.sessionDevice(r)
	agent := ""
	if ua != nil {
		agent = *ua
	}
	ok, err := store.RememberDevice(ctx, tx, orgID, userID, store.HashToken(token), agent)
	if err != nil || !ok {
		if err != nil {
			s.log.Error("remembering a device", "err", err)
		}
		return
	}
	days, err := store.RememberDeviceDaysForUser(ctx, tx, userID)
	if err != nil || days <= 0 {
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.device_remembered", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx), Detail: map[string]any{"days": days},
	}); err != nil {
		s.log.Error("auditing a remembered device", "err", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name: DeviceCookieName, Value: token, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int((time.Duration(days) * 24 * time.Hour).Seconds()),
	})
}

// handleDevices lists the devices the signed-in person has remembered.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/devices"), http.StatusSeeOther)
		return
	}
	devices, err := store.RememberedDevices(ctx, s.db, userID)
	if err != nil {
		s.log.Error("listing remembered devices", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	type row struct{ ID, UserAgent, When, Until string }
	rows := make([]row, 0, len(devices))
	for _, d := range devices {
		rows = append(rows, row{ID: d.ID, UserAgent: describeUserAgent(d.UserAgent),
			When:  d.CreatedAt.Format("2 January 2006"),
			Until: d.ExpiresAt.Format("2 January 2006")})
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "devices", map[string]any{
		"Devices": rows, "CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleDevicesForget forgets one remembered device, or all of them.
func (s *Server) handleDevicesForget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		http.Error(w, "that request could not be verified", http.StatusBadRequest)
		return
	}
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/devices"), http.StatusSeeOther)
		return
	}
	if s.credentialChangeRefused(w, r, sid, "/account/devices", false) {
		return
	}
	id := r.PostForm.Get("id")
	if id == "all" {
		id = ""
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n, err := store.ForgetDevices(ctx, tx, userID, id)
	if err != nil {
		s.log.Error("forgetting devices", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.device_forgotten", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx), Detail: map[string]any{"devices": n},
	}); err != nil {
		s.log.Error("auditing a forgotten device", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/account/devices", http.StatusSeeOther)
}

// deviceSkipsMFA is the walk's rule for the mfa stage, asked before the walk
// by the password path: a remembered device, and no client requiring more.
func (s *Server) deviceSkipsMFA(ctx context.Context, r *http.Request, orgID, userID, authzQuery string) bool {
	facts := &signInFacts{s: s, ctx: ctx, db: s.db, orgID: orgID, userID: userID, authzQuery: authzQuery}
	return !facts.Holds(string(flow.CondClientRequiresMFA)) && s.deviceRemembered(ctx, r, s.db, orgID, userID)
}

// deviceRemembered reports whether the browser presents a device userID
// remembered that still counts. A failed read counts as none: the question is
// whether to skip a factor, and the answer that cannot let anybody in wrongly
// is to ask for it.
func (s *Server) deviceRemembered(ctx context.Context, r *http.Request, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, userID string) bool {
	c, err := r.Cookie(DeviceCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return false
	}
	ok, err := store.DeviceRemembered(ctx, q, orgID, userID, store.HashToken(c.Value))
	if err != nil {
		s.log.Error("checking a remembered device", "err", err)
		return false
	}
	return ok
}
