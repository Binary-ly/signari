package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// The sessions a user is signed in on, and the buttons that end them.
//
// ASVS V7.5.2: a user should be able to "view and (having authenticated again
// with at least one factor) terminate any or all currently active sessions". The
// termination mechanism (store.TerminateSessions) already existed and the admin
// path used it; what was missing was the page where the person whose sessions
// they are can see them and press the button. The "authenticated again" clause is
// satisfied here by the session cookie plus a CSRF token -- the person is signed
// in on this browser -- which is the practical floor. Nothing asks for a fresh
// sign-in before ending a session, and no setting can yet; putting every
// changing /account route behind one is 4.04. This said an operator could layer
// a step-up on these routes, which nothing let them do.

type sessionRow struct {
	SID       string
	UserAgent string
	How       string // a plain-language "signed in with ..." from acr/amr
	Signed    string // when the session was established
	Current   bool
}

// handleSessions lists the user's live sessions.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/sessions"), http.StatusSeeOther)
		return
	}

	sessions, err := store.ListUserSessions(ctx, s.db, userID, sid)
	if err != nil {
		s.log.Error("listing sessions", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	rows := make([]sessionRow, 0, len(sessions))
	for _, ss := range sessions {
		rows = append(rows, sessionRow{
			SID:       ss.SID,
			UserAgent: describeUserAgent(ss.UserAgent),
			How:       describeAuth(ss.AMR),
			Signed:    ss.CreatedAt.Format("2 January 2006, 15:04 UTC"),
			Current:   ss.Current,
		})
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("issuing a CSRF token", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	htmlPageHeaders(w)
	s.renderPage(w, r, "sessions", map[string]any{
		"Sessions": rows,
		"CSRF":     csrf,
		"Message":  r.URL.Query().Get("m"),
	})
}

// handleSessionsRevoke ends one session, or all of them.
func (s *Server) handleSessionsRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		http.Error(w, "that request could not be verified", http.StatusBadRequest)
		return
	}
	curSID, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/sessions"), http.StatusSeeOther)
		return
	}
	target := strings.TrimSpace(r.PostForm.Get("sid"))
	if target == "" {
		http.Redirect(w, r, "/account/sessions", http.StatusSeeOther)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var term *store.Terminated
	var msg string
	if target == "all" {
		// Everywhere, including this browser -- "sign out everywhere" is a real
		// answer to "my account may be compromised", and leaving the current
		// session alive would be the wrong one in exactly that case.
		term, err = store.TerminateSessions(ctx, tx, "", userID, store.ReasonUserRevoke)
		msg = "Signed out of every session, on every device."
	} else {
		// One session, and it must be one of THIS user's. TerminateSessions keys on
		// the sid alone, so ownership is checked here first -- a sid arriving in a
		// form field must not let one account end another's session.
		owned, oerr := userOwnsSession(ctx, tx, userID, target)
		if oerr != nil {
			s.log.Error("checking session ownership", "err", oerr)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		if !owned {
			// Not this user's session (or already gone). Answered the same as a
			// no-op so nothing here confirms whether a guessed sid exists.
			http.Redirect(w, r, "/account/sessions", http.StatusSeeOther)
			return
		}
		term, err = store.TerminateSessions(ctx, tx, target, "", store.ReasonUserRevoke)
		if target == curSID {
			msg = "That session was ended. It was this one, so you are now signed out here too."
		} else {
			msg = "That session was ended."
		}
	}
	if err != nil {
		s.log.Error("revoking sessions", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "session.user_revoked", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"scope": revokeScope(target), "sessions_ended": term.Sessions,
		},
	}); aerr != nil {
		s.log.Error("recording a session revocation", "err", aerr)
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/account/sessions?m="+url.QueryEscape(msg), http.StatusSeeOther)
}

// userOwnsSession reports whether a live session belongs to a user.
func userOwnsSession(ctx context.Context, tx pgx.Tx, userID, sid string) (bool, error) {
	var owned bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS(
		  SELECT 1 FROM core.sessions
		  WHERE sid = $1 AND user_id = $2::uuid AND revoked_at IS NULL)`,
		sid, userID).Scan(&owned)
	return owned, err
}

func revokeScope(target string) string {
	if target == "all" {
		return "all"
	}
	return "one"
}

// describeAuth returns the MESSAGE KEY for how a session signed in, so the
// template renders it in the reader's language via {{T .How}} rather than this
// function deciding the words. Derived from amr alone, through the same
// predicate every MFA decision uses: this once labelled every password session
// "more than one factor", because a password session's acr is "1" and the test
// was acr != "0".
func describeAuth(amr []string) string {
	multi := oauth.IsMultiFactor(amr)
	// Which label, not whether it was multi-factor: that is `multi`.
	passkey := slices.Contains(amr, "webauthn") || slices.Contains(amr, oauth.AMRHardwareKey) ||
		slices.Contains(amr, "swk")
	switch {
	case passkey:
		return "sessions.how.passkey"
	case multi && slices.Contains(amr, oauth.AMRPassword):
		return "sessions.how.mfa"
	case multi:
		return "sessions.how.multifactor"
	default:
		return "sessions.how.password"
	}
}

// maxSessionUserAgent bounds what a session row keeps of the User-Agent header,
// which the client writes and may make as long as the server accepts.
const maxSessionUserAgent = 256

// sessionDevice is what a new session records about the browser that opened it:
// the User-Agent, trimmed, and a keyed hash of the address (keys.AddressHash).
// Both were columns from the start and nothing wrote either, so every session a
// person was shown looked the same and the admin list said no address was known.
//
// No root key, no hash: an unkeyed one would be reversible, and the address
// itself is not kept.
func (s *Server) sessionDevice(r *http.Request) (userAgent *string, ipHash []byte) {
	ua := strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f || c == utf8.RuneError {
			return -1
		}
		return c
	}, strings.TrimSpace(r.UserAgent()))
	for len(ua) > maxSessionUserAgent {
		_, size := utf8.DecodeLastRuneInString(ua)
		ua = ua[:len(ua)-size]
	}
	if ua != "" {
		userAgent = &ua
	}
	if ip := clientIP(r); ip != "" && s.root != nil {
		ipHash = s.root.AddressHash(ip)
	}
	return userAgent, ipHash
}

// describeUserAgent trims a raw User-Agent to something legible without pretending
// to a device dossier. The raw string is DATA (like an application name), shown
// as-is; an empty value is left empty so the template can render a translated
// fallback rather than an English one baked in here.
func describeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if len(ua) > 120 {
		ua = ua[:120]
	}
	return ua
}
