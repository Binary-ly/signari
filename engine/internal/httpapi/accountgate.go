package httpapi

import (
	"net/http"
)

// Changing how an account signs in.
//
// A live session used to be enough to add, replace, move or remove any factor:
// replace the TOTP (and with it every recovery code), point the email factor
// at another address, register a passkey, link an external account, regenerate
// the recovery codes. So a stolen cookie could be turned into access that
// outlives it -- the attacker's own passkey or linked account signs in long
// after the session is gone -- and an administrator in an impersonation session
// could do the same to the person they were helping.
//
// Two rules, checked together before any of those changes.
//
// An impersonation session changes nothing about how the account signs in. It
// exists so support can see what the person sees, and its tokens carry `act`
// so what it does is attributable; enrolling a credential the administrator
// then holds is neither.
//
// The session must have been authenticated recently. Otherwise the person
// signs in again and comes back to the page. The window is short because what
// it guards is persistent, and it is read against the database clock, the same
// clock auth_time was written with.
//
// The same rule holds every change made from /account, not only to the
// sign-in methods: the password, ending sessions, revoking an application's
// access, and answering a backchannel request. Those were open to any live
// session, so a cookie stolen hours after sign-in could set a password it
// would then know. TestEveryAccountWriteRequiresRecentAuth reads the routes
// and fails on one that does not ask.
//
// The window is the organisation's (migration 0167, `signari instance
// reauth-window`), ten minutes unless set.

// credentialChangeRefused answers a request that would change the account, and
// reports whether it did. dest is the page to come back to after signing in
// again. asJSON answers in the shape the passkey endpoints use, with the
// sign-in location in the body for the page's script to follow.
func (s *Server) credentialChangeRefused(w http.ResponseWriter, r *http.Request,
	sid, dest string, asJSON bool) bool {
	ctx := r.Context()
	var impersonated, recent bool
	if err := s.db.QueryRow(ctx, `
		SELECT s.impersonator_id IS NOT NULL,
		       s.auth_time > now() - make_interval(secs => o.reauth_window_s)
		  FROM core.sessions s JOIN core.organizations o ON o.id = s.org_id
		 WHERE s.sid = $1`, sid).
		Scan(&impersonated, &recent); err != nil {
		s.log.Error("reading the session before a credential change", "err", err)
		if asJSON {
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return true
	}
	switch {
	case impersonated:
		s.log.Warn("credential change refused in an impersonation session",
			"sid", sid, "path", r.URL.Path, "correlation_id", correlationID(ctx))
		const why = "You are signed in as somebody else. Their sign-in methods can " +
			"only be changed by them."
		if asJSON {
			writeError(w, http.StatusForbidden, "impersonation_refused", why)
		} else {
			http.Error(w, why, http.StatusForbidden)
		}
		return true
	case !recent:
		login := parkLogin(dest)
		if asJSON {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "reauthentication_required",
				"error_description": "sign in again to change how this account signs in",
				"location":          login,
			})
		} else {
			http.Redirect(w, r, login, http.StatusSeeOther)
		}
		return true
	}
	return false
}
