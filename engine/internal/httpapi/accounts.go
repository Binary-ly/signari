package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// Several accounts in one browser, and choosing between them (5.17).
//
// The session cookie holds the account in use. Signing in as somebody else
// used to overwrite it, so a person with a work and a personal account signed
// one out to use the other, and `prompt=select_account` could only ask for a
// fresh sign-in. Now the others are parked in two more cookies, as their
// session cookies' tokens: one that ends with the browser and one that
// outlasts it, so each parked session keeps the lifetime it was given
// (sessions.persistent, 0185). `prompt=select_account` and the sign-in page's
// "choose an account" show the picker, and choosing one swaps it into the
// session cookie.
//
// Every token is resolved against core.sessions each time the picker is shown
// or a choice is made, so a session revoked elsewhere is never offered
// (ADR-007), and it is dropped from the cookies the next time they are written.
// Showing the picker does not count as using the sessions it lists, so it moves
// no idle deadline; choosing one does. An impersonation session is never
// parked or offered: leaving one goes through its own end, not a switch.
//
// A sign-out ends every account the browser holds (handleEndSession): on a
// shared computer that is what signing out means.

const (
	// ParkedCookieName holds the parked sessions that end with the browser.
	ParkedCookieName = "__Host-signari_accounts"
	// KeptParkedCookieName holds the parked sessions that were signed in to
	// stay signed in, where the organisation offers it.
	KeptParkedCookieName = "__Host-signari_accounts_kept"
	// maxParkedAccounts bounds the accounts beside the one in use.
	maxParkedAccounts = 4
)

// heldAccount is one session this browser holds.
type heldAccount struct {
	token, sid, userID, orgID, name string
	active                          bool
	// keepFor is how long a cookie holding it may last: what the session has
	// left, for one signed in to stay signed in where that is offered; 0
	// otherwise, a cookie that ends with the browser.
	keepFor int
}

// validSessionToken is the shape newSID makes: 32 random bytes, base64url.
func validSessionToken(v string) bool {
	if len(v) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// parkedTokens reads both parked cookies, in their order, once each.
func parkedTokens(r *http.Request) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range []string{KeptParkedCookieName, ParkedCookieName} {
		c, err := r.Cookie(name)
		if err != nil {
			continue
		}
		for _, tok := range strings.Split(c.Value, ".") {
			if validSessionToken(tok) && !seen[tok] {
				seen[tok] = true
				out = append(out, tok)
			}
		}
	}
	return out
}

// heldAccounts are the live sessions this browser holds, the one in use first,
// in orgID when it is not empty. Read without touching any of them.
func (s *Server) heldAccounts(ctx context.Context, r *http.Request, orgID string) ([]heldAccount, error) {
	tokens := parkedTokens(r)
	active := sessionCookie(r)
	if validSessionToken(active) {
		tokens = append([]string{active}, tokens...)
	}
	if len(tokens) == 0 || s.db == nil {
		return nil, nil
	}
	hashes := make([][]byte, len(tokens))
	byHash := map[string]string{}
	for i, tok := range tokens {
		hashes[i] = store.HashToken(tok)
		byHash[string(hashes[i])] = tok
	}
	rows, err := s.db.Query(ctx, `
		SELECT s.cookie_hash, s.sid, s.user_id::text, s.org_id::text,
		       COALESCE(NULLIF(u.display_name, ''), u.email, u.username, ''),
		       CASE WHEN s.persistent AND o.persistent_sessions
		            THEN greatest(0, floor(extract(epoch FROM s.absolute_not_after - now())))::int ELSE 0 END
		  FROM core.sessions s
		  JOIN core.users u ON u.id = s.user_id
		  JOIN core.organizations o ON o.id = s.org_id
		 WHERE s.cookie_hash = ANY($1) AND s.revoked_at IS NULL AND s.not_after > now()
		   AND u.status = 'active' AND s.impersonator_id IS NULL
		   AND ($2 = '' OR s.org_id::text = $2)`, hashes, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]heldAccount{}
	for rows.Next() {
		var h heldAccount
		var hash []byte
		if err := rows.Scan(&hash, &h.sid, &h.userID, &h.orgID, &h.name, &h.keepFor); err != nil {
			return nil, err
		}
		h.token = byHash[string(hash)]
		h.active = h.token == active
		found[h.token] = h
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []heldAccount
	for _, tok := range tokens {
		if h, ok := found[tok]; ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// writeParked writes the parked cookies to hold exactly accounts, newest
// first, each in the cookie matching its lifetime, at most maxParkedAccounts.
func (s *Server) writeParked(w http.ResponseWriter, accounts []heldAccount) {
	if len(accounts) > maxParkedAccounts {
		accounts = accounts[:maxParkedAccounts]
	}
	var ends, kept []string
	keepFor := 0
	for _, a := range accounts {
		if a.keepFor > 0 {
			kept = append(kept, a.token)
			keepFor = max(keepFor, a.keepFor)
		} else {
			ends = append(ends, a.token)
		}
	}
	set := func(name string, tokens []string, maxAge int) {
		if len(tokens) == 0 {
			maxAge = -1
		}
		http.SetCookie(w, &http.Cookie{Name: name, Value: strings.Join(tokens, "."), Path: "/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	}
	set(ParkedCookieName, ends, 0)
	set(KeptParkedCookieName, kept, keepFor)
}

// parkOthers, as a sign-in for userID is about to take the session cookie,
// keeps every other live account this browser holds signed in beside it. The
// person's own earlier session is not kept: two of one account would be one
// account offered twice.
func (s *Server) parkOthers(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string) {
	held, err := s.heldAccounts(ctx, r, "")
	if err != nil {
		// The new sign-in still happens; the others are only not kept.
		s.log.Error("reading the accounts this browser holds", "err", err)
		return
	}
	if len(held) == 0 && len(parkedTokens(r)) == 0 {
		return
	}
	var keep []heldAccount
	for _, h := range held {
		if h.userID != userID {
			keep = append(keep, h)
		}
	}
	// One more than fits signs out the one parked longest ago, rather than
	// dropping it from the cookie and leaving its session live with nothing
	// left in the browser to end it.
	for len(keep) > maxParkedAccounts {
		if err := s.terminateOwnSession(ctx, keep[len(keep)-1].token); err != nil {
			s.log.Error("signing out an account the browser had no room for", "err", err)
		}
		keep = keep[:len(keep)-1]
	}
	s.writeParked(w, keep)
}

// holdsAccounts reports whether the sign-in page has accounts to offer.
func (s *Server) holdsAccounts(r *http.Request, orgID string) bool {
	if len(parkedTokens(r)) == 0 && sessionCookie(r) == "" {
		return false // nothing to look up, and the common case
	}
	held, err := s.heldAccounts(r.Context(), r, orgID)
	if err != nil {
		s.log.Error("reading the accounts this browser holds", "err", err)
		return false
	}
	return len(held) > 0
}

// clearParked forgets every parked account in this browser.
func (s *Server) clearParked(w http.ResponseWriter, r *http.Request) {
	if len(parkedTokens(r)) > 0 {
		s.writeParked(w, nil)
	}
}

// renderAccounts shows the picker for authz (empty for a page that names no
// request), listing accounts.
func (s *Server) renderAccounts(w http.ResponseWriter, r *http.Request, authz string, accounts []heldAccount, msg string) {
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	list := make([]map[string]any, 0, len(accounts))
	for _, a := range accounts {
		list = append(list, map[string]any{"SID": a.sid, "Name": a.name, "Active": a.active})
	}
	another := "/login"
	if authz != "" {
		another += "?authz=" + url.QueryEscape(authz)
	}
	s.renderPage(w, r, "accounts", map[string]any{
		"Accounts": list, "Authz": authz, "Another": another, "Error": msg,
		"CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleAccountsGet is the picker the sign-in page links to.
func (s *Server) handleAccountsGet(w http.ResponseWriter, r *http.Request) {
	authz := r.URL.Query().Get("authz")
	held, err := s.heldAccounts(r.Context(), r, s.loginOrg(r.Context(), authz))
	if err != nil {
		s.log.Error("reading the accounts this browser holds", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if len(held) == 0 {
		s.renderLogin(w, r, authz, "")
		return
	}
	s.renderAccounts(w, r, authz, held, "")
}

// handleAccountsPost uses the chosen account, or, cancelled, tells the
// application none was chosen.
func (s *Server) handleAccountsPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		s.renderLoginStatus(w, r, r.PostForm.Get("authz"),
			"Your sign-in session expired. Please try again.", http.StatusForbidden)
		return
	}
	authz := r.PostForm.Get("authz")
	if r.PostForm.Get("cancel") != "" {
		if authz == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// OIDC Core §3.1.2.1, select_account: without a choice the OP "MUST
		// return an error, typically account_selection_required".
		s.errorToClient(w, r, authz, "account_selection_required", "no account was chosen")
		return
	}
	held, err := s.heldAccounts(ctx, r, s.loginOrg(ctx, authz))
	if err != nil {
		s.log.Error("reading the accounts this browser holds", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	chosen := -1
	for i, h := range held {
		if h.sid == r.PostForm.Get("account") {
			chosen = i
		}
	}
	if chosen < 0 {
		// Ended since the page was shown, or never this browser's: only the
		// sessions it holds can be chosen, whatever sid is posted.
		s.renderAccounts(w, r, authz, held, s.tr(r).Text("accounts.gone"))
		return
	}
	pick := held[chosen]
	// Choosing is using: recorded on the session, and refused if it ended in
	// between.
	if _, live, err := store.ResolveSessionCookie(ctx, s.db, store.HashToken(pick.token)); err != nil || !live {
		s.renderAccounts(w, r, authz, held, s.tr(r).Text("accounts.gone"))
		return
	}
	// Everything else this browser holds, in this organisation or not, stays
	// parked; the one in use joins them.
	all, err := s.heldAccounts(ctx, r, "")
	if err != nil {
		s.log.Error("reading the accounts this browser holds", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	var rest []heldAccount
	for _, h := range all {
		if h.token != pick.token {
			rest = append(rest, h)
		}
	}
	s.writeParked(w, rest)
	s.setSessionCookie(w, pick.token, pick.keepFor)
	if authz == "" {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, oidc.PathAuthorize+"?"+consumePrompt(authz, oauth.PromptSelectAccount), http.StatusSeeOther)
}

// errorToClient reports an error to the client of a parked authorization
// request, after checking the request names a client and a redirect it has
// registered: the request came back from a form, so it is the browser's to
// change, and a redirect taken from it unchecked goes wherever it says.
func (s *Server) errorToClient(w http.ResponseWriter, r *http.Request, authz, code, description string) {
	req := oauth.ParseAuthz(parseQuery(authz))
	// In any state: ValidateAuthz refuses a disabled client, saying so.
	c, lookupErr := s.lookupClientAnyState(r.Context(), req.ClientID)
	if aerr := oauth.ValidateAuthz(req, c, lookupErr); aerr != nil && aerr.Disposition != oauth.DispositionRedirect {
		s.writeAuthzError(w, r, req, aerr)
		return
	}
	s.writeAuthzError(w, r, req, &oauth.AuthzError{Code: code, Description: description,
		Disposition: oauth.DispositionRedirect})
}
