package httpapi

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/store"
)

// Signing out at the provider a person came through, when its operator asked for
// that (`signari idp logout`).
//
// Which provider is the browser's to say. A person's session upstream is a cookie
// in this browser, set when they came back from it, so a cookie set at that moment
// names it exactly, through every stage that may stand between the callback and a
// session here, and needs nothing kept against the session. It is not trusted
// further than that: it picks among the providers of the session's own
// organisation, and only for a session that was federated, so changing it can send
// a browser to a sign-out page its operator configured and nowhere else.

// upstreamCookieName holds the slug of the provider a browser came through.
const upstreamCookieName = "signari_upstream"

// pathLogoutComplete is where a provider sends the browser back to, and the
// address to register with it.
const pathLogoutComplete = "/logout/complete"

func (s *Server) rememberUpstream(w http.ResponseWriter, provider *federation.Config) {
	if provider.EndSessionURL == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: upstreamCookieName, Value: provider.Slug, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) forgetUpstream(w http.ResponseWriter) {
	for _, name := range []string{upstreamCookieName, samlSubjectCookieName} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode, MaxAge: -1})
	}
}

// upstreamLogout is the address to send a browser to next, to end its session at
// the provider and come back to target; empty when this sign-out stops here. No
// id_token_hint goes with it, because the upstream token is not kept, so a provider
// may ask the person to confirm.
func (s *Server) upstreamLogout(ctx context.Context, r *http.Request, sid, target string) string {
	cookie, err := r.Cookie(upstreamCookieName)
	if err != nil || sid == "" {
		return ""
	}
	endSession, clientID, kind, err := store.UpstreamLogout(ctx, s.db, sid, cookie.Value)
	if err != nil {
		s.log.Error("reading the provider to sign out at", "err", err, "correlation_id", correlationID(ctx))
		return ""
	}
	u, err := url.Parse(endSession)
	if endSession == "" || err != nil {
		return ""
	}
	if kind == "saml" {
		return s.samlUpstreamLogout(ctx, r, cookie.Value, target)
	}
	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("post_logout_redirect_uri", s.cfg.Issuer+pathLogoutComplete)
	if target != "" {
		if state := s.sealLogoutReturn(target); state != "" {
			q.Set("state", state)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// sealLogoutReturn carries a validated address through the provider, marked so
// that only an address this server validated comes back as one: the state passes
// through the provider and the browser, and an open redirect is all it would need
// to be otherwise.
func (s *Server) sealLogoutReturn(target string) string {
	if s.root == nil {
		return ""
	}
	mark := s.root.AddressHash("logout-return:" + target)
	return base64.RawURLEncoding.EncodeToString([]byte(target)) + "." + base64.RawURLEncoding.EncodeToString(mark)
}

func (s *Server) openLogoutReturn(state string) (string, bool) {
	encoded, mark, ok := strings.Cut(state, ".")
	if !ok || s.root == nil {
		return "", false
	}
	target, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	got, err := base64.RawURLEncoding.DecodeString(mark)
	if err != nil || !hmac.Equal(got, s.root.AddressHash("logout-return:"+string(target))) {
		return "", false
	}
	return string(target), true
}

// handleLogoutComplete is where the provider sends the browser back to.
func (s *Server) handleLogoutComplete(w http.ResponseWriter, r *http.Request) {
	if target, ok := s.openLogoutReturn(r.URL.Query().Get("state")); ok {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}
