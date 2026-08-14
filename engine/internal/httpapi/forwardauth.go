package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Forward authentication, for applications that speak no OIDC at all.
//
// A reverse proxy (nginx auth_request, Traefik forwardAuth, Caddy forward_auth)
// asks this endpoint about each request. 200 means let it through; 401 means
// send them to sign in. It is how most people actually put an identity provider
// in front of something -- an internal tool, a dashboard, anything with no
// authentication of its own.
//
// # Why this needs its own cookie
//
// The IdP session cookie is `__Host-` prefixed, which FORBIDS a Domain
// attribute, so the browser sends it only to the IdP's own origin. A request to
// app.example.com never carries it, and no amount of proxying changes that.
//
// So forward auth issues a SEPARATE, narrower credential scoped to the parent
// domain. That cookie is deliberately not the session:
//
//   - It is readable by every subdomain of the parent, which is the point and
//     also the risk. Putting the actual session there would hand a session
//     cookie to anything that can get a hostname under that domain.
//   - It carries no session-management authority. It proves "this browser
//     completed sign-in", nothing more.
//   - It is bound to the sid, so signing out kills it -- otherwise forward auth
//     becomes a way to outlive a logout.

const (
	// ProxyCookieName uses the __Secure- prefix, not __Host-. __Host- would be
	// stronger and is unusable here: it forbids the Domain attribute this design
	// requires. __Secure- keeps the "HTTPS only" guarantee, which is the part
	// that still applies.
	ProxyCookieName = "__Secure-signari_proxy"

	typProxy = "proxy+jwt"

	// proxyTTL is short and refreshed by the flow. It bounds how long a forward
	// auth decision can outlive the session it was derived from, between the
	// checks against the live session below.
	proxyTTL = 30 * time.Minute
)

type proxyClaims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	SID     string `json:"sid"`
	Email   string `json:"email,omitempty"`
	Expiry  int64  `json:"exp"`
}

// handleProxyVerify is the endpoint the reverse proxy calls per request.
//
// It must be FAST and it must be conservative: every request to every protected
// application passes through here, and anything it lets through is a request
// nobody else will check.
func (s *Server) handleProxyVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Identity headers are STRIPPED before anything else.
	//
	// A client that sends its own X-Forwarded-User must not have it survive to
	// the application. Most forward-auth setups pass the proxy's response headers
	// through, so a header the caller supplied and we failed to overwrite becomes
	// an identity the application trusts. This is the classic forward-auth
	// vulnerability, and it is a two-line defence.
	for _, h := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Sub"} {
		w.Header().Del(h)
	}

	c, err := r.Cookie(ProxyCookieName)
	if err != nil || c.Value == "" {
		s.denyProxy(w, r, "no proxy session")
		return
	}
	payload, err := tokens.VerifyTyped(s.cfg.Keys, s.cfg.Issuer, c.Value, typProxy)
	if err != nil {
		s.denyProxy(w, r, "proxy token did not verify")
		return
	}
	var pc proxyClaims
	if err := json.Unmarshal(payload, &pc); err != nil || pc.Subject == "" {
		s.denyProxy(w, r, "malformed proxy token")
		return
	}
	if time.Now().After(time.Unix(pc.Expiry, 0)) {
		s.denyProxy(w, r, "proxy token expired")
		return
	}

	// The live session is rechecked on every request. Without this the proxy
	// cookie keeps working for its full lifetime after the user signs out --
	// which is exactly the "logout does not work" failure this project spent a
	// day making visible elsewhere.
	if pc.SID != "" {
		live, err := store.SessionLive(ctx, s.db, pc.SID)
		if err != nil || !live {
			s.denyProxy(w, r, "the session behind this proxy token has ended")
			return
		}
	}

	// Set by US, from the verified token. Never copied from the request.
	w.Header().Set("X-Forwarded-User", pc.Subject)
	w.Header().Set("X-Forwarded-Sub", pc.Subject)
	if pc.Email != "" {
		w.Header().Set("X-Forwarded-Email", pc.Email)
	}
	w.WriteHeader(http.StatusOK)
}

// denyProxy answers 401 with where to go next.
func (s *Server) denyProxy(w http.ResponseWriter, r *http.Request, reason string) {
	// The original URL, reconstructed from what the proxy told us. Used only to
	// come back to after sign-in, and validated before any redirect is issued.
	orig := originalURL(r)
	loc := s.cfg.Issuer + "/proxy/start"
	if orig != "" {
		loc += "?rd=" + url.QueryEscape(orig)
	}
	w.Header().Set("Location", loc)
	// The reason is a HEADER, not a body: nginx auth_request discards the body,
	// and an operator debugging this needs somewhere to look.
	w.Header().Set("X-Signari-Reason", reason)
	w.WriteHeader(http.StatusUnauthorized)
}

// originalURL rebuilds the request the proxy is asking about.
func originalURL(r *http.Request) string {
	proto := firstHeader(r, "X-Forwarded-Proto")
	host := firstHeader(r, "X-Forwarded-Host")
	uri := firstHeader(r, "X-Forwarded-Uri")
	if proto == "" || host == "" {
		return ""
	}
	if uri == "" {
		uri = "/"
	}
	return proto + "://" + host + uri
}

// firstHeader takes only the FIRST value.
//
// A proxy chain can append, and a caller can inject: "X-Forwarded-Host: good,
// evil" arrives as one header with two values. Taking the last -- or joining
// them -- is how an attacker chooses the host.
func firstHeader(r *http.Request, name string) string {
	v := r.Header.Get(name)
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// handleProxyStart issues the proxy cookie for an already signed-in browser.
func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rd := r.URL.Query().Get("rd")

	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		// Not signed in: send them through the normal login, and come back here.
		back := "/proxy/start"
		if rd != "" {
			back += "?rd=" + url.QueryEscape(rd)
		}
		http.Redirect(w, r, "/login?authz="+url.QueryEscape("return="+back), http.StatusFound)
		return
	}

	// THE open-redirect check. `rd` arrives from a header the proxy set from the
	// original request, so it is attacker-influenced. Redirecting to it unchecked
	// turns every protected application into an open redirector reached from a
	// link that looks like a login.
	target, err := s.validateProxyRedirect(ctx, orgID, rd)
	if err != nil {
		s.log.Info("proxy redirect refused", "rd", rd, "err", err,
			"correlation_id", correlationID(ctx))
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	sid, _, _ := store.ResolveSessionCookie(ctx, s.db, store.HashToken(sessionCookie(r)))
	var email string
	_ = s.db.QueryRow(ctx,
		`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid`, userID).Scan(&email)

	key, err := s.anySigningKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	tok, err := tokens.NewSigner(key).SignJSON(proxyClaims{
		Issuer: s.cfg.Issuer, Subject: userID, SID: sid, Email: email,
		Expiry: time.Now().Add(proxyTTL).Unix(),
	}, typProxy)
	if err != nil {
		s.log.Error("signing proxy token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  ProxyCookieName,
		Value: tok,
		Path:  "/",
		// The parent domain, so every protected subdomain receives it. This is
		// the reason the cookie cannot be __Host- prefixed, and the reason it
		// must never carry session authority.
		Domain:   s.cfg.ProxyCookieDomain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(proxyTTL.Seconds()),
	})

	s.auditDetached(ctx, audit.Event{
		Type: "proxy.session_issued", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"target": target},
	})

	if target == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "proxy session established"})
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// validateProxyRedirect refuses anything not under a protected host.
//
// An allow-list, not a pattern: "same registrable domain" is the check people
// reach for and it is wrong, because a hostname an attacker controls under that
// domain then qualifies. The hosts are registered explicitly.
func (s *Server) validateProxyRedirect(ctx context.Context, orgID, rd string) (string, error) {
	if rd == "" {
		return "", nil
	}
	u, err := url.Parse(rd)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("rd must be an absolute URL")
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("rd must be https")
	}

	var allowed bool
	if err := s.db.QueryRow(ctx, `
		SELECT true FROM core.proxy_hosts
		WHERE org_id = $1::uuid AND lower(host) = lower($2) AND enabled`,
		orgID, u.Host).Scan(&allowed); err != nil || !allowed {
		return "", fmt.Errorf("%q is not a registered protected host", u.Host)
	}
	return u.String(), nil
}

// isLoopback reports whether a host is unreachable from the network.
//
// The `.localhost` SUFFIX counts, not just the bare name. RFC 6761 reserves the
// whole TLD and requires it to resolve to loopback, and browsers treat
// `app.localhost` as a secure context exactly like `localhost` -- which is why
// it is the conventional way to run several services locally on real hostnames.
//
// Matching only the exact string rejected `n8n.localhost` as insecure, which is
// wrong and would have made local development of forward auth impossible.
func isLoopback(h string) bool {
	h = strings.ToLower(h)
	return h == "localhost" || h == "127.0.0.1" || h == "::1" ||
		strings.HasSuffix(h, ".localhost")
}
