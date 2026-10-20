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
	// OrgID is the organisation the person signed in to, which decides the
	// hosts they may reach. Signed with the rest, so it is ours and not the
	// browser's.
	OrgID  string `json:"org"`
	Email  string `json:"email,omitempty"`
	Expiry int64  `json:"exp"`
}

// handleProxyVerify is the endpoint the reverse proxy calls per request.
//
// It must be FAST and it must be conservative: every request to every protected
// application passes through here, and anything it lets through is a request
// nobody else will check.
func (s *Server) handleProxyVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	// A token naming no session or no organisation is one issued before both
	// were required. Asked to sign in again rather than honoured: without a
	// session nothing can revoke it, and without an organisation nothing can
	// say which applications it reaches.
	if pc.SID == "" || pc.OrgID == "" {
		s.denyProxy(w, r, "proxy token predates per-host authorization; sign in again")
		return
	}

	// The live session is rechecked on every request. Without this the proxy
	// cookie keeps working for its full lifetime after the user signs out --
	// which is exactly the "logout does not work" failure this project spent a
	// day making visible elsewhere.
	live, err := store.SessionLive(ctx, s.db, pc.SID)
	if err != nil || !live {
		s.denyProxy(w, r, "the session behind this proxy token has ended")
		return
	}

	// Authorization, which this endpoint did not do at all. A valid cookie
	// passed every protected host of every organisation: anybody who could
	// sign in anywhere in the deployment reached the payroll dashboard of a
	// tenant they had never heard of.
	if reason, ok := s.authorizeProxyHost(r, pc); !ok {
		s.forbidProxy(w, reason)
		return
	}

	// Set by US, from the verified token. Never copied from the request.
	//
	// EVERY identity header, every time, empty when there is nothing to say.
	// The client's own X-Forwarded-Email is on the request the proxy will
	// forward, and this response is the only thing that can overwrite it: a
	// proxy that copies a header from the auth response only when the response
	// carries one leaves the client's value in place whenever this one is
	// absent. So a person with no address on record could hand the application
	// any address they liked. There used to be a loop here deleting these from
	// the response before anything was written -- from an empty map, which is
	// to say it did nothing.
	w.Header().Set("X-Forwarded-User", pc.Subject)
	w.Header().Set("X-Forwarded-Sub", pc.Subject)
	w.Header().Set("X-Forwarded-Email", pc.Email)
	w.WriteHeader(http.StatusOK)
}

// authorizeProxyHost decides whether this person may reach the host the proxy
// is asking about: it must be one of their organisation's registered, enabled
// hosts, and the access policy -- keyed "proxy:<host>" as a relying party is
// keyed by its client ID -- must allow it.
//
// The network, device and travel conditions are not met. The request here is
// the proxy's, so its address, TLS state and headers are the proxy's own, and
// a `from_networks` rule read against them would let everybody in from inside
// the office the proxy sits in. Until the person's address can be taken from a
// trusted proxy, those conditions refuse rather than guess. The request used
// to be passed with its address removed, which refused the network condition
// and let the travel one through as "not checked", and left the device check
// reading posture headers relayed by the proxy.
func (s *Server) authorizeProxyHost(r *http.Request, pc proxyClaims) (string, bool) {
	ctx := r.Context()
	host := strings.ToLower(firstHeader(r, "X-Forwarded-Host"))
	if host == "" {
		return "the proxy did not say which application it is asking about (X-Forwarded-Host)", false
	}
	var registered bool
	if err := s.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.proxy_hosts
		                WHERE org_id = $1::uuid AND lower(host) = $2 AND enabled)`,
		pc.OrgID, host).Scan(&registered); err != nil {
		s.log.Error("checking a protected host", "err", err)
		return "the protected host could not be checked", false
	}
	if !registered {
		return "this application is not one of your organisation's protected hosts", false
	}

	mfa, amr := sessionFactors(ctx, s.db, pc.SID)
	if pd := s.checkAccessPolicyUnobserved(ctx, pc.OrgID, "proxy:"+host, pc.Subject, "", mfa, amr); pd != nil {
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: pc.OrgID, SubjectID: pc.Subject,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": "access_policy", "rule": pd.Rule, "via": "proxy", "host": host},
		})
		return pd.Message, false
	}
	return "", true
}

// forbidProxy answers 403: the person is signed in and may not reach this host.
// Not 401, which would send them back to sign in, be let through by the IdP,
// and arrive here again -- a loop that tells nobody anything.
func (s *Server) forbidProxy(w http.ResponseWriter, reason string) {
	w.Header().Set("X-Signari-Reason", reason)
	w.WriteHeader(http.StatusForbidden)
}

// pathProxyVerifyRedirect is the verify endpoint for proxies that relay the
// auth response to the browser unchanged (2.57). Traefik's forwardAuth and
// Caddy's forward_auth both copy a non-2xx answer's status, Location and body
// to the client, and a browser follows Location only on a 3xx, so the 401 that
// nginx's recipe turns into a redirect left their users on a blank error page.
// Here a browser navigation is answered 302 instead; anything else, a fetch or
// an API call that would only be given an opaque redirect, keeps the 401.
const pathProxyVerifyRedirect = "/proxy/verify/redirect"

// denyProxy answers 401 with where to go next, or 302 to it for a browser
// navigation on the redirect variant.
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
	if r.URL.Path == pathProxyVerifyRedirect && isNavigation(r) {
		w.WriteHeader(http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// isNavigation reports whether the request the proxy is asking about is a
// browser loading a page: a GET or HEAD that accepts HTML. The method is the
// one the proxy forwards in X-Forwarded-Method, since the verify call itself
// is always a GET.
func isNavigation(r *http.Request) bool {
	method := firstHeader(r, "X-Forwarded-Method")
	if method == "" {
		method = r.Method
	}
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
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
		http.Redirect(w, r, parkLogin(back), http.StatusSeeOther)
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
	if sid == "" {
		// A proxy token with no session behind it could not be revoked by
		// signing out, and verify refuses one.
		writeError(w, http.StatusInternalServerError, "server_error", "the session could not be read")
		return
	}
	var email string
	_ = s.db.QueryRow(ctx,
		`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid`, userID).Scan(&email)

	key, err := s.anySigningKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	tok, err := tokens.NewSigner(key).SignJSON(proxyClaims{
		Issuer: s.cfg.Issuer, Subject: userID, SID: sid, OrgID: orgID, Email: email,
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
	http.Redirect(w, r, target, http.StatusSeeOther)
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

	// The cookie has to REACH the protected host, or this endpoint issues a
	// credential the browser will never send back. The proxy then answers 401,
	// which sends the browser here, which sets the cookie again: an infinite
	// redirect loop, and the single most confusing way forward auth fails.
	//
	// It is caught here, at configuration time, because the loop itself gives an
	// operator nothing to go on -- the cookie is set, every response is a valid
	// redirect, and no component reports an error.
	if err := cookieReaches(s.cfg.ProxyCookieDomain, u.Hostname()); err != nil {
		return "", err
	}
	return u.String(), nil
}

// cookieReaches reports whether a cookie scoped to domain would be sent to host,
// using the same suffix rule the browser applies (RFC 6265 §5.1.3).
func cookieReaches(domain, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(domain, "."), "."))

	if domain == "" {
		return fmt.Errorf("no proxy cookie domain is configured, so the proxy cookie "+
			"is scoped to this issuer alone and %q would never receive it -- the "+
			"browser would loop between the proxy and here forever. Set "+
			"SIGNARI_PROXY_COOKIE_DOMAIN to the domain shared by this issuer and "+
			"the protected host", host)
	}
	if host == domain || strings.HasSuffix(host, "."+domain) {
		return nil
	}
	return fmt.Errorf("the proxy cookie is scoped to %q, which %q is not under, so "+
		"the browser would never send it back and would loop between the proxy and "+
		"here forever. Both this issuer and the protected host must sit under "+
		"SIGNARI_PROXY_COOKIE_DOMAIN", domain, host)
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
