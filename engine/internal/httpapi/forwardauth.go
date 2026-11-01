package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/proxyrules"
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
	// Host is the one application it is good for, when it was set on that
	// application's own address. A cookie for a parent domain says nothing here.
	Host string `json:"host,omitempty"`
}

// handleProxyVerify is the endpoint the reverse proxy calls per request.
//
// It must be FAST and it must be conservative: every request to every protected
// application passes through here, and anything it lets through is a request
// nobody else will check.
func (s *Server) handleProxyVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rule, answered := s.proxyRule(w, r)
	if answered {
		return
	}

	c, err := r.Cookie(ProxyCookieName)
	if err != nil || c.Value == "" {
		// No browser session here, so this may be a program with a token. Only
		// then: a browser's cookie is the proxy's own and says more, and an
		// application behind the proxy may have an Authorization of its own.
		if raw := bearerToken(r); raw != "" {
			pc, reason := s.proxyClaimsFromToken(r, raw)
			if reason != "" {
				s.denyProxy(w, r, reason)
				return
			}
			s.answerProxy(w, r, pc, rule)
			return
		}
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
	// Carried to another application by hand, a cookie set on one address says nothing.
	if pc.Host != "" && pc.Host != strings.ToLower(firstHeader(r, "X-Forwarded-Host")) {
		s.denyProxy(w, r, "this proxy token is for another application")
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
	s.answerProxy(w, r, pc, rule)
}

// proxyRule holds a request to the rules of its host before anything else, because
// one of them may say nobody has to be signed in. It answers the rule that goes on to
// decide, nil for none, or says the request has been answered.
//
// A host with rules refuses what they cannot be applied to. Without that, one way of
// spelling a path that the application reads differently is a way past every rule on it.
func (s *Server) proxyRule(w http.ResponseWriter, r *http.Request) (*proxyrules.Rule, bool) {
	ctx := r.Context()
	host := strings.ToLower(firstHeader(r, "X-Forwarded-Host"))
	if host == "" || s.db == nil {
		return nil, false
	}
	rules, err := store.ProxyRulesOf(ctx, s.db, s.instanceID, host)
	if err != nil {
		s.log.Error("reading the rules of a protected host", "err", err, "correlation_id", correlationID(ctx))
		s.forbidProxy(w, "the rules of this application could not be read")
		return nil, true
	}
	if len(rules) == 0 {
		return nil, false
	}
	// Not firstHeader, which stops at a comma. A comma is a character of a path, and
	// /public,/../admin compared up to it is /public.
	uri := r.Header.Values("X-Forwarded-Uri")
	if len(uri) != 1 {
		s.forbidProxy(w, "the proxy must say which path it is asking about (X-Forwarded-Uri)")
		return nil, true
	}
	path, err := proxyrules.Canonical(uri[0])
	if err != nil {
		s.forbidProxy(w, err.Error())
		return nil, true
	}
	rule := proxyrules.Match(rules, strings.ToUpper(firstHeader(r, "X-Forwarded-Method")), path)
	switch {
	case rule == nil:
		return nil, false
	case rule.Effect == proxyrules.EffectPublic:
		writeProxyIdentity(w, proxyClaims{}, nil, "")
		w.WriteHeader(http.StatusOK)
		return nil, true
	case rule.Effect == proxyrules.EffectDeny:
		s.forbidProxy(w, "this path is not served")
		return nil, true
	}
	return rule, false
}

// proxyClaimsFromToken reads who an access token speaks for, and answers why not
// when it cannot be honoured here. The audience is the host, as RFC 8707 has a
// client ask for: a token for anything else, this client's own or the issuer
// included, is not for this application. A sender-constrained token is refused
// because what proves it is bound to the application's address and only the
// application could check it, so a proxy would be taking possession on trust.
// What ends a token is read now, as userinfo reads it (ADR-007).
func (s *Server) proxyClaimsFromToken(r *http.Request, raw string) (proxyClaims, string) {
	ctx := r.Context()
	claims, err := s.verifyPresented(ctx, s.acceptedIssuers(ctx), raw)
	if err != nil {
		return proxyClaims{}, "the access token did not verify"
	}
	host := strings.ToLower(firstHeader(r, "X-Forwarded-Host"))
	if host == "" || !audienceIncludes(claims.Audience, "https://"+host) {
		return proxyClaims{}, "the access token was not issued for this application"
	}
	if claims.Cnf != nil {
		return proxyClaims{}, "a sender-constrained access token cannot be presented through a proxy"
	}
	if ended := endedDescription(s.standing(ctx, claims, "the proxy")); ended != "" {
		return proxyClaims{}, ended
	}
	c, err := s.lookupClient(ctx, claims.ClientID)
	if err != nil || c == nil {
		return proxyClaims{}, "the client of this access token could not be found"
	}
	pc := proxyClaims{Subject: claims.Subject, SID: claims.SessionID, OrgID: c.OrgID}
	if id, ok := store.CanonicalUUID(claims.Subject); ok {
		if err := s.db.QueryRow(ctx, `SELECT COALESCE(email, '') FROM core.users WHERE id = $1::uuid`, id).
			Scan(&pc.Email); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return proxyClaims{}, "the subject of this access token could not be read"
		}
	}
	return pc, ""
}

// answerProxy decides whoever pc names against the host, and says who they are.
func (s *Server) answerProxy(w http.ResponseWriter, r *http.Request, pc proxyClaims, rule *proxyrules.Rule) {
	// Authorization, which this endpoint did not do at all. A valid cookie
	// passed every protected host of every organisation: anybody who could
	// sign in anywhere in the deployment reached the payroll dashboard of a
	// tenant they had never heard of.
	host, reason := s.authorizeProxyHost(r, pc, rule)
	if host == nil {
		s.forbidProxy(w, reason)
		return
	}
	groups, signed, err := s.proxyDisclosure(r.Context(), host, pc)
	if err != nil {
		s.log.Error("saying who is at a protected host", "host", host.Host, "err", err,
			"correlation_id", correlationID(r.Context()))
		s.forbidProxy(w, "what this application is told could not be read")
		return
	}
	writeProxyIdentity(w, pc, groups, signed)
	w.WriteHeader(http.StatusOK)
}

// writeProxyIdentity says who is there, from the verified token and never from the
// request, or on a public path that nobody is.
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
func writeProxyIdentity(w http.ResponseWriter, pc proxyClaims, groups []string, signed string) {
	w.Header().Set("X-Forwarded-User", pc.Subject)
	w.Header().Set("X-Forwarded-Sub", pc.Subject)
	w.Header().Set("X-Forwarded-Email", pc.Email)
	w.Header().Set("X-Forwarded-Groups", strings.Join(groups, ","))
	w.Header().Set("X-Forwarded-Jwt", signed)
}

// typProxyIdentity marks the statement an application is given, so it cannot be
// taken for anything else this issuer signs.
const typProxyIdentity = "proxy-identity+jwt"

// proxyIdentityTTL is short because it is made afresh for every request.
const proxyIdentityTTL = time.Minute

// proxyIdentity is the signed statement: who, for which application, until when.
type proxyIdentity struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience string   `json:"aud"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
}

// proxyDisclosure is what this host is told beyond who: the released groups this
// person is in, and the signed statement when the host asked for one. A group's
// name says something about a person, so only what the operator released goes.
func (s *Server) proxyDisclosure(ctx context.Context, host *store.ProxyHost, pc proxyClaims) ([]string, string, error) {
	var groups []string
	if len(host.ReleaseGroups) > 0 {
		if _, person := store.CanonicalUUID(pc.Subject); person {
			held, err := store.AllGroupsForUser(ctx, s.db, pc.Subject)
			if err != nil {
				return nil, "", err
			}
			for _, g := range held {
				if slices.Contains(host.ReleaseGroups, g) {
					groups = append(groups, g)
				}
			}
		}
	}
	if !host.SignedIdentity {
		return groups, "", nil
	}
	key, err := s.anySigningKey()
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	signed, err := tokens.NewSigner(key).SignJSON(proxyIdentity{Issuer: s.cfg.Issuer, Subject: pc.Subject,
		Audience: "https://" + host.Host, Email: pc.Email, Groups: groups, IssuedAt: now.Unix(),
		Expiry: now.Add(proxyIdentityTTL).Unix()}, typProxyIdentity)
	return groups, signed, err
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
//
// It answers the host, or nil and why not.
func (s *Server) authorizeProxyHost(r *http.Request, pc proxyClaims, rule *proxyrules.Rule) (*store.ProxyHost, string) {
	ctx := r.Context()
	host := strings.ToLower(firstHeader(r, "X-Forwarded-Host"))
	if host == "" {
		return nil, "the proxy did not say which application it is asking about (X-Forwarded-Host)"
	}
	registered, err := store.ProxyHostFor(ctx, s.db, pc.OrgID, host)
	if err != nil {
		s.log.Error("checking a protected host", "err", err)
		return nil, "the protected host could not be checked"
	}
	if registered == nil {
		return nil, "this application is not one of your organisation's protected hosts"
	}

	// The host's policy, and on top of it the one a named path has of its own.
	keys := []string{"proxy:" + host}
	if rule != nil && rule.Name != "" {
		keys = append(keys, "proxy:"+host+"#"+rule.Name)
	}
	mfa, amr := sessionFactors(ctx, s.db, pc.SID)
	for _, key := range keys {
		if pd := s.checkAccessPolicyUnobserved(ctx, pc.OrgID, key, pc.Subject, "", mfa, amr); pd != nil {
			s.auditDetached(ctx, audit.Event{
				Type: audit.EventLoginFailed, OrgID: pc.OrgID, SubjectID: pc.Subject,
				CorrelationID: correlationID(ctx),
				Detail:        map[string]any{"reason": "access_policy", "rule": pd.Rule, "via": "proxy", "host": host},
			})
			return nil, pd.Message
		}
	}
	return registered, ""
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
		// A host with a cookie of its own starts on its own address, where the
		// browser can be given something to prove at the end that it was this one.
		if s.db != nil {
			own, err := store.ProxyHostKeepsOwnCookie(r.Context(), s.db, s.instanceID, strings.ToLower(firstHeader(r, "X-Forwarded-Host")))
			if err != nil {
				s.log.Error("reading where a protected host keeps its cookie", "err", err)
			}
			if own {
				loc = firstHeader(r, "X-Forwarded-Proto") + "://" + firstHeader(r, "X-Forwarded-Host") + pathProxyBegin +
					"?rd=" + url.QueryEscape(orig)
			}
		}
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
	rd, state := r.URL.Query().Get("rd"), r.URL.Query().Get("state")

	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		// Not signed in: send them through the normal login, and come back here.
		again := url.Values{}
		if rd != "" {
			again.Set("rd", rd)
		}
		if state != "" {
			again.Set("state", state)
		}
		back := "/proxy/start"
		if len(again) > 0 {
			back += "?" + again.Encode()
		}
		http.Redirect(w, r, parkLogin(back), http.StatusSeeOther)
		return
	}

	// THE open-redirect check. `rd` arrives from a header the proxy set from the
	// original request, so it is attacker-influenced. Redirecting to it unchecked
	// turns every protected application into an open redirector reached from a
	// link that looks like a login.
	target, host, err := s.validateProxyRedirect(ctx, orgID, rd)
	if err != nil {
		s.log.Info("proxy redirect refused", "rd", rd, "err", err,
			"correlation_id", correlationID(ctx))
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	sid, _, _ := store.ResolveSessionCookie(ctx, s.db, store.HashToken(sessionCookie(r)), s.instanceID)
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

	// A cookie of its own can only be set from its own address, so the sign-in goes
	// there to be turned into one, in a code good only for this browser and this host.
	if host != nil && host.OwnCookie {
		if state == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"this application's sign-in starts at its own address, "+pathProxyBegin)
			return
		}
		code, err := tokens.NewSigner(key).SignJSON(proxyCode{Issuer: s.cfg.Issuer, Subject: userID, SID: sid, OrgID: orgID,
			Email: email, Host: strings.ToLower(host.Host), State: state, Target: target,
			Expiry: time.Now().Add(proxyCodeTTL).Unix()}, typProxyCode)
		if err != nil {
			s.log.Error("signing a proxy code", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		u, err := url.Parse(target)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "rd must be an absolute URL")
			return
		}
		http.Redirect(w, r, u.Scheme+"://"+u.Host+pathProxyCallback+"?code="+url.QueryEscape(code), http.StatusSeeOther)
		return
	}

	// The parent domain, so every protected subdomain receives it. This is the
	// reason the cookie cannot be __Host- prefixed, and the reason it must never
	// carry session authority.
	domain := s.cfg.ProxyCookieDomain
	if host != nil && host.CookieDomain != "" {
		domain = host.CookieDomain
	}
	if !s.issueProxyCookie(w, r, proxyClaims{Subject: userID, SID: sid, OrgID: orgID, Email: email}, domain, target) {
		return
	}
	if target == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "proxy session established"})
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// issueProxyCookie signs a person's proxy token and sets it, for a parent domain or,
// with none, for the address answering. It reports whether it did.
func (s *Server) issueProxyCookie(w http.ResponseWriter, r *http.Request, pc proxyClaims, domain, target string) bool {
	ctx := r.Context()
	key, err := s.anySigningKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return false
	}
	pc.Issuer, pc.Expiry = s.cfg.Issuer, time.Now().Add(proxyTTL).Unix()
	tok, err := tokens.NewSigner(key).SignJSON(pc, typProxy)
	if err != nil {
		s.log.Error("signing proxy token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ProxyCookieName,
		Value:    tok,
		Path:     "/",
		Domain:   domain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(proxyTTL.Seconds()),
	})
	s.auditDetached(ctx, audit.Event{
		Type: "proxy.session_issued", OrgID: pc.OrgID, SubjectID: pc.Subject,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"target": target},
	})
	return true
}

const (
	// pathProxyBegin and pathProxyCallback are served here and reached on a protected
	// application's own address, through its proxy, for a host with a cookie of its own.
	pathProxyBegin    = "/.signari/proxy/begin"
	pathProxyCallback = "/.signari/proxy/callback"

	// proxyStateCookie is what ties the browser that starts a sign-in to the browser
	// that finishes it. __Host-, so nothing at another address can have set it.
	proxyStateCookie = "__Host-signari_proxy_state"
	proxyStateTTL    = 30 * time.Minute

	typProxyCode = "proxy-code+jwt"
	// proxyCodeTTL is a redirect's length: the code goes straight to the callback.
	proxyCodeTTL = time.Minute
)

// proxyCode carries a sign-in from the issuer to an application's own address.
type proxyCode struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	SID     string `json:"sid"`
	OrgID   string `json:"org"`
	Email   string `json:"email,omitempty"`
	// Host is the application it is for, and State what its browser must hold.
	Host   string `json:"host"`
	State  string `json:"state"`
	Target string `json:"target"`
	Expiry int64  `json:"exp"`
}

// proxyRequestHost is the application a request reached here through.
func proxyRequestHost(r *http.Request) string {
	if host := firstHeader(r, "X-Forwarded-Host"); host != "" {
		return strings.ToLower(host)
	}
	return strings.ToLower(r.Host)
}

// handleProxyBegin starts a sign-in on an application's own address, leaving in the
// browser what the end of it will ask for.
//
// # Why the browser has to be told anything
//
// A code in a URL is usable by whoever opens it. Without this, somebody signs in to the
// application themselves, stops at the callback, and sends the link to somebody else,
// who is then working in the application as them, and telling it things.
func (s *Server) handleProxyBegin(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	u, err := url.Parse(rd)
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Host, proxyRequestHost(r)) {
		writeError(w, http.StatusBadRequest, "invalid_request", "rd must be on this application")
		return
	}
	state, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: proxyStateCookie, Value: state, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(proxyStateTTL.Seconds())})
	http.Redirect(w, r, s.cfg.Issuer+"/proxy/start?"+url.Values{"rd": {rd}, "state": {state}}.Encode(), http.StatusSeeOther)
}

// handleProxyCallback turns a code into a cookie for the application it arrived at.
func (s *Server) handleProxyCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refuse := func(why string) {
		s.log.Info("proxy callback refused", "reason", why, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusBadRequest, "invalid_request", "this sign-in could not be finished: "+why)
	}
	var code proxyCode
	payload, err := tokens.VerifyTyped(s.cfg.Keys, s.cfg.Issuer, r.URL.Query().Get("code"), typProxyCode)
	if err != nil || json.Unmarshal(payload, &code) != nil {
		refuse("the code did not verify")
		return
	}
	if time.Now().After(time.Unix(code.Expiry, 0)) {
		refuse("the code has expired")
		return
	}
	host := proxyRequestHost(r)
	if code.Host != host {
		refuse("the code is for another application")
		return
	}
	held, err := r.Cookie(proxyStateCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(held.Value), []byte(code.State)) != 1 {
		refuse("this browser did not start it")
		return
	}
	// Everything the code said could have changed in the minute it was good for.
	live, err := store.SessionLive(ctx, s.db, code.SID)
	if err != nil || !live {
		refuse("the session has ended")
		return
	}
	registered, err := store.ProxyHostFor(ctx, s.db, code.OrgID, host)
	if err != nil || registered == nil || !registered.OwnCookie {
		refuse("this application no longer keeps a cookie of its own")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: proxyStateCookie, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if !s.issueProxyCookie(w, r, proxyClaims{Subject: code.Subject, SID: code.SID, OrgID: code.OrgID, Email: code.Email,
		Host: host}, "", code.Target) {
		return
	}
	http.Redirect(w, r, code.Target, http.StatusSeeOther)
}

// validateProxyRedirect refuses anything not under a protected host.
//
// An allow-list, not a pattern: "same registrable domain" is the check people
// reach for and it is wrong, because a hostname an attacker controls under that
// domain then qualifies. The hosts are registered explicitly.
func (s *Server) validateProxyRedirect(ctx context.Context, orgID, rd string) (string, *store.ProxyHost, error) {
	if rd == "" {
		return "", nil, nil
	}
	u, err := url.Parse(rd)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", nil, fmt.Errorf("rd must be an absolute URL")
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return "", nil, fmt.Errorf("rd must be https")
	}

	host, err := store.ProxyHostFor(ctx, s.db, orgID, strings.ToLower(u.Host))
	if err != nil || host == nil {
		return "", nil, fmt.Errorf("%q is not a registered protected host", u.Host)
	}
	if host.OwnCookie {
		return u.String(), host, nil
	}

	// The cookie has to REACH the protected host, or this endpoint issues a
	// credential the browser will never send back. The proxy then answers 401,
	// which sends the browser here, which sets the cookie again: an infinite
	// redirect loop, and the single most confusing way forward auth fails.
	//
	// It is caught here, at configuration time, because the loop itself gives an
	// operator nothing to go on -- the cookie is set, every response is a valid
	// redirect, and no component reports an error.
	domain := s.cfg.ProxyCookieDomain
	if host.CookieDomain != "" {
		domain = host.CookieDomain
		// A browser refuses a domain the address setting it is not under, which is
		// the same loop from the other side.
		if issuer, err := url.Parse(s.cfg.Issuer); err != nil || cookieReaches(domain, issuer.Hostname()) != nil {
			return "", nil, fmt.Errorf("this issuer is not under %q, so a browser would refuse a cookie for it", domain)
		}
	}
	if err := cookieReaches(domain, u.Hostname()); err != nil {
		return "", nil, err
	}
	return u.String(), host, nil
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
