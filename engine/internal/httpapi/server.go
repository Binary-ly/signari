// Package httpapi serves the engine's public protocol endpoints.
package httpapi

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/captcha"
	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/risk"
	"signari.dev/engine/internal/store"
)

// Server holds the public endpoints. Everything it serves is derived from a live
// key set, so metadata cannot drift from what the server can actually do.
type Server struct {
	cfg   oidc.Config
	log   *slog.Logger
	jwks  *bucket
	login *bucket
	// captcha is nil-safe: every method tolerates a nil receiver, so a
	// deployment that has never configured one needs no branches elsewhere.
	captcha *captcha.Verifier
	// device throttles the RFC 8628 verification screen. A user code is short by
	// necessity, so the endpoint is what limits guessing -- there is no per-code
	// counter, because a wrong guess names no record to charge it to.
	device   *bucket
	db       *pgxpool.Pool
	hasher   *passwords.Hasher
	policies *policyCache
	geo      risk.Resolver
	// mailer is never nil: New substitutes a logging driver when no SMTP is
	// configured, so no call site has to nil-check before telling a user
	// something important.
	mailer mail.Sender
	// delegator verifies credentials against a provider being migrated from.
	delegator *delegated.Verifier
}

func New(cfg oidc.Config, db *pgxpool.Pool, log *slog.Logger, mailer mail.Sender) (*Server, error) {
	if mailer == nil {
		// A nil mailer would mean recovery silently does nothing, which is worse
		// than not offering it. The logging driver at least puts the link where a
		// developer can see it and warns on every send.
		mailer = mail.NewLogSender(log, "noreply@invalid")
	}
	// Fail at construction if the metadata is not renderable, rather than serving
	// 500s from a discovery endpoint that relying parties poll.
	if _, err := oidc.Build(cfg); err != nil {
		return nil, err
	}
	// The challenge verifier, from the environment. Absent or malformed
	// configuration is refused at construction rather than degraded to "off":
	// an operator who typed the mode wrong believes they have a control they do
	// not, which is the failure mode this project keeps finding.
	cap, err := captchaFromEnv()
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:     cfg,
		captcha: cap,
		log:     log,
		db:      db,
		jwks:    newBucket(20, 40), // 20 req/s sustained, burst 40
		// The login endpoint is the expensive one: every attempt costs an Argon2
		// evaluation. Rate limiting in FRONT of the hash is what keeps a flood
		// from turning into memory exhaustion, independent of the semaphore.
		login:     newBucket(5, 20),
		device:    newBucket(3, 10),
		hasher:    passwords.NewHasher(passwords.MemoryBudgetMiB),
		policies:  newPolicyCache(),
		geo:       risk.NewResolver(),
		mailer:    mailer,
		delegator: delegated.New(),
	}, nil
}

// Routes returns the public endpoints, wrapped so every request carries a
// correlation id. Returned as http.Handler rather than *ServeMux because the
// wrapper is not optional -- a route reachable without an id would be the one
// nobody can trace.
func (s *Server) Routes() http.Handler {
	return s.withCorrelation(s.mux())
}

func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+oidc.PathDiscovery, s.handleDiscovery)
	mux.HandleFunc("GET "+oidc.PathJWKS, s.handleJWKS)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	mux.HandleFunc("GET "+oidc.PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("POST "+oidc.PathToken, s.handleToken)
	mux.HandleFunc("POST /oauth2/par", s.handlePAR)
	mux.HandleFunc("POST /oauth2/device_authorization", s.handleDeviceAuthorization)
	mux.HandleFunc("POST /oauth2/register", s.handleRegister)
	mux.HandleFunc("GET /oauth2/register/{clientID}", s.handleRegisteredClient)
	mux.HandleFunc("DELETE /oauth2/register/{clientID}", s.handleRegisteredClient)
	// Both methods on one path: GET renders the code entry screen, POST handles
	// entry and the approve/refuse decision.
	mux.HandleFunc("GET /account/mfa/email", s.handleEmailOTPEnrol)
	mux.HandleFunc("POST /account/mfa/email", s.handleEmailOTPEnrol)
	mux.HandleFunc("GET /device", s.handleDeviceVerification)
	mux.HandleFunc("POST /device", s.handleDeviceVerification)
	mux.HandleFunc("GET "+oidc.PathUserinfo, s.handleUserinfo)
	mux.HandleFunc("POST "+oidc.PathUserinfo, s.handleUserinfo)
	mux.HandleFunc("GET "+oidc.PathEndSession, s.handleEndSession)
	mux.HandleFunc("POST "+oidc.PathRevocation, s.handleRevoke)
	mux.HandleFunc("POST "+oidc.PathIntrospection, s.handleIntrospect)
	mux.HandleFunc("GET /login/with/{slug}", s.handleFederatedStart)
	mux.HandleFunc("GET /login/callback/{slug}", s.handleFederatedCallback)
	mux.HandleFunc("GET /account", s.handleAccount)
	mux.HandleFunc("GET /account/link/{slug}", s.handleFederatedLink)
	mux.HandleFunc("POST /account/unlink/{slug}", s.handleAccountUnlink)
	mux.HandleFunc("GET /saml/metadata", s.handleSAMLMetadata)
	mux.HandleFunc("GET /saml/sso", s.handleSAMLSSO)
	mux.HandleFunc("POST /saml/sso", s.handleSAMLSSO)
	mux.HandleFunc("GET /saml/slo", s.handleSAMLSLO)
	mux.HandleFunc("POST /saml/slo", s.handleSAMLSLO)
	mux.HandleFunc("GET /proxy/verify", s.handleProxyVerify)
	mux.HandleFunc("GET /proxy/start", s.handleProxyStart)
	mux.HandleFunc("GET /passkey.js", s.handlePasskeyJS)
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.rateLimitedLogin)
	mux.HandleFunc("POST /login/mfa", s.handleMFAPost)
	mux.HandleFunc("POST /consent", s.handleConsentPost)
	mux.HandleFunc("GET /recover", s.handleRecoverGet)
	mux.HandleFunc("POST /recover", s.handleRecoverPost)
	mux.HandleFunc("GET /recover/cancel", s.handleRecoverCancel)
	mux.HandleFunc("GET /recover/reset", s.handleResetGet)
	mux.HandleFunc("POST /recover/reset", s.handleResetPost)
	mux.HandleFunc("GET /account/mfa/totp", s.handleTOTPStart)
	mux.HandleFunc("POST /account/mfa/totp", s.handleTOTPConfirm)
	mux.HandleFunc("POST /account/passkeys/begin", s.handlePasskeyRegisterBegin)
	mux.HandleFunc("POST /account/passkeys/finish", s.handlePasskeyRegisterFinish)
	mux.HandleFunc("POST /login/passkey/begin", s.handlePasskeyLoginBegin)
	mux.HandleFunc("POST /login/passkey/finish", s.handlePasskeyLoginFinish)
	return mux
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, r, r.URL.Query().Get("authz"), "")
}

// rateLimitedLogin rejects forged submissions and caps attempts before any
// hashing happens.
func (s *Server) rateLimitedLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}

	// CSRF is checked BEFORE the rate limiter, not after. The limiter is a single
	// global bucket, so charging forged cross-site posts against it would let one
	// attacker page lock every real user out of signing in.
	if !checkCSRF(r) {
		// Re-rendered rather than returned as a bare error: the common real cause
		// is a cookie the browser dropped or a form left open across a restart,
		// and handing the user a working form is the useful response. The mint in
		// renderLogin gives them a fresh token.
		s.renderLoginStatus(w, r, r.PostForm.Get("authz"),
			"Your sign-in session expired. Please try again.", http.StatusForbidden)
		return
	}

	if !s.login.allow() {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts")
		return
	}
	s.handleLoginPost(w, r)
}

// renderLogin shows the sign-in form, carrying the parked authorization request
// so the flow can resume after authentication.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, authzQuery, msg string) {
	// A message here always means a rejected credential.
	status := http.StatusOK
	if msg != "" {
		status = http.StatusUnauthorized
	}
	s.renderLoginStatus(w, r, authzQuery, msg, status)
}

func (s *Server) renderLoginStatus(w http.ResponseWriter, r *http.Request, authzQuery, msg string, status int) {
	// Minted before any header is written: Set-Cookie after WriteHeader is
	// silently dropped, which would produce a form whose token can never match.
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("minting csrf token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "sign-in unavailable")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A login page must never be cached: it is per-session and carries state.
	w.Header().Set("Cache-Control", "no-store")
	// Defence in depth for a page that renders user-supplied error text.
	// script-src 'self' -- NOT 'unsafe-inline'. The passkey code is served from
	// its own path precisely so this page never has to allow inline script, which
	// would disable script CSP on the one page where an injection is worth most.
	// # CSP and the cost of a CAPTCHA
	//
	// A challenge widget is third-party script running on the sign-in page --
	// the one page where an injection is worth most. So the policy is widened
	// ONLY when a challenge is actually configured, and only to that provider's
	// own origins. A blanket relaxation would leave the hole in place for every
	// deployment, including the ones that never turn this on.
	script, frame, connect := "'self'", "'none'", "'self'"
	if s.captcha.Enabled() {
		if origins := captchaOrigins(s.captcha.Provider()); origins != "" {
			script += " " + origins
			frame = origins
			connect += " " + origins
		}
	}
	w.Header().Set("Content-Security-Policy",
		`default-src 'none'; script-src `+script+`; connect-src `+connect+`; `+
			`frame-src `+frame+`; style-src 'unsafe-inline'; form-action 'self'; `+
			`frame-ancestors 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	// The reference is only shown alongside an error. On a normal page it is
	// noise; on a failure it is the one string that connects what the user saw
	// to the audit rows and log lines for that exact request.
	ref := ""
	if msg != "" {
		ref = shortCode(correlationID(r.Context()))
	}
	_ = loginPage.Execute(w, map[string]any{
		"Authz": authzQuery, "Error": msg, "CSRF": csrf, "CSRFField": csrfFormField,
		"Reference": ref,
		// The external providers are read per render rather than cached at
		// startup: adding one should take effect immediately, and an operator who
		// has to restart the engine to see their new sign-in button will assume it
		// is broken.
		"Providers": s.externalProviders(r.Context()),
		// Only when this request actually needs one. In adaptive mode a person
		// signing in normally never sees a widget at all.
		"Captcha":         s.captcha.Enabled() && s.captcha.Required(r.RemoteAddr),
		"CaptchaProvider": string(s.captcha.Provider()),
		"CaptchaSiteKey":  s.captcha.SiteKey(),
	})
}

// loginPage is deliberately minimal and server-rendered: no JavaScript, so it
// works with autofill, password managers, and screen readers by default.
// html/template escapes every interpolation, so the parked query string cannot
// break out of the value attribute.
var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}
label{display:block;margin:.75rem 0 .25rem}input{width:100%;padding:.5rem;font-size:1rem}
button{margin-top:1rem;padding:.6rem 1rem;font-size:1rem;width:100%}
.err{color:#b00020;margin:.5rem 0}
.ref{color:#666;font-size:.85rem;margin:.25rem 0}
.alt{margin-top:1.25rem;border-top:1px solid #e4e4e7;padding-top:1rem}
.ext{display:block;padding:.6rem 1rem;border:1px solid #d4d4d8;border-radius:.25rem;
text-align:center;text-decoration:none;color:inherit}</style></head>
<body>
<h1>Sign in</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Reference}}<p class="ref">Reference: <code>{{.Reference}}</code></p>{{end}}
<form method="POST" action="/login">
<input type="hidden" name="authz" value="{{.Authz}}">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
<label for="u">Username or email</label>
<input id="u" name="username" autocomplete="username webauthn" autocapitalize="none" autofocus required>
<label for="p">Password</label>
<input id="p" name="password" type="password" autocomplete="current-password" required>
{{if .Captcha}}
{{if eq .CaptchaProvider "turnstile"}}
<div class="cf-turnstile" data-sitekey="{{.CaptchaSiteKey}}"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
{{else if eq .CaptchaProvider "hcaptcha"}}
<div class="h-captcha" data-sitekey="{{.CaptchaSiteKey}}"></div>
<script src="https://hcaptcha.com/1/api.js" async defer></script>
{{else}}
<div class="g-recaptcha" data-sitekey="{{.CaptchaSiteKey}}"></div>
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
{{end}}
{{end}}
<button type="submit">Sign in</button>
</form>
<p class="alt"><button type="button" id="passkey-signin">Sign in with a passkey</button></p>
{{if .Providers}}<div class="alt">
{{range .Providers}}<p><a class="ext" href="/login/with/{{.Slug}}">Continue with {{.Name}}</a></p>{{end}}
</div>{{end}}
<script src="/passkey.js"></script>
</body></html>`))

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	md, err := oidc.Build(s.cfg)
	if err != nil {
		s.log.Error("building discovery metadata", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "metadata unavailable")
		return
	}
	// registration_endpoint is advertised only where dynamic registration is
	// actually enabled. The endpoint exists either way, but a discovery document
	// naming one that answers 401 to every possible caller is the "advertised
	// before it works" mistake this project refuses elsewhere -- and a client
	// that reads it will try, fail, and blame its own configuration.
	if on, cerr := store.AnyRegistrationEnabled(r.Context(), s.db); cerr != nil {
		s.log.Error("checking whether dynamic registration is enabled", "err", cerr)
	} else if on {
		md.RegistrationEndpoint = s.cfg.Issuer + "/oauth2/register"
	}

	// Discovery is public, stable, and polled. Let it be cached, but not so long
	// that adding a signing algorithm takes a day to become visible.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, md)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// A relying party that refreshes its JWKS whenever it sees an unknown `kid`
	// is a free DoS amplifier: send tokens with random kids and it hammers this
	// endpoint. Cheap to fix, rarely discussed, so it is fixed here.
	if !s.jwks.allow() {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many key set requests")
		return
	}

	body, err := s.cfg.Keys.MarshalJWKS()
	if err != nil {
		s.log.Error("marshalling jwks", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "key set unavailable")
		return
	}
	// Well-behaved clients converge within max-age. Never assume they honour it:
	// the rotation dwell in internal/keys is sized for clients that do not.
	w.Header().Set("Cache-Control",
		fmt.Sprintf("public, max-age=%d", int(keys.JWKSMaxAge.Seconds())))
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"algs":   s.cfg.Keys.Algorithms(),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError uses the OAuth 2.0 error shape everywhere, including on endpoints
// that are not strictly OAuth, so clients and operators see one format.
func writeError(w http.ResponseWriter, code int, err, desc string) {
	writeJSON(w, code, map[string]string{
		"error":             err,
		"error_description": desc,
	})
}

// bucket is a token bucket. Global rather than per-IP on purpose: the JWKS
// endpoint is unauthenticated and typically sits behind a proxy, so per-IP
// limiting mostly measures the proxy.
type bucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

func newBucket(ratePerSec, capacity float64) *bucket {
	return &bucket{tokens: capacity, capacity: capacity, rate: ratePerSec, last: time.Now()}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// captchaOrigins returns the script and frame origins a provider needs.
//
// Enumerated rather than derived from the verify URL: the origin that serves a
// widget is often not the origin that verifies it, and guessing would produce a
// policy that silently blocks the challenge from rendering.
func captchaOrigins(p captcha.Provider) string {
	switch p {
	case captcha.Turnstile:
		return "https://challenges.cloudflare.com"
	case captcha.HCaptcha:
		return "https://hcaptcha.com https://*.hcaptcha.com"
	case captcha.ReCaptcha:
		return "https://www.google.com https://www.gstatic.com"
	default:
		return ""
	}
}

// captchaFromEnv reads the challenge configuration.
//
// Every value is refused rather than defaulted when it does not parse. A CAPTCHA
// that silently turned itself off because of a typo would be the worst kind of
// control: one an operator believes they have.
func captchaFromEnv() (*captcha.Verifier, error) {
	mode, err := captcha.ParseMode(os.Getenv("SIGNARI_CAPTCHA_MODE"))
	if err != nil {
		return nil, err
	}
	if mode == captcha.ModeOff {
		return nil, nil
	}

	provider, err := captcha.ParseProvider(os.Getenv("SIGNARI_CAPTCHA_PROVIDER"))
	if err != nil {
		return nil, err
	}
	site := os.Getenv("SIGNARI_CAPTCHA_SITE_KEY")
	secret := os.Getenv("SIGNARI_CAPTCHA_SECRET")
	if site == "" || secret == "" {
		return nil, fmt.Errorf("SIGNARI_CAPTCHA_MODE is %q but SIGNARI_CAPTCHA_SITE_KEY "+
			"or SIGNARI_CAPTCHA_SECRET is missing; a challenge with no keys renders "+
			"an empty box and refuses every sign-in", mode)
	}

	threshold := 3
	if v := os.Getenv("SIGNARI_CAPTCHA_AFTER_FAILURES"); v != "" {
		n, cerr := strconv.Atoi(v)
		if cerr != nil || n < 1 {
			return nil, fmt.Errorf("SIGNARI_CAPTCHA_AFTER_FAILURES must be a positive "+
				"integer, got %q", v)
		}
		threshold = n
	}

	return captcha.New(captcha.Config{
		Mode:                    mode,
		Provider:                provider,
		SiteKey:                 site,
		Secret:                  secret,
		FailuresBeforeChallenge: threshold,
		// Opt-in. See captcha.Config for why the default is to stay available.
		FailClosed: os.Getenv("SIGNARI_CAPTCHA_FAIL_CLOSED") == "1",
	}, nil), nil
}
