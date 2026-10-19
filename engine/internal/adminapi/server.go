// Package adminapi is the engine's write surface.
//
// Every change the Laravel admin makes arrives here. That is not a stylistic
// preference -- ADR-004 gives the admin role no privilege on schema `core` at
// all, so this is the only path that exists.
//
// The invariant this package enforces, from ADR-008:
//
//	EVERY mutation bumps core.config_version IN THE SAME TRANSACTION.
//
// Engine nodes poll that version to decide when to reload. If a write commits
// without bumping it, the change is durable but invisible: the database says a
// client is disabled while every running node keeps honouring it, until some
// unrelated write happens to bump the version. That failure is silent, it is
// intermittent, and it looks like a caching bug rather than a missing line --
// so the bump lives in one helper that every handler must route through.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/metrics"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/ratelimit"
	"signari.dev/engine/internal/store"
)

// Server is the admin write API. It listens separately from the public protocol
// endpoints so it can be bound to a private interface: an internet-reachable
// admin API on an identity provider is a large and unnecessary target.
type Server struct {
	db    *pgxpool.Pool
	log   *slog.Logger
	token string
	// ops is what Routes() registered, in registration order. The OpenAPI
	// document is rendered from this rather than from a parallel description,
	// so it cannot name a route that does not exist or omit one that does.
	ops []operation
	// metrics counts every admin request by route, method and status, on the
	// same series as the protocol listener (the /admin/ prefix keeps them
	// apart). Nil when nothing scrapes the process.
	metrics *metrics.Engine
	// hasher is the ENGINE's Argon2 configuration. Passwords set by an
	// administrator must be written with the same parameters the login path
	// expects; a hash produced elsewhere is a credential that may simply not
	// work, and the failure looks like the user mistyping.
	hasher *passwords.Hasher
	// pwPolicy is the SAME policy the sign-in paths enforce. An administrator
	// setting a password must not be able to set one a user could not.
	pwPolicy passwords.Policy

	// root unwraps subject keys, which is what personal user attributes are
	// sealed under. nil when the admin API was built without one, and the
	// attribute routes are then not registered at all -- a route that could only
	// ever answer "no key configured" is worse than an absent one, because it
	// looks like a capability.
	root *keys.RootKey

	// arrivals bounds work done for callers who have not authenticated yet.
	//
	// Every request costs a SHA-256 and an indexed database probe before it can
	// be refused, so an anonymous caller with no credential at all can generate
	// unbounded database load on the administrative interface. That is the
	// threat this answers, and it is a denial of service rather than a
	// credential attack: `auth` already explains why guessing a 256-bit random
	// token is not the risk, and a limiter does not change that either way.
	arrivals *ratelimit.Bucket

	// perToken keeps one caller from starving the others.
	//
	// A single shared bucket means the noisiest integration decides what
	// everybody else gets -- a bulk provisioning script would throttle the
	// console an operator is trying to use during the same incident. Keyed on
	// the authenticated token, which is safe to evict from because the key had
	// to exist and be unrevoked before the limiter is ever consulted.
	perToken *ratelimit.Keyed
}

func New(db *pgxpool.Pool, log *slog.Logger, token string) (*Server, error) {
	// Empty is allowed now: a deployment can run entirely on database tokens and
	// set no environment token at all, which is the better configuration. What is
	// refused is a SHORT one -- there is no rate limit that makes a 12-character
	// admin credential safe, and accepting it with a warning is not a control.
	if token != "" && len(token) < 32 {
		return nil, fmt.Errorf("admin API token must be at least 32 characters (got %d)", len(token))
	}
	return &Server{db: db, log: log, token: token,
		hasher:   passwords.Shared(),
		pwPolicy: passwords.PolicyFromEnv(),
		// Generous on purpose. Administration is low-volume and bursty -- an
		// operator paging through clients, a provisioning run creating a batch --
		// so these bound the damage without being something a real deployment
		// ever notices. A limit tight enough to interfere is a limit somebody
		// raises to infinity during an incident.
		arrivals: ratelimit.New(adminArrivalsPerSecond, adminArrivalsBurst),
		perToken: ratelimit.NewKeyed(adminPerTokenPerSecond, adminPerTokenBurst,
			adminTrackedTokens),
	}, nil
}

// Rate limits for the administrative interface.
const (
	adminArrivalsPerSecond = 100
	adminArrivalsBurst     = 200
	adminPerTokenPerSecond = 50
	adminPerTokenBurst     = 100
	// adminTrackedTokens bounds the per-token map. Far above the number of
	// credentials any deployment issues, because the map is only a memory bound
	// and evicting an entry hands its key a fresh allowance.
	adminTrackedTokens = 1024
)

// SetRootKey supplies the key that unwraps subject keys.
//
// Set after construction like the engine's other optional collaborators. Without
// it the user-attribute routes are not registered, because a personal attribute
// is sealed under a subject key and there is nothing useful to answer without
// the key that opens it.
func (s *Server) SetRootKey(root *keys.RootKey) { s.root = root }

// Routes returns the fully wrapped handler.
//
// It returns http.Handler rather than *http.ServeMux so that the global limiter
// is part of what a caller receives. Exposing the bare mux and a separate
// wrapper would leave two ways to serve this API, one of them unlimited -- and
// the unlimited one is shorter to type.
// SetMetrics instruments the admin API. Until it existed, every write to the
// identity provider (each client disabled, each token minted, each privilege
// granted) went unmeasured while the protocol listener counted its health
// checks.
func (s *Server) SetMetrics(e *metrics.Engine) { s.metrics = e }

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	handle := mux.HandleFunc
	if s.metrics != nil {
		// Each pattern declared to the route label set as it is registered,
		// as the protocol router does, or every admin series would read
		// route="other".
		handle = func(pattern string, h func(http.ResponseWriter, *http.Request)) {
			if i := strings.IndexByte(pattern, '/'); i >= 0 {
				metrics.RegisterRoutePattern(pattern[i:])
			}
			mux.HandleFunc(pattern, h)
		}
	}

	// route registers a handler AND records the operation, so the OpenAPI
	// document is derived from this list rather than written beside it.
	//
	// One call rather than a registration plus a separate "and describe it":
	// the second call is the one a route added next week does not get, and a
	// missing description is an operation that exists on the server and not in
	// the document that generated somebody's client.
	s.ops = s.ops[:0]
	route := func(pattern, scope string, h http.HandlerFunc) {
		handle(pattern, s.auth(scope, canonicalIDs(h)))
		s.recordOperation(pattern, scope)
	}
	// privileged is route for a write on a user or a group, which needs
	// privileged-users:write as well when the target is privileged (see
	// privileged.go). TestEveryWriteOnAUserOrGroupGuardsPrivilegedTargets
	// derives the routes that need it from this table, so a write on a user
	// registered with plain route fails there.
	privileged := func(pattern, scope string, target privilegedTarget, h http.HandlerFunc) {
		handle(pattern, s.auth(scope, canonicalIDs(s.requirePrivileged(target, h))))
		s.recordOperation(pattern, scope)
		s.ops[len(s.ops)-1].privileged = true
	}

	route("PATCH /admin/clients/{clientID}", ScopeClientsWrite, s.patchClient)
	route("DELETE /admin/clients/{clientID}", ScopeClientsWrite, s.deleteClient)
	route("POST /admin/users", ScopeUsersWrite, s.createUser)
	route("POST /admin/clients", ScopeClientsWrite, s.createClient)
	route("POST /admin/clients/{clientID}/rotate-secret", ScopeClientsWrite, s.rotateClientSecret)
	privileged("PATCH /admin/users/{userID}", ScopeUsersWrite, targetUser, s.patchUser)
	privileged("DELETE /admin/users/{userID}", ScopeUsersWrite, targetUser, s.deleteUser)
	route("GET /admin/users/{userID}/factors", ScopeUsersRead, s.listUserFactors)
	// Two patterns rather than an optional segment: the kinds a user may hold
	// several of need the credential named, and the ones keyed on the user must
	// not accept an id that would be silently ignored.
	privileged("DELETE /admin/users/{userID}/factors/{kind}", ScopeUsersWrite, targetUser, s.deleteUserFactor)
	privileged("DELETE /admin/users/{userID}/factors/{kind}/{factorID}", ScopeUsersWrite, targetUser, s.deleteUserFactor)
	route("POST /admin/organizations", ScopeOrganizationsWrite, s.createOrganization)

	// The scope catalogue. Registered unconditionally — unlike attributes, a
	// scope holds no personal data and needs no subject key.
	route("GET /admin/organizations/{orgID}/webauthn-policy", ScopeConfigRead, s.getWebAuthnPolicy)
	route("PUT /admin/organizations/{orgID}/webauthn-policy", ScopeOrganizationsWrite, s.putWebAuthnPolicy)
	route("GET /admin/organizations/{orgID}/scopes", ScopeConfigRead, s.listScopes)
	route("PUT /admin/organizations/{orgID}/scopes", ScopeOrganizationsWrite, s.declareScope)
	route("DELETE /admin/organizations/{orgID}/scopes/{scope}",
		ScopeOrganizationsWrite, s.deleteScope)

	// Forward-auth protected hosts.
	route("GET /admin/organizations/{orgID}/proxy-hosts", ScopeConfigRead, s.listProxyHosts)
	route("PUT /admin/organizations/{orgID}/proxy-hosts", ScopeOrganizationsWrite, s.putProxyHost)
	route("DELETE /admin/organizations/{orgID}/proxy-hosts/{host}",
		ScopeOrganizationsWrite, s.deleteProxyHost)
	route("GET /admin/audit-events", ScopeAuditRead, s.listAuditEvents)
	route("GET /admin/config-version", ScopeConfigRead, s.configVersion)

	// Reads. These complete the conditional-write protocol: a caller GETs the
	// resource, takes the ETag from the response, and sends it back as If-Match.
	// Without them the only readable endpoint was the version counter, so the
	// precondition had nothing to be a precondition ON.
	route("GET /admin/clients", ScopeClientsRead, s.listClients)
	route("GET /admin/clients/{clientID}", ScopeClientsRead, s.getClient)
	route("GET /admin/users", ScopeUsersRead, s.listUsers)
	route("GET /admin/users/{userID}", ScopeUsersRead, s.getUser)

	// Groups. Their own scope pair: editing membership grants application
	// access, which is a different decision from resetting a password.
	route("GET /admin/groups", ScopeGroupsRead, s.listGroups)
	route("GET /admin/groups/{groupID}", ScopeGroupsRead, s.getGroup)
	route("POST /admin/groups", ScopeGroupsWrite, s.createGroup)
	privileged("PATCH /admin/groups/{groupID}", ScopeGroupsWrite, targetGroup, s.patchGroup)
	privileged("DELETE /admin/groups/{groupID}", ScopeGroupsWrite, targetGroup, s.deleteGroup)
	route("GET /admin/groups/{groupID}/members", ScopeGroupsRead, s.listGroupMembers)
	privileged("PUT /admin/groups/{groupID}/members/{userID}", ScopeGroupsWrite, targetGroup, s.addGroupMember)
	privileged("DELETE /admin/groups/{groupID}/members/{userID}", ScopeGroupsWrite, targetGroup, s.removeGroupMember)

	// Sessions. Reading is part of seeing a user; ending one is acting on them,
	// so the scopes follow users:* rather than getting a third pair. Ending
	// sessions is plain route even for a privileged user: it only withdraws
	// access (see privileged.go).
	route("GET /admin/users/{userID}/sessions", ScopeUsersRead, s.listUserSessions)
	route("DELETE /admin/users/{userID}/sessions", ScopeUsersWrite, s.revokeUserSessions)
	route("DELETE /admin/sessions/{sid}", ScopeUsersWrite, s.revokeSession)
	privileged("POST /admin/subjects/{subjectID}/erase", ScopeSubjectsErase, targetUser, s.eraseSubject)

	// User attributes. Registered only when a root key is available, because a
	// personal attribute is sealed under a subject key and cannot be read
	// without it. Declaring the SHAPE is configuration and takes the config
	// scope; setting one person's values is user administration.
	if s.root != nil {
		route("GET /admin/organizations/{orgID}/attributes", ScopeConfigRead, s.listAttributes)
		route("PUT /admin/organizations/{orgID}/attributes", ScopeOrganizationsWrite, s.declareAttribute)
		route("GET /admin/users/{userID}/attributes", ScopeUsersRead, s.getUserAttributes)
		privileged("PUT /admin/users/{userID}/attributes", ScopeUsersWrite, targetUser, s.setUserAttributes)

		// Claim mappers. Creating one decides that a relying party receives a
		// fact about every user who has it, so it takes the same scope as
		// declaring the attribute rather than the user-administration scope.
		route("GET /admin/organizations/{orgID}/claim-mappers", ScopeConfigRead, s.listMappers)
		route("POST /admin/organizations/{orgID}/claim-mappers",
			ScopeOrganizationsWrite, s.createMapper)
		route("DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}",
			ScopeOrganizationsWrite, s.deleteMapper)
	}

	// The document itself, unauthenticated. See handleOpenAPI for why: it
	// describes the shape of the API and no data, and the same facts are already
	// public in docs/admin-api.md.
	handle("GET /admin/openapi.json", s.handleOpenAPI)

	var inner http.Handler = mux
	if s.metrics != nil {
		// Innermost, next to the mux, which is the only place the matched
		// pattern is known (see the same choice in httpapi.Routes).
		inner = s.metrics.Middleware(mux)
	}
	return s.limitArrivals(inner)
}

// limitArrivals is the outermost wrapper: it runs before authentication, because
// authentication is the work being protected.
func (s *Server) limitArrivals(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.arrivals != nil && !s.arrivals.Allow() {
			tooManyRequests(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tooManyRequests answers a throttled caller.
//
// Retry-After is set for the same reason the JWKS endpoint sets it: a client
// told only "no" retries immediately and makes the problem worse.
func tooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeJSON(w, http.StatusTooManyRequests, map[string]string{
		"error":  "rate_limited",
		"detail": "too many administrative requests",
	})
}

// auth authenticates the caller and requires a scope.
//
// # Why this now reads the database
//
// It used to be a constant-time comparison against one environment variable and
// nothing else, on the reasoning that a lookup turns a guessing attempt into a
// query. That reasoning was sound about load and wrong about risk: it also meant
// no revocation, no expiry, no attribution and no organisation boundary, and a
// leaked token stayed valid until somebody restarted every node.
//
// The lookup is a single indexed probe on a SHA-256 of the presented value.
// Guessing is not the threat against a 256-bit random token; leaking is, and
// leaking is what the old design had no answer to. The environment token still
// works and still needs no database, so the break-glass path is unchanged.
func (s *Server) auth(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
			unauthorized(w)
			return
		}

		p, err := s.resolveToken(r.Context(), h[len(prefix):])
		if err != nil {
			if !errors.Is(err, errTokenRejected) {
				s.log.Error("resolving an admin token", "err", err)
				writeJSON(w, http.StatusServiceUnavailable,
					map[string]string{"error": "unavailable"})
				return
			}
			unauthorized(w)
			return
		}

		// Per-token, and placed HERE rather than earlier for a specific reason.
		//
		// The key has to be an authenticated identity. Keying a limiter on
		// anything the caller supplies -- the raw bearer value, a header, an
		// address behind a proxy -- lets them mint fresh keys at will, and since
		// a new key starts with a full bucket, the limit becomes something the
		// attacker resets rather than something they are subject to. By this
		// point the token has been found, is unrevoked and is unexpired, so its
		// name is a bounded value we chose.
		//
		// Its purpose is fairness, not defence: the global limiter above already
		// bounds total work. This stops one integration's bulk run from consuming
		// the whole allowance while an operator is trying to use the console.
		if s.perToken != nil && !s.perToken.Allow(p.Name) {
			s.log.Info("admin request throttled", "token", p.Name,
				"method", r.Method, "path", r.URL.Path)
			tooManyRequests(w)
			return
		}

		// Authenticated but not permitted is 403, and says which scope was
		// missing. This is an operator-facing API: "forbidden" with no detail
		// turns a one-line fix into an afternoon.
		if !p.Can(scope) {
			s.log.Info("admin request refused: missing scope", "token", p.Name,
				"required", scope, "held", p.Scopes)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "insufficient_scope",
				"detail": "this token does not hold " + scope,
			})
			return
		}

		if p.BreakGlass {
			// Logged every single time. A credential that bypasses revocation and
			// expiry should never be quietly interchangeable with the others.
			s.log.Warn("admin request used the break-glass environment token",
				"method", r.Method, "path", r.URL.Path)
		}
		s.touch(p.TokenID)
		next(w, r.WithContext(withPrincipal(r.Context(), p)))
	}
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="signari-admin"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

type patchClientRequest struct {
	// Pointer so "absent" and "false" are distinguishable. Without this, a PATCH
	// that does not mention `enabled` would silently disable the client.
	Enabled *bool `json:"enabled"`
	// RequirePKCE is the opt-out for an application that cannot send a PKCE
	// challenge, and the way back. A public client cannot opt out.
	RequirePKCE *bool `json:"require_pkce"`
	// MayExchange grants or withdraws RFC 8693 token exchange, and
	// ExchangeAudiences replaces the audiences it may exchange for besides
	// itself. Either alone leaves the other as it is. Written by the same
	// store.SetClientExchange as the CLI and `signari apply`.
	MayExchange       *bool     `json:"may_exchange"`
	ExchangeAudiences *[]string `json:"exchange_audiences"`
	// The sign-out registration, through store.SetClientLogout as the CLI,
	// `apply` and dynamic registration write it. Each is left alone when absent.
	PostLogoutRedirectURIs      *[]string `json:"post_logout_redirect_uris"`
	FrontchannelLogoutURI       *string   `json:"frontchannel_logout_uri"`
	FrontchannelSessionRequired *bool     `json:"frontchannel_logout_session_required"`
}

func (r patchClientRequest) setsLogout() bool {
	return r.PostLogoutRedirectURIs != nil || r.FrontchannelLogoutURI != nil || r.FrontchannelSessionRequired != nil
}

func (s *Server) patchClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	var req patchClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Enabled == nil && req.RequirePKCE == nil && req.MayExchange == nil && req.ExchangeAudiences == nil &&
		!req.setsLogout() {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "nothing_to_change", "detail": "no supported field present",
		})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var enabled, requirePKCE, mayExchange bool
	var exchangeAudiences []string
	var logout map[string]any
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		// This handler previously changed a client without ever reading which
		// organisation it belonged to, so there was nothing for the boundary to
		// check against. The lookup exists for that reason.
		var orgID, kind string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text, client_type FROM core.clients WHERE client_id = $1`,
			clientID).Scan(&orgID, &kind); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		if kind == "public" && req.RequirePKCE != nil && !*req.RequirePKCE {
			return errPublicClientNeedsPKCE
		}

		err := tx.QueryRow(ctx, `
			UPDATE core.clients
			   SET enabled = COALESCE($2, enabled),
			       require_pkce = COALESCE($3, require_pkce),
			       updated_at = now()
			 WHERE client_id = $1
			RETURNING enabled, require_pkce`,
			clientID, req.Enabled, req.RequirePKCE).Scan(&enabled, &requirePKCE)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}

		// Disabling a client is the emergency lever -- the way an operator cuts a
		// compromised integration off from every user at once. It had no audit
		// record at all, so afterwards there was no way to say who pulled it, or
		// when, or whether it was pulled rather than the client breaking on its
		// own. The record names only the fields this request set.
		detail := map[string]any{}
		if req.Enabled != nil {
			detail["enabled"] = *req.Enabled
		}
		if req.RequirePKCE != nil {
			detail["require_pkce"] = *req.RequirePKCE
		}
		if req.MayExchange != nil || req.ExchangeAudiences != nil {
			if err := tx.QueryRow(ctx, `SELECT may_exchange, exchange_audiences FROM core.clients
				WHERE client_id = $1`, clientID).Scan(&mayExchange, &exchangeAudiences); err != nil {
				return err
			}
			if req.MayExchange != nil {
				mayExchange = *req.MayExchange
			}
			if req.ExchangeAudiences != nil {
				exchangeAudiences = *req.ExchangeAudiences
			}
			if _, err := store.SetClientExchange(ctx, tx, clientID, mayExchange, exchangeAudiences); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT may_exchange, exchange_audiences FROM core.clients
				WHERE client_id = $1`, clientID).Scan(&mayExchange, &exchangeAudiences); err != nil {
				return err
			}
			detail["may_exchange"] = mayExchange
			detail["exchange_audiences"] = exchangeAudiences
		}
		if req.setsLogout() {
			if err := store.SetClientLogout(ctx, tx, clientID, store.ClientLogout{
				PostLogoutRedirectURIs: req.PostLogoutRedirectURIs, FrontchannelURI: req.FrontchannelLogoutURI,
				FrontchannelSessionRequired: req.FrontchannelSessionRequired,
			}); err != nil {
				return err
			}
			uris, fc, fcSID, err := store.ClientLogoutOf(ctx, tx, clientID)
			if err != nil {
				return err
			}
			logout = map[string]any{"post_logout_redirect_uris": uris, "frontchannel_logout_uri": fc,
				"frontchannel_logout_session_required": fcSID}
			for k, v := range logout {
				detail[k] = v
			}
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.client_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: clientID, Detail: detail,
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case errors.Is(err, errPublicClientNeedsPKCE):
		writePublicClientNeedsPKCE(w)
		return
	case errors.Is(err, store.ErrExchangeNeedsConfidentialClient):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "confidential_client_required", "detail": err.Error() +
				": a public client cannot prove it is the client the permission was granted to",
		})
		return
	case errors.Is(err, store.ErrInvalidExchangeAudience):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_audience", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrInvalidLogoutRegistration):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_logout_uri", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("patching client", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)

	// Disabling is a security-relevant action, so it is logged at a level an
	// operator will actually see, with the version needed to confirm propagation.
	s.log.Info("client updated", "client_id", clientID, "enabled", enabled,
		"require_pkce", requirePKCE, "config_version", version)

	out := map[string]any{
		"client_id": clientID, "enabled": enabled, "require_pkce": requirePKCE,
		"config_version": version,
	}
	if req.MayExchange != nil || req.ExchangeAudiences != nil {
		out["may_exchange"], out["exchange_audiences"] = mayExchange, exchangeAudiences
	}
	for k, v := range logout {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

var errPublicClientNeedsPKCE = errors.New("a public client must require PKCE")

// configVersion reports the current configuration version.
//
// It is also the READ half of the conditional-write protocol: the ETag it
// returns is what a caller sends back as If-Match. Without an ETag here a client
// would have to construct the header from the JSON body, and the whole point of
// using RFC 7232 rather than a bespoke scheme is that ordinary HTTP clients,
// proxies and generated SDKs already understand it.
func (s *Server) configVersion(w http.ResponseWriter, r *http.Request) {
	var v int64
	if err := s.db.QueryRow(r.Context(),
		`SELECT version FROM core.config_version`).Scan(&v); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, v)
	writeJSON(w, http.StatusOK, map[string]any{"config_version": v})
}

var errNotFound = errors.New("not found")

// writeCrossOrg answers a boundary violation with 403 and says so.
//
// Not 404. The record exists; this credential simply may not touch it, and
// pretending otherwise sends an operator hunting for a resource that is right
// where they left it.
func writeCrossOrg(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": "outside_token_organisation", "detail": err.Error(),
	})
}

// mutate runs fn inside a transaction and bumps config_version with it.
//
// This is the ONLY way a handler should write. The bump is not appended after
// fn succeeds -- it is part of the same transaction, so a rollback takes the
// version with it. A write that commits while the bump rolls back would leave
// every engine node serving stale config with no signal that anything changed.
//
// Unconditional. Handlers that honour RFC 7232 preconditions call mutateIf.
func (s *Server) mutate(ctx context.Context, fn func(pgx.Tx) error) (int64, error) {
	return s.mutateIf(ctx, precondition{}, fn)
}

// mutateIf is mutate with an optional If-Match precondition.
//
// The check runs INSIDE the transaction, before fn, holding a row lock on
// config_version (see precondition.go for why anything else races). A failed
// precondition returns before fn has written anything, so a refused conditional
// write leaves the database exactly as it was -- which is the property that makes
// it worth offering rather than a status code that arrives too late.
func (s *Server) mutateIf(ctx context.Context, p precondition, fn func(pgx.Tx) error) (int64, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := checkPrecondition(ctx, tx, p); err != nil {
		return 0, err
	}

	if err := fn(tx); err != nil {
		return 0, err
	}

	var version int64
	if err := tx.QueryRow(ctx, `
		UPDATE core.config_version
		SET version = version + 1, bumped_at = now()
		WHERE id = true
		RETURNING version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("bumping config version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return version, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// constantTimeEqual compares without leaking length or content through timing.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		// Length alone is not secret here (the token length is fixed by config),
		// and comparing different lengths in constant time is not meaningful.
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
