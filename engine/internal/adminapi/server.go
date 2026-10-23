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
// That version is what an If-Match precondition is compared against, and what
// the console and Terraform send back. If a write commits without bumping it,
// a client that read the configuration before the write still matches, and its
// conditional write overwrites the change it never saw. That failure is silent
// and looks like a lost edit rather than a missing line -- so the bump lives in
// one helper that every handler must route through. No reload loop watches the
// counter: configuration is read per request (ADR-007, ADR-008). This comment
// once described a reload driven by it, which never existed.
package adminapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/metrics"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/provision"
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

	// accessIssuers verify this deployment's own access tokens audienced to
	// the Admin API (accesstoken.go), one for each instance served. Empty until
	// AcceptAccessTokens, and then only admin tokens are accepted.
	accessIssuers []accessIssuer

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

	// limits are the rates the two limiters were built with, reported by
	// /admin/system; release names the build there.
	limits  adminLimits
	release string

	// mux is the router Routes last built, which a batch dispatches its
	// operations through.
	mux atomic.Pointer[http.ServeMux]

	// targetClient is what calls a provisioning target: provision.HTTPClient,
	// the client `signari scim sync` uses, unless a test hands it a server it
	// started.
	targetClient func() (*http.Client, error)

	// directorySync runs one directory sync: directory.Sync, which
	// `signari dir sync` runs too, unless a test stands in for the
	// directory it would call.
	directorySync func(ctx context.Context, pool *pgxpool.Pool, root *keys.RootKey, orgID, slug string,
		apply bool) (directory.SyncReport, error)
}

func New(db *pgxpool.Pool, log *slog.Logger, token string) (*Server, error) {
	// Empty is allowed now: a deployment can run entirely on database tokens and
	// set no environment token at all, which is the better configuration. What is
	// refused is a SHORT one -- there is no rate limit that makes a 12-character
	// admin credential safe, and accepting it with a warning is not a control.
	if token != "" && len(token) < 32 {
		return nil, fmt.Errorf("admin API token must be at least 32 characters (got %d)", len(token))
	}
	limits, err := limitsFromEnv()
	if err != nil {
		return nil, err
	}
	return &Server{db: db, log: log, token: token,
		hasher:   passwords.Shared(),
		pwPolicy: passwords.PolicyFromEnv(),
		// Generous on purpose. Administration is low-volume and bursty -- an
		// operator paging through clients, a provisioning run creating a batch --
		// so these bound the damage without being something a real deployment
		// ever notices. A limit tight enough to interfere is a limit somebody
		// raises to infinity during an incident. SIGNARI_ADMIN_RATE and
		// SIGNARI_ADMIN_TOKEN_RATE move them (6.08); the bursts are twice.
		limits:   limits,
		arrivals: ratelimit.New(float64(limits.arrivals), float64(2*limits.arrivals)),
		perToken: ratelimit.NewKeyed(float64(limits.perToken), float64(2*limits.perToken),
			adminTrackedTokens),
		targetClient:  provision.HTTPClient,
		directorySync: directory.Sync,
	}, nil
}

// Rate limits for the administrative interface, by default; the bursts are
// twice the rate.
const (
	adminArrivalsPerSecond = 100
	adminPerTokenPerSecond = 50
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

	privileged("PATCH /admin/clients/{clientID}", ScopeClientsWrite, targetClient, s.patchClient)
	privileged("DELETE /admin/clients/{clientID}", ScopeClientsWrite, targetClient, s.deleteClient)
	route("POST /admin/users", ScopeUsersWrite, s.createUser)
	route("POST /admin/clients", ScopeClientsWrite, s.createClient)
	privileged("POST /admin/clients/{clientID}/rotate-secret", ScopeClientsWrite, targetClient, s.rotateClientSecret)
	// Which groups it is told of (grouprelease.go).
	privileged("PUT /admin/clients/{clientID}/group-release", ScopeClientsWrite, targetClient, s.putGroupRelease)
	privileged("DELETE /admin/clients/{clientID}/group-release", ScopeClientsWrite, targetClient, s.deleteGroupRelease)
	// A client's Shared Signals stream paused, disabled or enabled (ssf.go).
	privileged("PATCH /admin/clients/{clientID}/ssf-stream", ScopeClientsWrite, targetClient, s.setStreamStatus)
	privileged("PATCH /admin/users/{userID}", ScopeUsersWrite, targetUser, s.patchUser)
	privileged("DELETE /admin/users/{userID}", ScopeUsersWrite, targetUser, s.deleteUser)
	route("GET /admin/users/{userID}/factors", ScopeUsersRead, s.listUserFactors)
	// Two patterns rather than an optional segment: the kinds a user may hold
	// several of need the credential named, and the ones keyed on the user must
	// not accept an id that would be silently ignored.
	privileged("DELETE /admin/users/{userID}/factors/{kind}", ScopeUsersWrite, targetUser, s.deleteUserFactor)
	privileged("DELETE /admin/users/{userID}/factors/{kind}/{factorID}", ScopeUsersWrite, targetUser, s.deleteUserFactor)
	privileged("DELETE /admin/users/{userID}/throttle", ScopeUsersWrite, targetUser, s.unlockUser)
	// A passkey is a way into the account, so a privileged target needs the
	// privileged scope as a password reset does.
	privileged("POST /admin/users/{userID}/passkey-link", ScopeUsersWrite, targetUser, s.issuePasskeyLink)
	// Invitations. users:write, because an accepted one makes an account; a
	// group it names is checked as adding a member is (invitations.go).
	route("GET /admin/invitations", ScopeUsersRead, s.listInvitations)
	route("POST /admin/invitations", ScopeUsersWrite, s.createInvitation)
	route("DELETE /admin/invitations/{invitationID}", ScopeUsersWrite, s.revokeInvitation)
	// Admin tokens, each held to the caller in every dimension (tokensapi.go).
	route("GET /admin/tokens", ScopeTokensRead, s.listTokens)
	route("POST /admin/tokens", ScopeTokensWrite, s.createToken)
	route("POST /admin/tokens/{tokenID}/rotate", ScopeTokensWrite, s.rotateToken)
	route("DELETE /admin/tokens/{tokenID}", ScopeTokensWrite, s.revokeToken)
	route("POST /admin/organizations", ScopeOrganizationsWrite, s.createOrganization)
	route("GET /admin/organizations", ScopeConfigRead, s.listOrganizations)
	route("GET /admin/organizations/{orgID}", ScopeConfigRead, s.getOrganization)
	// Suspension, deployment-wide tokens only (organizations.go).
	route("PATCH /admin/organizations/{orgID}", ScopeOrganizationsWrite, s.patchOrganization)
	// Each organisation's budget (budgets.go): deployment-wide tokens set it.
	route("GET /admin/organizations/{orgID}/budgets", ScopeConfigRead, s.getBudgets)
	route("PUT /admin/organizations/{orgID}/budgets", ScopeOrganizationsWrite, s.putBudgets)
	// Its sign-in and session policy, the `instance` commands' (orgsettings.go).
	route("GET /admin/organizations/{orgID}/settings", ScopeConfigRead, s.getOrgSettings)
	route("PATCH /admin/organizations/{orgID}/settings", ScopeOrganizationsWrite, s.patchOrgSettings)
	// Self-sign-up, `signari signup` (signup.go).
	route("GET /admin/organizations/{orgID}/signup", ScopeConfigRead, s.getSignup)
	route("PUT /admin/organizations/{orgID}/signup", ScopeOrganizationsWrite, s.putSignup)
	route("DELETE /admin/organizations/{orgID}/signup", ScopeOrganizationsWrite, s.deleteSignup)
	// Instances and their appearance, deployment-wide tokens only
	// (instances.go).
	route("GET /admin/instances", ScopeConfigRead, s.listInstances)
	route("GET /admin/instances/{instanceID}/brand", ScopeConfigRead, s.getBrand)
	route("PUT /admin/instances/{instanceID}/brand", ScopeOrganizationsWrite, s.putBrand)
	route("DELETE /admin/instances/{instanceID}/brand", ScopeOrganizationsWrite, s.deleteBrand)
	route("GET /admin/instances/{instanceID}/webauthn", ScopeConfigRead, s.getInstanceWebAuthn)
	route("PUT /admin/instances/{instanceID}/webauthn", ScopeOrganizationsWrite, s.putInstanceWebAuthn)
	route("GET /admin/instances/{instanceID}/issuer-aliases", ScopeConfigRead, s.listIssuerAliases)
	route("POST /admin/instances/{instanceID}/issuer-aliases", ScopeOrganizationsWrite, s.addIssuerAlias)
	route("PATCH /admin/instances/{instanceID}/issuer-aliases", ScopeOrganizationsWrite, s.retireIssuerAlias)
	// UMA resource-owner intervention, `signari uma` (uma.go).
	route("GET /admin/organizations/{orgID}/uma", ScopeConfigRead, s.getUMASettings)
	route("PUT /admin/organizations/{orgID}/uma", ScopeOrganizationsWrite, s.putUMASettings)
	route("GET /admin/organizations/{orgID}/uma/requests", ScopeConfigRead, s.listUMARequests)
	route("POST /admin/organizations/{orgID}/uma/requests/{requestID}/approve", ScopeOrganizationsWrite, s.approveUMA)
	route("POST /admin/organizations/{orgID}/uma/requests/{requestID}/deny", ScopeOrganizationsWrite, s.denyUMA)
	// Trusted Client Attesters, `signari attester` (attesters.go).
	route("GET /admin/organizations/{orgID}/attesters", ScopeConfigRead, s.listAttesters)
	route("PUT /admin/organizations/{orgID}/attesters/{name}", ScopeOrganizationsWrite, s.putAttester)
	route("DELETE /admin/organizations/{orgID}/attesters/{name}", ScopeOrganizationsWrite, s.deleteAttester)
	// RFC 9396 authorization details types, `signari rar register` (rar.go).
	route("GET /admin/organizations/{orgID}/authorization-detail-types", ScopeConfigRead, s.listDetailTypes)
	route("PUT /admin/organizations/{orgID}/authorization-detail-types", ScopeOrganizationsWrite, s.putDetailType)
	route("DELETE /admin/organizations/{orgID}/authorization-detail-types", ScopeOrganizationsWrite, s.deleteDetailType)
	// Interstitial prompts, `signari prompt` (prompts.go).
	route("GET /admin/organizations/{orgID}/prompts", ScopeConfigRead, s.listPrompts)
	route("PUT /admin/organizations/{orgID}/prompts/{slug}", ScopeOrganizationsWrite, s.putPrompt)
	route("PATCH /admin/organizations/{orgID}/prompts/{slug}", ScopeOrganizationsWrite, s.patchPrompt)
	// The access policy and sign-in flows, `signari policy` and `signari flow`
	// (declarative.go).
	route("GET /admin/organizations/{orgID}/access-policy", ScopeConfigRead, s.getAccessPolicy)
	route("PUT /admin/organizations/{orgID}/access-policy", ScopeOrganizationsWrite, s.putAccessPolicy)
	route("GET /admin/organizations/{orgID}/sign-in-flow", ScopeConfigRead, s.getSignInFlow)
	route("PUT /admin/organizations/{orgID}/sign-in-flow", ScopeOrganizationsWrite, s.putSignInFlow)
	// Upstream identity providers' settings, `signari idp` (idps.go).
	route("GET /admin/organizations/{orgID}/identity-providers", ScopeConfigRead, s.listIdentityProviders)
	route("PATCH /admin/organizations/{orgID}/identity-providers/{slug}", ScopeOrganizationsWrite,
		s.patchIdentityProvider)
	route("PUT /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map", ScopeOrganizationsWrite,
		s.putIdPAttributeMap)
	route("DELETE /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map", ScopeOrganizationsWrite,
		s.deleteIdPAttributeMap)
	// SAML service providers, `signari saml` (saml.go).
	route("GET /admin/organizations/{orgID}/saml-providers", ScopeConfigRead, s.listSAMLProviders)
	route("POST /admin/organizations/{orgID}/saml-providers", ScopeOrganizationsWrite, s.addSAMLProvider)
	route("PATCH /admin/organizations/{orgID}/saml-providers/{providerID}", ScopeOrganizationsWrite,
		s.patchSAMLProvider)
	route("PUT /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release", ScopeOrganizationsWrite,
		s.putSAMLAttributeRelease)
	route("DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release", ScopeOrganizationsWrite,
		s.deleteSAMLAttributeRelease)
	route("PUT /admin/organizations/{orgID}/saml-providers/{providerID}/group-release", ScopeOrganizationsWrite,
		s.putSAMLGroupRelease)
	route("DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/group-release", ScopeOrganizationsWrite,
		s.deleteSAMLGroupRelease)
	// Inbound SCIM sources, `signari scim-source` (scimsources.go).
	route("GET /admin/organizations/{orgID}/scim-sources", ScopeConfigRead, s.listSCIMSources)
	route("POST /admin/organizations/{orgID}/scim-sources", ScopeOrganizationsWrite, s.addSCIMSource)
	route("PATCH /admin/organizations/{orgID}/scim-sources/{slug}", ScopeOrganizationsWrite, s.patchSCIMSource)
	// The transmitters whose Shared Signals events are acted on, `signari ssf
	// add-source` (ssf.go).
	route("GET /admin/organizations/{orgID}/ssf-sources", ScopeConfigRead, s.listSources)
	route("PUT /admin/organizations/{orgID}/ssf-sources", ScopeOrganizationsWrite, s.putSource)
	// Fine-grained authorization, `signari authz` (authz.go).
	route("GET /admin/organizations/{orgID}/authorization-model", ScopeConfigRead, s.getAuthzModel)
	route("PUT /admin/organizations/{orgID}/authorization-model", ScopeOrganizationsWrite, s.putAuthzModel)
	route("PUT /admin/organizations/{orgID}/relations", ScopeOrganizationsWrite, s.grantRelation)
	route("DELETE /admin/organizations/{orgID}/relations", ScopeOrganizationsWrite, s.revokeRelation)
	// Configuration as code, `signari plan` and `signari apply`
	// (configapply.go). Each change also needs the scope its own route takes.
	route("POST /admin/organizations/{orgID}/config", ScopeOrganizationsWrite, s.applyConfig)
	// Outposts, `signari outpost` (outposts.go).
	route("GET /admin/organizations/{orgID}/outposts", ScopeConfigRead, s.listOutposts)
	route("POST /admin/organizations/{orgID}/outposts", ScopeOrganizationsWrite, s.createOutpost)
	route("PATCH /admin/organizations/{orgID}/outposts/{name}", ScopeOrganizationsWrite, s.patchOutpost)
	// Dynamic client registration and its initial access tokens, `signari
	// registration` (registration.go).
	route("GET /admin/organizations/{orgID}/registration", ScopeConfigRead, s.getRegistration)
	route("PUT /admin/organizations/{orgID}/registration", ScopeOrganizationsWrite, s.putRegistration)
	route("DELETE /admin/organizations/{orgID}/registration", ScopeOrganizationsWrite, s.deleteRegistration)
	route("GET /admin/organizations/{orgID}/registration-tokens", ScopeConfigRead, s.listRegistrationTokens)
	route("POST /admin/organizations/{orgID}/registration-tokens", ScopeOrganizationsWrite, s.createRegistrationToken)
	route("DELETE /admin/organizations/{orgID}/registration-tokens/{tokenID}", ScopeOrganizationsWrite,
		s.revokeRegistrationToken)

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

	// Who the caller is, for any caller (me.go).
	route("GET /admin/me", "", s.handleMe)

	// Administrative roles (roles.go): who holds which in the organisation.
	route("GET /admin/organizations/{orgID}/role-bindings", ScopeConfigRead, s.listRoleBindings)
	route("POST /admin/organizations/{orgID}/role-bindings", ScopeOrganizationsWrite, s.grantRole)
	route("DELETE /admin/organizations/{orgID}/role-bindings/{bindingID}",
		ScopeOrganizationsWrite, s.revokeRole)
	route("GET /admin/audit-events", ScopeAuditRead, s.listAuditEvents)
	route("GET /admin/config-version", ScopeConfigRead, s.configVersion)

	// Reads. These complete the conditional-write protocol: a caller GETs the
	// resource, takes the ETag from the response, and sends it back as If-Match.
	// Without them the only readable endpoint was the version counter, so the
	// precondition had nothing to be a precondition ON.
	route("GET /admin/clients", ScopeClientsRead, s.listClients)
	route("GET /admin/clients/{clientID}", ScopeClientsRead, s.getClient)
	route("GET /admin/clients/{clientID}/group-release", ScopeClientsRead, s.getGroupRelease)
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
	// The VLAN or Filter-Id a group's members are given (radius.go). Under
	// groups:write, which already decides who is in the group.
	route("GET /admin/organizations/{orgID}/radius-authorizations", ScopeConfigRead, s.listRADIUSAuthorizations)
	privileged("PUT /admin/groups/{groupID}/radius", ScopeGroupsWrite, targetGroup, s.putRADIUSAuthorization)
	privileged("DELETE /admin/groups/{groupID}/radius", ScopeGroupsWrite, targetGroup, s.deleteRADIUSAuthorization)

	// Sessions. Reading is part of seeing a user; ending one is acting on them,
	// so the scopes follow users:* rather than getting a third pair. Ending
	// sessions is plain route even for a privileged user: it only withdraws
	// access (see privileged.go).
	route("GET /admin/users/{userID}/sessions", ScopeUsersRead, s.listUserSessions)
	route("DELETE /admin/users/{userID}/sessions", ScopeUsersWrite, s.revokeUserSessions)
	// What the person sees at /account/connected, and its withdrawal (6.08).
	route("GET /admin/users/{userID}/consents", ScopeUsersRead, s.listUserConsents)
	route("DELETE /admin/users/{userID}/consents/{clientID}", ScopeUsersWrite, s.revokeUserConsent)
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
		// Everything kept about a person, which includes their attributes
		// unsealed; registered here for the same reason.
		route("GET /admin/subjects/{subjectID}/export", ScopeSubjectsExport, s.exportSubject)
		privileged("PUT /admin/users/{userID}/attributes", ScopeUsersWrite, targetUser, s.setUserAttributes)

		// Claim mappers. Creating one decides that a relying party receives a
		// fact about every user who has it, so it takes the same scope as
		// declaring the attribute rather than the user-administration scope.
		route("GET /admin/organizations/{orgID}/claim-mappers", ScopeConfigRead, s.listMappers)
		route("POST /admin/organizations/{orgID}/claim-mappers",
			ScopeOrganizationsWrite, s.createMapper)
		route("DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}",
			ScopeOrganizationsWrite, s.deleteMapper)

		// The provider an organisation is migrating off (2.01). Under the root
		// key because an oidc_password source's client secret is sealed with it.
		route("GET /admin/organizations/{orgID}/migration-source", ScopeConfigRead, s.getMigrationSource)
		route("PUT /admin/organizations/{orgID}/migration-source", ScopeOrganizationsWrite, s.putMigrationSource)
		route("DELETE /admin/organizations/{orgID}/migration-source", ScopeOrganizationsWrite, s.deleteMigrationSource)
		route("GET /admin/organizations/{orgID}/resource-servers", ScopeConfigRead, s.listResourceServers)
		route("PUT /admin/organizations/{orgID}/resource-servers", ScopeOrganizationsWrite, s.putResourceServer)
		route("DELETE /admin/organizations/{orgID}/resource-servers", ScopeOrganizationsWrite, s.deleteResourceServer)

		// Event subscriptions (subscriptions.go), whose signing secrets are
		// sealed with the root key.
		route("GET /admin/organizations/{orgID}/event-subscriptions", ScopeConfigRead, s.listSubscriptions)
		route("POST /admin/organizations/{orgID}/event-subscriptions", ScopeOrganizationsWrite, s.createSubscription)
		route("DELETE /admin/organizations/{orgID}/event-subscriptions/{name}", ScopeOrganizationsWrite, s.deleteSubscription)
		route("POST /admin/organizations/{orgID}/event-subscriptions/{name}/rotate-secret", ScopeOrganizationsWrite,
			s.rotateSubscriptionSecret)
		route("POST /admin/organizations/{orgID}/event-subscriptions/{name}/enable", ScopeOrganizationsWrite,
			s.enableSubscription)
		route("POST /admin/organizations/{orgID}/event-subscriptions/{name}/test", ScopeOrganizationsWrite,
			s.testSubscription)

		// Extension providers (providers.go), whose signing secrets are sealed
		// with the root key.
		route("GET /admin/organizations/{orgID}/providers", ScopeConfigRead, s.listProviders)
		route("PUT /admin/organizations/{orgID}/providers/{hook}", ScopeOrganizationsWrite, s.putProvider)
		route("DELETE /admin/organizations/{orgID}/providers/{hook}", ScopeOrganizationsWrite, s.deleteProvider)
		route("POST /admin/organizations/{orgID}/providers/{hook}/rotate-secret", ScopeOrganizationsWrite,
			s.rotateProviderSecret)
		route("PUT /admin/organizations/{orgID}/providers/{hook}/claims", ScopeOrganizationsWrite,
			s.putProviderClaims)

		// RADIUS devices (radius.go), whose shared secrets are sealed with the
		// root key.
		route("GET /admin/organizations/{orgID}/radius-clients", ScopeConfigRead, s.listRADIUSClients)
		route("POST /admin/organizations/{orgID}/radius-clients", ScopeOrganizationsWrite, s.addRADIUSClient)
		route("PATCH /admin/organizations/{orgID}/radius-clients/{deviceID}", ScopeOrganizationsWrite,
			s.patchRADIUSClient)

		// Directory sources (directories.go), whose credentials are sealed
		// with the root key.
		route("GET /admin/organizations/{orgID}/directories", ScopeConfigRead, s.listDirectories)
		route("POST /admin/organizations/{orgID}/directories", ScopeOrganizationsWrite, s.addDirectory)
		route("PATCH /admin/organizations/{orgID}/directories/{slug}", ScopeOrganizationsWrite, s.patchDirectory)
		route("PUT /admin/organizations/{orgID}/directories/{slug}/group-map", ScopeOrganizationsWrite,
			s.mapDirectoryGroup)
		route("DELETE /admin/organizations/{orgID}/directories/{slug}/group-map", ScopeOrganizationsWrite,
			s.unmapDirectoryGroup)
		route("POST /admin/organizations/{orgID}/directories/{slug}/sync", ScopeOrganizationsWrite,
			s.syncDirectory)

		// Provisioning targets (scimtargets.go), whose tokens and credentials
		// are sealed with the root key.
		route("GET /admin/organizations/{orgID}/scim-targets", ScopeConfigRead, s.listSCIMTargets)
		route("POST /admin/organizations/{orgID}/scim-targets", ScopeOrganizationsWrite, s.addSCIMTarget)
		route("PATCH /admin/organizations/{orgID}/scim-targets/{slug}", ScopeOrganizationsWrite, s.patchSCIMTarget)
		route("PUT /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}", ScopeOrganizationsWrite,
			s.provisionSCIMGroup)
		route("DELETE /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}", ScopeOrganizationsWrite,
			s.deprovisionSCIMGroup)
		route("POST /admin/organizations/{orgID}/scim-targets/{slug}/sync", ScopeOrganizationsWrite,
			s.syncSCIMTarget)

		// Shared Signals streams (ssf.go), whose receiver tokens are sealed
		// with the root key.
		route("GET /admin/organizations/{orgID}/ssf-streams", ScopeClientsRead, s.listStreams)
		route("POST /admin/organizations/{orgID}/ssf-streams", ScopeClientsWrite, s.addStream)

		// Remote-access connections (rac.go), whose credentials are sealed
		// with the root key.
		route("GET /admin/organizations/{orgID}/rac-connections", ScopeConfigRead, s.listRAC)
		route("POST /admin/organizations/{orgID}/rac-connections", ScopeOrganizationsWrite, s.addRAC)
		route("PATCH /admin/organizations/{orgID}/rac-connections/{slug}", ScopeOrganizationsWrite, s.patchRAC)

		// An instance's signing keys (keys.go), under the root key their
		// private halves are sealed with; deployment-wide tokens only.
		route("GET /admin/instances/{instanceID}/keys", ScopeConfigRead, s.listSigningKeys)
		route("POST /admin/instances/{instanceID}/keys/rotate", ScopeOrganizationsWrite, s.rotateSigningKeys)
		route("POST /admin/instances/{instanceID}/keys/retire", ScopeOrganizationsWrite, s.retireSigningKeys)

		// OpenID Federation and Trust Marks (federation.go), signed with the
		// instance's federation key, which is sealed with the root key;
		// deployment-wide tokens only.
		route("GET /admin/instances/{instanceID}/federation", ScopeConfigRead, s.getFederation)
		route("PUT /admin/instances/{instanceID}/federation", ScopeOrganizationsWrite, s.putFederation)
		route("GET /admin/instances/{instanceID}/trust-marks", ScopeConfigRead, s.listTrustMarks)
		route("POST /admin/instances/{instanceID}/trust-marks", ScopeOrganizationsWrite, s.issueTrustMark)
		route("POST /admin/instances/{instanceID}/trust-marks/revoke", ScopeOrganizationsWrite, s.revokeTrustMark)
		route("PUT /admin/instances/{instanceID}/held-trust-marks", ScopeOrganizationsWrite, s.acceptTrustMark)
		route("DELETE /admin/instances/{instanceID}/held-trust-marks", ScopeOrganizationsWrite, s.dropTrustMark)
		route("POST /admin/instances/{instanceID}/trust-mark-delegations", ScopeOrganizationsWrite,
			s.delegateTrustMark)

		// Duo as a second factor (duo.go), under the root key its secret is
		// sealed with.
		route("GET /admin/organizations/{orgID}/duo", ScopeConfigRead, s.getDuo)
		route("PUT /admin/organizations/{orgID}/duo", ScopeOrganizationsWrite, s.putDuo)
		privileged("PUT /admin/users/{userID}/duo", ScopeUsersWrite, targetUser, s.enrollDuo)
	}

	// The document itself, unauthenticated. See handleOpenAPI for why: it
	// describes the shape of the API and no data, and the same facts are already
	// public in docs/admin-api.md.
	handle("GET /admin/openapi.json", s.handleOpenAPI)
	route("GET /admin/system", ScopeConfigRead, s.getSystem)
	// No scope of its own: each operation it carries is held to its own
	// (batch.go).
	route("POST /admin/batch", "", s.handleBatch)
	s.mux.Store(mux)

	var inner http.Handler = mux
	if s.metrics != nil {
		// Innermost, next to the mux, which is the only place the matched
		// pattern is known (see the same choice in httpapi.Routes).
		inner = s.metrics.Middleware(mux)
	}
	return s.limitArrivals(versioned(inner))
}

// versioned serves /admin/v1/... as /admin/..., one route table under both
// (6.08). The version is in the path so a caller can pin it: this API is v1,
// a change that breaks a caller would come as /admin/v2 beside it, and
// /admin/... stays v1's. Rewritten before the router rather than registered
// twice, so the OpenAPI document and the route guards see each route once.
func versioned(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(r.URL.Path, "/admin/v1/"); ok {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/admin/" + rest
			if r.URL.RawPath != "" {
				if raw, ok := strings.CutPrefix(r.URL.RawPath, "/admin/v1/"); ok {
					r2.URL.RawPath = "/admin/" + raw
				}
			}
			next.ServeHTTP(w, r2)
			return
		}
		next.ServeHTTP(w, r)
	})
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
		if errors.Is(err, errMultiFactorRequired) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "multi_factor_required",
				"detail": "administration needs a session that proved a second factor; sign in again with one"})
			return
		}
		if errors.Is(err, errOrgSuspended) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "organisation_suspended",
				"detail": "this token's organisation is suspended; a deployment-wide token can reactivate it"})
			return
		}
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
		// An operation inside a batch was counted with its batch.
		_, batched := inBatch(r.Context())
		if s.perToken != nil && !batched && !s.perToken.Allow(p.Name) {
			s.log.Info("admin request throttled", "token", p.Name,
				"method", r.Method, "path", r.URL.Path)
			tooManyRequests(w)
			return
		}

		// Authenticated but not permitted is 403, and says which scope was
		// missing. This is an operator-facing API: "forbidden" with no detail
		// turns a one-line fix into an afternoon. No scope is the batch, whose
		// operations are each held to their own.
		if scope != "" && !p.Can(scope) {
			s.log.Info("admin request refused: missing scope", "token", p.Name,
				"required", scope, "held", p.Scopes)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "insufficient_scope",
				"detail": "this token does not hold " + scope,
			})
			return
		}

		// A role delegated over groups reaches only their members (6.01): every
		// route naming a person in its path is held to it here, so none can be
		// registered without it. Handlers finding their person another way
		// apply it themselves (TestEveryRouteOnAPersonIsHeldToADelegatedReach).
		for _, name := range []string{"userID", "subjectID"} {
			id := r.PathValue(name)
			if id == "" {
				continue
			}
			if err := requireReach(r.Context(), s.db, p, scope, id); err != nil {
				if errors.Is(err, errCrossOrg) {
					writeCrossOrg(w, err)
					return
				}
				s.log.Error("checking a delegated role's reach", "err", err)
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
				return
			}
		}

		if p.BreakGlass {
			// Logged every single time. A credential that bypasses revocation and
			// expiry should never be quietly interchangeable with the others.
			s.log.Warn("admin request used the break-glass environment token",
				"method", r.Method, "path", r.URL.Path)
		}
		s.touch(p.TokenID)
		// A read is tagged with the version as it was BEFORE the handler reads
		// anything, so a change that commits while the rows are read moves the
		// version past the tag, and a write sent back with it is refused. Read
		// after the rows, as writeList did until October 2026, a change landing
		// between the two was tagged as seen and the write made over it.
		if r.Method == http.MethodGet {
			var v int64
			if err := s.db.QueryRow(r.Context(),
				`SELECT version FROM core.config_version`).Scan(&v); err == nil {
				setETag(w, v)
			}
		}
		// Who the caller acts for, written onto every audit record this request
		// makes, with whether it came through the break-glass token (6.05).
		operator := r.Header.Get(OperatorHeader)
		if operator != "" && !operatorPattern.MatchString(operator) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_operator",
				"detail": OperatorHeader + " is the caller's own reference for the person it acts for, " +
					"1-128 of A-Z a-z 0-9 . _ : -, such as console-user:42; never an address, since " +
					"it is kept in the audit trail, which nothing erases"})
			return
		}
		// A role principal is named on the record by who it is (6.01): the
		// person as the actor, and either kind as the principal, since it has no
		// admin token for admin_token_id to name.
		actor := audit.Actor{BreakGlass: p.BreakGlass, Operator: operator, UserID: p.UserID}
		if p.TokenID == "" && !p.BreakGlass {
			actor.Principal = p.Name
		}
		ctx := audit.WithActor(withPrincipal(r.Context(), p), actor)
		next(w, r.WithContext(ctx))
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
	// Token lifetimes in seconds, the columns' own units, through
	// store.SetClientSettings as the CLI and `apply` write them.
	AccessTokenTTLSeconds  *int `json:"access_token_ttl_s"`
	RefreshTokenTTLSeconds *int `json:"refresh_token_ttl_s"`
	// IDTokenSignedResponseAlg, by its dynamic-registration name, signs the
	// client's ID and access tokens.
	IDTokenSignedResponseAlg *string `json:"id_token_signed_response_alg"`
	// RequirePushedAuthorizationRequests is RFC 9126 §6's name; FirstParty
	// skips the consent screen.
	RequirePushedAuthorizationRequests *bool `json:"require_pushed_authorization_requests"`
	FirstParty                         *bool `json:"first_party"`
	// AdminAPI designates the client for the Admin API (6.01): it may obtain
	// tokens that act with their holder's roles. Needs privileged-users:write,
	// as every later write on such a client does (targetClient).
	AdminAPI *bool `json:"admin_api"`
	// IssuerAlias pins the client to a live alias of its instance; "" clears.
	IssuerAlias *string `json:"issuer_alias"`
	// MinimumACR is the weakest authentication the client accepts, "1" to "4".
	MinimumACR *string `json:"minimum_acr"`
	// ConsentLifetimeSeconds is how long a person's consent to the client lasts
	// before they are asked again; 0 for never (0188).
	ConsentLifetimeSeconds *int `json:"consent_lifetime_s"`

	// The settings the CLI's `client set-*` verbs write, through the same
	// store writers, so the two refuse alike (6.03). Each by its column name,
	// as GET returns it; each left alone when absent.
	GrantTypes                            *[]string `json:"grant_types"`
	BackchannelTokenDeliveryMode          *string   `json:"backchannel_token_delivery_mode"`
	BackchannelClientNotificationEndpoint *string   `json:"backchannel_client_notification_endpoint"`
	AllowHybrid                           *bool     `json:"allow_hybrid"`
	HybridReviewBy                        *string   `json:"hybrid_review_by"`
	ClaimsRedirectURIs                    *[]string `json:"claims_redirect_uris"`
	DPoPBoundAccessTokens                 *bool     `json:"dpop_bound_access_tokens"`
	ExchangeRequiresAudienceMatch         *bool     `json:"exchange_requires_audience_match"`
	JWTBearerProviders                    *[]string `json:"jwt_bearer_providers"`

	// AuthorizationDetailTypes replaces the RFC 9396 types the client may ask
	// for, each its organisation registered, as `signari rar allow` adds one.
	AuthorizationDetailTypes *[]string `json:"authorization_detail_types"`

	// What only `signari apply` or nothing set: the name, the redirect URIs,
	// the scopes, the portal fields and the back channel (6.03).
	DisplayName                      *string   `json:"display_name"`
	RedirectURIs                     *[]string `json:"redirect_uris"`
	Scopes                           *[]string `json:"scopes"`
	InitiateLoginURI                 *string   `json:"initiate_login_uri"`
	LogoURI                          *string   `json:"logo_uri"`
	PortalHidden                     *bool     `json:"portal_hidden"`
	BackchannelLogoutURI             *string   `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired *bool     `json:"backchannel_logout_session_required"`
	// The key set moves the client to private_key_jwt and drops its secret,
	// as `client set-keys` does.
	JWKS *json.RawMessage `json:"jwks"`
	// Mutual TLS, as `client set-tls`: any rule field replaces the rule, and
	// exactly one must then be set; tls_certificate is a self-signed client's
	// PEM certificate, kept as its thumbprint.
	TLSSubjectDN   *string `json:"tls_subject_dn"`
	TLSSANDNS      *string `json:"tls_san_dns"`
	TLSSANURI      *string `json:"tls_san_uri"`
	TLSSANIP       *string `json:"tls_san_ip"`
	TLSSANEmail    *string `json:"tls_san_email"`
	TLSCertificate *string `json:"tls_certificate"`
	TLSBoundTokens *bool   `json:"tls_bound_tokens"`
}

func (req patchClientRequest) setsTLSRule() bool {
	return req.TLSSubjectDN != nil || req.TLSSANDNS != nil || req.TLSSANURI != nil ||
		req.TLSSANIP != nil || req.TLSSANEmail != nil || req.TLSCertificate != nil
}

// applyTLS replaces the mutual-TLS rule when one is sent, keeping the current
// one when only tls_bound_tokens is.
func (req patchClientRequest) applyTLS(ctx context.Context, tx pgx.Tx, clientID string, before map[string]any) error {
	str := func(k string) string { v, _ := before[k].(string); return v }
	t := store.ClientTLS{SubjectDN: str("tls_subject_dn"), SANDNS: str("tls_san_dns"), SANURI: str("tls_san_uri"),
		SANIP: str("tls_san_ip"), SANEmail: str("tls_san_email")}
	if th := strings.TrimPrefix(str("tls_thumbprint"), `\x`); th != "" {
		t.Thumbprint, _ = hex.DecodeString(th)
	}
	t.BoundTokens, _ = before["tls_bound_tokens"].(bool)
	if req.setsTLSRule() {
		t = store.ClientTLS{BoundTokens: t.BoundTokens}
		for dst, src := range map[*string]*string{&t.SubjectDN: req.TLSSubjectDN, &t.SANDNS: req.TLSSANDNS,
			&t.SANURI: req.TLSSANURI, &t.SANIP: req.TLSSANIP, &t.SANEmail: req.TLSSANEmail} {
			if src != nil {
				*dst = strings.TrimSpace(*src)
			}
		}
		if req.TLSCertificate != nil && strings.TrimSpace(*req.TLSCertificate) != "" {
			th, err := store.CertificateThumbprint([]byte(*req.TLSCertificate))
			if err != nil {
				return err
			}
			t.Thumbprint = th
		}
	}
	if req.TLSBoundTokens != nil {
		t.BoundTokens = *req.TLSBoundTokens
	}
	return store.SetClientTLS(ctx, tx, clientID, t)
}

// setsShared reports whether the request sets any of the settings the CLI's
// verbs share.
func (req patchClientRequest) setsShared() bool {
	return req.GrantTypes != nil || req.BackchannelTokenDeliveryMode != nil ||
		req.BackchannelClientNotificationEndpoint != nil || req.AllowHybrid != nil ||
		req.HybridReviewBy != nil || req.ClaimsRedirectURIs != nil || req.DPoPBoundAccessTokens != nil ||
		req.ExchangeRequiresAudienceMatch != nil || req.JWTBearerProviders != nil ||
		req.DisplayName != nil || req.RedirectURIs != nil || req.Scopes != nil ||
		req.InitiateLoginURI != nil || req.LogoURI != nil || req.PortalHidden != nil ||
		req.JWKS != nil || req.setsTLSRule() || req.TLSBoundTokens != nil ||
		req.AuthorizationDetailTypes != nil
}

// applySharedSettings writes what the request sets of the settings the CLI's
// verbs share, holding each unset half of a pair at what it was.
func (req patchClientRequest) applySharedSettings(ctx context.Context, tx pgx.Tx, clientID string,
	before map[string]any) error {
	if req.GrantTypes != nil {
		if err := store.SetClientGrants(ctx, tx, clientID, *req.GrantTypes); err != nil {
			return err
		}
	}
	if req.BackchannelTokenDeliveryMode != nil || req.BackchannelClientNotificationEndpoint != nil {
		mode, _ := before["backchannel_token_delivery_mode"].(string)
		endpoint, _ := before["backchannel_client_notification_endpoint"].(string)
		if req.BackchannelTokenDeliveryMode != nil {
			mode = *req.BackchannelTokenDeliveryMode
		}
		if req.BackchannelClientNotificationEndpoint != nil {
			endpoint = *req.BackchannelClientNotificationEndpoint
		}
		if err := store.SetClientCIBA(ctx, tx, clientID, mode, endpoint); err != nil {
			return err
		}
	}
	if req.AllowHybrid != nil || req.HybridReviewBy != nil {
		allow, _ := before["allow_hybrid"].(bool)
		review, _ := before["hybrid_review_by"].(string)
		if req.AllowHybrid != nil {
			allow = *req.AllowHybrid
		}
		if req.HybridReviewBy != nil {
			review = *req.HybridReviewBy
		}
		if err := store.SetClientHybrid(ctx, tx, clientID, allow, review); err != nil {
			return err
		}
	}
	if req.ClaimsRedirectURIs != nil {
		if err := store.SetClientClaimsRedirects(ctx, tx, clientID, *req.ClaimsRedirectURIs); err != nil {
			return err
		}
	}
	if req.DPoPBoundAccessTokens != nil {
		if err := store.SetClientDPoP(ctx, tx, clientID, *req.DPoPBoundAccessTokens); err != nil {
			return err
		}
	}
	if req.ExchangeRequiresAudienceMatch != nil {
		if err := store.SetClientExchangeContainment(ctx, tx, clientID, *req.ExchangeRequiresAudienceMatch); err != nil {
			return err
		}
	}
	if req.JWTBearerProviders != nil {
		if _, err := store.SetClientAssertionIssuers(ctx, tx, clientID, *req.JWTBearerProviders); err != nil {
			return err
		}
	}
	if req.DisplayName != nil {
		if err := store.SetClientDisplayName(ctx, tx, clientID, *req.DisplayName); err != nil {
			return err
		}
	}
	if req.RedirectURIs != nil {
		if err := store.SetClientRedirectURIs(ctx, tx, clientID, *req.RedirectURIs); err != nil {
			return err
		}
	}
	if req.Scopes != nil {
		if err := store.SetClientScopes(ctx, tx, clientID, *req.Scopes); err != nil {
			return err
		}
	}
	if req.InitiateLoginURI != nil || req.LogoURI != nil || req.PortalHidden != nil {
		if err := store.SetClientPortal(ctx, tx, clientID, store.ClientPortal{
			LaunchURL: req.InitiateLoginURI, LogoURL: req.LogoURI, Hidden: req.PortalHidden}); err != nil {
			return err
		}
	}
	if req.JWKS != nil {
		if _, err := store.SetClientKeys(ctx, tx, clientID, *req.JWKS); err != nil {
			return err
		}
	}
	if req.AuthorizationDetailTypes != nil {
		if err := store.SetClientDetailTypes(ctx, tx, clientID, *req.AuthorizationDetailTypes); err != nil {
			return err
		}
	}
	if req.setsTLSRule() || req.TLSBoundTokens != nil {
		if err := req.applyTLS(ctx, tx, clientID, before); err != nil {
			return err
		}
	}
	return nil
}

func (r patchClientRequest) setsLogout() bool {
	return r.PostLogoutRedirectURIs != nil || r.FrontchannelLogoutURI != nil || r.FrontchannelSessionRequired != nil ||
		r.BackchannelLogoutURI != nil || r.BackchannelLogoutSessionRequired != nil
}

// settings is the request's part for store.SetClientSettings, and whether it
// has one.
func (r patchClientRequest) settings() (store.ClientSettings, bool) {
	var s store.ClientSettings
	if r.AccessTokenTTLSeconds != nil {
		d := time.Duration(*r.AccessTokenTTLSeconds) * time.Second
		s.AccessTokenTTL = &d
	}
	if r.RefreshTokenTTLSeconds != nil {
		d := time.Duration(*r.RefreshTokenTTLSeconds) * time.Second
		s.RefreshTokenTTL = &d
	}
	s.IDTokenAlg = r.IDTokenSignedResponseAlg
	s.RequirePAR, s.FirstParty, s.IssuerAlias = r.RequirePushedAuthorizationRequests, r.FirstParty, r.IssuerAlias
	s.MinimumACR = r.MinimumACR
	if r.ConsentLifetimeSeconds != nil {
		d := time.Duration(*r.ConsentLifetimeSeconds) * time.Second
		s.ConsentLifetime = &d
	}
	return s, r.AccessTokenTTLSeconds != nil || r.RefreshTokenTTLSeconds != nil ||
		r.IDTokenSignedResponseAlg != nil || r.RequirePushedAuthorizationRequests != nil ||
		r.FirstParty != nil || r.IssuerAlias != nil || r.MinimumACR != nil || r.ConsentLifetimeSeconds != nil
}

func (s *Server) patchClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	var req patchClientRequest
	// A field this cannot set is refused by name rather than dropped. Dropped,
	// a caller sending the name or redirect URIs before 6.03, or a typo, got
	// 200 with nothing written, which is how the Terraform provider came to
	// replace a client rather than update it.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	settings, setsSettings := req.settings()
	if req.Enabled == nil && req.RequirePKCE == nil && req.MayExchange == nil && req.ExchangeAudiences == nil &&
		req.AdminAPI == nil && !req.setsLogout() && !setsSettings && !req.setsShared() {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "nothing_to_change", "detail": "no supported field present",
		})
		return
	}
	if p, _ := principalFrom(ctx); req.AdminAPI != nil && !p.Can(ScopePrivilegedUsersWrite) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "privileged_target",
			"detail": "designating an application for the Admin API makes it where administrators sign in; " +
				"it needs " + ScopePrivilegedUsersWrite})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var enabled, requirePKCE, mayExchange bool
	var exchangeAudiences []string
	var logout, lifetimes map[string]any
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
		// What the client was, for the record's before-and-after (6.05).
		before, err := clientState(ctx, tx, clientID)
		if err != nil {
			return err
		}

		err = tx.QueryRow(ctx, `
			UPDATE core.clients
			   SET enabled = COALESCE($2, enabled),
			       require_pkce = COALESCE($3, require_pkce),
			       admin_api = COALESCE($4, admin_api),
			       updated_at = now()
			 WHERE client_id = $1
			RETURNING enabled, require_pkce`,
			clientID, req.Enabled, req.RequirePKCE, req.AdminAPI).Scan(&enabled, &requirePKCE)
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
				FrontchannelSessionRequired: req.FrontchannelSessionRequired, BackchannelURI: req.BackchannelLogoutURI,
				BackchannelSessionRequired: req.BackchannelLogoutSessionRequired,
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
		if setsSettings {
			if err := store.SetClientSettings(ctx, tx, clientID, settings); err != nil {
				return err
			}
			got, err := store.ClientSettingsOf(ctx, tx, clientID)
			if err != nil {
				return err
			}
			lifetimes = map[string]any{
				"access_token_ttl_s":                    int(got.AccessTokenTTL.Seconds()),
				"refresh_token_ttl_s":                   int(got.RefreshTokenTTL.Seconds()),
				"id_token_signed_response_alg":          got.IDTokenAlg,
				"require_pushed_authorization_requests": got.RequirePAR,
				"first_party":                           got.FirstParty,
				"issuer_alias":                          got.IssuerAlias,
				"minimum_acr":                           got.MinimumACR,
				"consent_lifetime_s":                    int(got.ConsentLifetime.Seconds()),
			}
			for k, v := range lifetimes {
				detail[k] = v
			}
		}
		if err := req.applySharedSettings(ctx, tx, clientID, before); err != nil {
			return err
		}
		after, err := clientState(ctx, tx, clientID)
		if err != nil {
			return err
		}
		detail["changes"] = stateChanges(before, after, clientValueless)
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
	case errors.Is(err, store.ErrInvalidClientSetting):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_setting", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrInvalidDetailType):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_authorization_details_type",
			"detail": err.Error()})
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
	for k, v := range lifetimes {
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

// writeOrgRefusal answers a refusal from requireNamedOrg, or from requireOrg,
// and reports whether err was one.
func writeOrgRefusal(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
	case errors.Is(err, errUnknownOrg):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "organization_not_found", "detail": err.Error(),
		})
	case errors.Is(err, errMalformedOrg):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "detail": err.Error(),
		})
	default:
		return false
	}
	return true
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
	// Inside a batch (batch.go), into the batch's transaction: it holds the
	// version lock and checked the batch's precondition, and bumps and commits
	// once, after every operation has written.
	if b, ok := inBatch(ctx); ok {
		if err := fn(b.tx); err != nil {
			return 0, err
		}
		b.wrote = true
		return b.version, nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The version row first, conditional or not, before fn can take another
	// lock (store.LockConfigVersion). An unconditional write here took the
	// audit chain's lock inside fn and the row at the end, and a CLI command
	// and this API, run together, deadlocked (4.25).
	if err := store.LockConfigVersion(ctx, tx); err != nil {
		return 0, err
	}

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
