package adminapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// The OpenAPI document, derived from the router.
//
// # Why derived rather than written
//
// A hand-written API document is a second description of the same facts, and
// two descriptions of one fact drift. `docs/cli.md` once listed eight commands
// that had never existed, which is why `internal/docsync` derives that list from
// the dispatch instead — and this is the same principle applied to the surface
// with the most consumers.
//
// The consequence worth stating: this document cannot describe a route that is
// not registered, and cannot omit one that is. A generated client built from it
// is therefore a client of the server that exists, rather than of the server
// somebody last remembered to document.
//
// # What it derives, and what it cannot
//
// From the router: the path, the method, and — because every handler is wrapped
// by `auth(scope, ...)` — the SCOPE each operation requires. That last one is
// the part a hand-written document gets wrong most often and the part an
// integrator most needs, since a 403 naming a scope is only useful if you can
// find out which scope an operation wanted before you call it.
//
// Request and response schemas come from openapischema.go (6.02): requests
// reflected from the type each handler decodes, responses declared and held to
// what the handlers send by TestEveryResponseMatchesItsSchema. This said they
// were not derived, since reflection describes JSON tags rather than meaning;
// the meaning stays in the summaries here and in `docs/admin-api.md`, which
// `TestEveryAdminAPIRouteIsDocumented` keeps aligned with the same route table,
// and the schemas give a generated client the shapes, which it had none of.

// operation is one method on one path.
type operation struct {
	method  string
	path    string
	scope   string
	summary string
	// privileged marks a write that also needs privileged-users:write when
	// its target may impersonate (see privileged.go).
	privileged bool
}

// recordOperation notes a route as Routes() registers it.
func (s *Server) recordOperation(pattern, scope string) {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return
	}
	s.ops = append(s.ops, operation{
		method: strings.ToLower(method), path: path,
		scope: scope, summary: summaries[pattern],
	})
}

// summaries describes each operation in one line.
//
// Keyed by the route pattern, so a route with no entry is visible: the document
// gets an empty summary and `TestEveryOperationHasASummary` fails. That is
// deliberately noisier than defaulting to the path, which would look complete.
var summaries = map[string]string{
	"GET /admin/config-version":                              "The current configuration version, for conditional writes.",
	"GET /admin/clients":                                     "List clients.",
	"GET /admin/clients/{clientID}":                          "One client.",
	"POST /admin/clients":                                    "Register a client.",
	"PATCH /admin/clients/{clientID}":                        "Enable or disable a client, or opt it out of PKCE.",
	"DELETE /admin/clients/{clientID}":                       "Remove a client and everything issued under it.",
	"POST /admin/clients/{clientID}/rotate-secret":           "Issue a new client secret, shown once.",
	"GET /admin/users":                                       "List users.",
	"GET /admin/users/{userID}":                              "One user.",
	"POST /admin/users":                                      "Create a user.",
	"PATCH /admin/users/{userID}":                            "Update a user's status, password or identity fields.",
	"DELETE /admin/users/{userID}":                           "Remove a user, ending their sessions first.",
	"GET /admin/users/{userID}/factors":                      "What the user can authenticate with. No secret material.",
	"DELETE /admin/users/{userID}/factors/{kind}":            "Remove a factor the user holds one of.",
	"DELETE /admin/users/{userID}/factors/{kind}/{factorID}": "Remove one of several factors.",
	"DELETE /admin/users/{userID}/throttle":                  "Clear the sign-in delay and the budgets wrong guesses charged to the user.",
	"POST /admin/users/{userID}/passkey-link":                "Email the user a single-use link to register a passkey. The token is never returned.",
	"GET /admin/invitations":                                 "Invitations, with whether each is open, used, revoked or expired.",
	"POST /admin/invitations":                                "Invite somebody to create an account: the link once, or mailed to the bound address with send.",
	"DELETE /admin/invitations/{invitationID}":               "Revoke an open invitation.",
	"GET /admin/users/{userID}/sessions":                     "A user's live sessions.",
	"DELETE /admin/users/{userID}/sessions":                  "End all of a user's sessions.",
	"DELETE /admin/sessions/{sid}":                           "End one session.",
	"GET /admin/groups":                                      "List groups.",
	"GET /admin/groups/{groupID}":                            "One group.",
	"POST /admin/groups":                                     "Create a group.",
	"PATCH /admin/groups/{groupID}":                          "Rename a group or change its description.",
	"DELETE /admin/groups/{groupID}":                         "Delete a group and its memberships.",
	"GET /admin/groups/{groupID}/members":                    "List a group's members.",
	"PUT /admin/groups/{groupID}/members/{userID}":           "Add a member.",
	"DELETE /admin/groups/{groupID}/members/{userID}":        "Remove a member.",
	"GET /admin/system":                                      "The release, schema and size of the deployment. Requires an unscoped token.",
	"POST /admin/batch":                                      "Up to 100 writes in one transaction, all or none, one version bump.",
	"GET /admin/users/{userID}/consents":                     "The applications a person consented to or that hold a grant.",
	"DELETE /admin/users/{userID}/consents/{clientID}":       "Withdraw a consent and revoke the application's refresh grants.",
	"GET /admin/tokens":                                      "The admin tokens this token may see; never a secret or hash.",
	"POST /admin/tokens":                                     "Mint an admin token no wider than the caller. The secret is returned once.",
	"POST /admin/tokens/{tokenID}/rotate":                    "Replace a token's secret, the old one working for a grace period.",
	"DELETE /admin/tokens/{tokenID}":                         "Revoke an admin token no wider than the caller.",
	"POST /admin/organizations":                              "Provision a tenant. Requires an unscoped token.",
	"GET /admin/organizations":                               "The organisations this token may see, with their status.",
	"GET /admin/organizations/{orgID}":                       "One organisation and its status.",
	"PATCH /admin/organizations/{orgID}":                     "Suspend or reactivate a tenant. Requires an unscoped token.",
	"POST /admin/subjects/{subjectID}/erase":                 "Crypto-shred a subject. Permanent.",
	"GET /admin/subjects/{subjectID}/export":                 "Everything kept about a person, credentials withheld.",
	"GET /admin/audit-events":                                "Read the audit trail. Does not verify the hash chain.",

	// Thirteen operations shipped with no line here and the document said
	// nothing about them, because the test that requires one never built the
	// router it was reading.
	"GET /admin/organizations/{orgID}/scopes":                      "The organisation's declared scopes, plus the standard set.",
	"PUT /admin/organizations/{orgID}/scopes":                      "Declare or update a scope.",
	"GET /admin/organizations/{orgID}/webauthn-policy":             "Read the organisation's authenticator policy.",
	"PUT /admin/organizations/{orgID}/webauthn-policy":             "Set attestation, approved models and cloned-authenticator refusal.",
	"DELETE /admin/organizations/{orgID}/scopes/{scope}":           "Remove a scope declaration.",
	"GET /admin/organizations/{orgID}/proxy-hosts":                 "The applications forward auth protects.",
	"PUT /admin/organizations/{orgID}/proxy-hosts":                 "Register a protected host, or enable or disable one.",
	"DELETE /admin/organizations/{orgID}/proxy-hosts/{host}":       "Remove a protected host.",
	"GET /admin/organizations/{orgID}/migration-source":            "The provider this organisation is migrating off, and how the cutover is going.",
	"PUT /admin/organizations/{orgID}/migration-source":            "Configure the old directory or provider that verifies a migrating person's password.",
	"DELETE /admin/organizations/{orgID}/migration-source":         "Remove the migration source.",
	"GET /admin/organizations/{orgID}/resource-servers":            "The RFC 8707 resources this organisation's tokens may be audienced to.",
	"PUT /admin/organizations/{orgID}/resource-servers":            "Register a resource server, or rename one.",
	"DELETE /admin/organizations/{orgID}/resource-servers":         "Withdraw a resource server; tokens for it are refused from the next request.",
	"GET /admin/organizations/{orgID}/attributes":                  "The organisation's user attribute declarations.",
	"PUT /admin/organizations/{orgID}/attributes":                  "Declare or update a user attribute.",
	"GET /admin/users/{userID}/attributes":                         "One user's attribute values.",
	"PUT /admin/users/{userID}/attributes":                         "Set a user's attribute values.",
	"GET /admin/organizations/{orgID}/claim-mappers":               "Every attribute this organisation releases as a claim.",
	"POST /admin/organizations/{orgID}/claim-mappers":              "Release an attribute as a claim.",
	"DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}": "Stop releasing an attribute as a claim.",

	"GET /admin/me": "Who the caller is, as this request was authenticated: kind, organisation, scopes and any delegation.",
	"GET /admin/organizations/{orgID}/budgets": "The tokens and sign-ins the organisation may take a minute.",
	"PUT /admin/organizations/{orgID}/budgets": "Set the organisation's budgets; deployment-wide tokens only.",

	// Self-sign-up (6.07).
	"GET /admin/organizations/{orgID}/signup":    "Whether people may make their own accounts, from which addresses, and into which groups.",
	"PUT /admin/organizations/{orgID}/signup":    "Open self-sign-up or replace its rule.",
	"DELETE /admin/organizations/{orgID}/signup": "Close self-sign-up; invitations and administrators still make accounts.",

	// Instances and their appearance (6.07).
	"GET /admin/instances":                       "The issuers this deployment has; deployment-wide tokens only.",
	"GET /admin/instances/{instanceID}/brand":    "The instance's name, logo, support link and colours.",
	"PUT /admin/instances/{instanceID}/brand":    "Brand the instance's pages, checked for contrast.",
	"DELETE /admin/instances/{instanceID}/brand": "Return the instance's pages to the built-in appearance.",

	"GET /admin/instances/{instanceID}/webauthn":         "The Relying Party ID the instance's passkeys are bound to, and its related origins.",
	"PUT /admin/instances/{instanceID}/webauthn":         "Set the RP ID, its name and related origins; changing a set RP ID must be confirmed.",
	"GET /admin/instances/{instanceID}/issuer-aliases":   "Legacy issuers the instance also claims, and who is pinned to each.",
	"POST /admin/instances/{instanceID}/issuer-aliases":  "Claim a legacy issuer while relying parties move across.",
	"PATCH /admin/instances/{instanceID}/issuer-aliases": "Retire an alias, now unless told when.",

	// Event subscriptions (6.07).
	"GET /admin/organizations/{orgID}/event-subscriptions":                       "Where the organisation's events are delivered, and how the deliveries are going.",
	"POST /admin/organizations/{orgID}/event-subscriptions":                      "Subscribe a URL to events; its signing secret is shown once.",
	"DELETE /admin/organizations/{orgID}/event-subscriptions/{name}":             "Remove a subscription; nothing more is delivered to it.",
	"POST /admin/organizations/{orgID}/event-subscriptions/{name}/rotate-secret": "Replace a subscription's signing secret, shown once.",
	"POST /admin/organizations/{orgID}/event-subscriptions/{name}/enable":        "Switch a subscription back on after it was given up on.",
	"POST /admin/organizations/{orgID}/event-subscriptions/{name}/test":          "Queue one signed test delivery to a subscription.",

	// An instance's signing keys (6.07).
	"GET /admin/instances/{instanceID}/keys":         "The instance's signing keys by id, algorithm and state; never a private half.",
	"POST /admin/instances/{instanceID}/keys/rotate": "Take the next safe step of rotation for each algorithm in use.",
	"POST /admin/instances/{instanceID}/keys/retire": "Retire the passive keys whose dwell is over.",

	// Duo as a second factor (6.07).
	"GET /admin/organizations/{orgID}/duo": "The organisation's Duo application, without its secret, and how many people are enrolled.",
	"PUT /admin/organizations/{orgID}/duo": "Configure Duo, checked against Duo before anything is stored.",
	"PUT /admin/users/{userID}/duo":        "Enrol a person in Duo by the username they have there.",

	// UMA resource-owner intervention (6.07).
	"GET /admin/organizations/{orgID}/uma":                               "Whether refused UMA requests wait for a resource owner, and how often clients poll.",
	"PUT /admin/organizations/{orgID}/uma":                               "Offer or stop offering resource-owner intervention.",
	"GET /admin/organizations/{orgID}/uma/requests":                      "The UMA requests waiting for a decision, with the relations that would let each through.",
	"POST /admin/organizations/{orgID}/uma/requests/{requestID}/approve": "Grant a relation that lets the whole request through, and approve it.",
	"POST /admin/organizations/{orgID}/uma/requests/{requestID}/deny":    "Close the request, granting nothing.",

	// Trusted Client Attesters (6.07).
	"GET /admin/organizations/{orgID}/attesters":           "The attesters whose client attestations the organisation accepts.",
	"PUT /admin/organizations/{orgID}/attesters/{name}":    "Trust an attester's public keys, or replace them.",
	"DELETE /admin/organizations/{orgID}/attesters/{name}": "Stop trusting an attester.",

	// RFC 9396 authorization details types (6.07).
	"GET /admin/organizations/{orgID}/authorization-detail-types":    "The authorization details types the organisation accepts, and which clients may ask for each.",
	"PUT /admin/organizations/{orgID}/authorization-detail-types":    "Register a type, or replace its fields.",
	"DELETE /admin/organizations/{orgID}/authorization-detail-types": "Forget a type, named by ?type=, and every client's leave to ask for it.",

	// Interstitial prompts (6.07).
	"GET /admin/organizations/{orgID}/prompts":          "The prompts asked between sign-in and the session, in order.",
	"PUT /admin/organizations/{orgID}/prompts/{slug}":   "Define or replace a prompt; a change to its wording asks everyone again.",
	"PATCH /admin/organizations/{orgID}/prompts/{slug}": "Enable or disable a prompt, keeping its answers.",

	// Dynamic client registration (6.07).
	"GET /admin/organizations/{orgID}/registration":                     "Whether /oauth2/register is on, open, and what it allows.",
	"PUT /admin/organizations/{orgID}/registration":                     "Turn dynamic registration on with this policy.",
	"DELETE /admin/organizations/{orgID}/registration":                  "Turn dynamic registration off, keeping its policy and tokens.",
	"GET /admin/organizations/{orgID}/registration-tokens":              "The organisation's initial access tokens, never their secrets.",
	"POST /admin/organizations/{orgID}/registration-tokens":             "Mint an initial access token, shown once.",
	"DELETE /admin/organizations/{orgID}/registration-tokens/{tokenID}": "Revoke an initial access token.",

	// Which groups an application is told of (6.07).
	"GET /admin/clients/{clientID}/group-release":    "Which groups the application is told of in the groups claim.",
	"PUT /admin/clients/{clientID}/group-release":    "Tell the application of these groups, or every group when none is named.",
	"DELETE /admin/clients/{clientID}/group-release": "Tell the application of no group.",

	// Its settings, the `instance` commands' (6.07).
	"GET /admin/organizations/{orgID}/settings":   "The organisation's sign-in and session policy.",
	"PATCH /admin/organizations/{orgID}/settings": "Change the settings named; the rest are left as they are.",

	// Administrative roles (6.01).
	"GET /admin/organizations/{orgID}/role-bindings":                "Who holds which administrative role in the organisation.",
	"POST /admin/organizations/{orgID}/role-bindings":               "Give a person or an application a role, a user manager optionally over one group's members.",
	"DELETE /admin/organizations/{orgID}/role-bindings/{bindingID}": "Take a role away; the holder's next request is refused what it gave.",
}

// OpenAPI renders the document.
func (s *Server) openAPI() map[string]any {
	ops := s.routeTable()

	paths := map[string]any{}
	for _, op := range ops {
		item, _ := paths[op.path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[op.path] = item
		}

		// Path parameters, taken from the pattern's own {braces} so they cannot
		// disagree with what the router will actually bind.
		var params []any
		for _, name := range pathParams(op.path) {
			params = append(params, map[string]any{
				"name": name, "in": "path", "required": true,
				"schema": map[string]any{"type": "string"},
			})
		}

		refusal := func(desc string) map[string]any {
			return map[string]any{"description": desc, "content": map[string]any{
				"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}}
		}
		sc := opSchemas[strings.ToUpper(op.method)+" "+op.path]
		status := sc.Status
		if status == 0 {
			status = http.StatusOK
		}
		success := map[string]any{"description": "Success."}
		if sc.Response != nil {
			success["content"] = map[string]any{"application/json": map[string]any{"schema": sc.Response}}
		}
		scopes, lacks := []any{op.scope}, "The token lacks "+op.scope+", or is scoped to another organisation."
		if op.scope == "" {
			// The batch: any token, each operation held to its own scope.
			scopes, lacks = []any{}, "An operation was refused; `failed_index` names which, and nothing was written."
		}
		entry := map[string]any{
			"summary":     op.summary,
			"operationId": operationID(op),
			"security":    []any{map[string]any{"bearerAuth": scopes}},
			"responses": map[string]any{
				strconv.Itoa(status): success,
				"400":                refusal("The request was refused; `error` names why."),
				"401":                refusal("No usable bearer token."),
				"403":                refusal(lacks),
			},
		}
		if sc.Request != nil {
			entry["requestBody"] = map[string]any{"required": true, "content": map[string]any{
				"application/json": map[string]any{"schema": requestSchema(sc.Request)}}}
		}
		if len(params) > 0 {
			entry["parameters"] = params
		}
		// Conditional writes. Advertised on every mutation because the
		// precondition is the feature worth knowing about, and a document that
		// omitted it would leave integrators writing the lost-update bug it
		// exists to prevent.
		if op.method != "get" {
			entry["parameters"] = append(params, map[string]any{
				"name": "If-Match", "in": "header", "required": false,
				"description": "RFC 7232 precondition. The write is refused with 412 " +
					"if the configuration moved since the ETag was read.",
				"schema": map[string]any{"type": "string"},
			})
			resp := entry["responses"].(map[string]any)
			resp["412"] = refusal("The configuration version moved; nothing was written. " +
				"`expected_version` and `current_version` name both.")
		}
		// The second scope is conditional on the target, so it cannot go in
		// `security`: listing it there would claim every call needs it.
		if op.privileged {
			entry["x-privileged-scope"] = ScopePrivilegedUsersWrite
			resp := entry["responses"].(map[string]any)
			resp["403"] = refusal("The token lacks " + op.scope +
				", or is scoped to another organisation, or the target may impersonate " +
				"others and the token lacks " + ScopePrivilegedUsersWrite + ".")
		}
		item[op.method] = entry
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title": "Signari Admin API",
			"description": "The engine's only write surface. Generated from the " +
				"router, so it cannot describe a route that does not exist or " +
				"omit one that does.",
			"version": "1",
		},
		"components": map[string]any{
			"schemas": map[string]any{"Error": errorSchema},
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type": "http", "scheme": "bearer",
					"description": "An admin token. The scope each operation " +
						"requires is listed in its security entry.",
				},
			},
		},
		"paths": paths,
	}
}

// pathParams extracts {names} from a route pattern.
func pathParams(path string) []string {
	var out []string
	for {
		open := strings.IndexByte(path, '{')
		if open < 0 {
			return out
		}
		close := strings.IndexByte(path[open:], '}')
		if close < 0 {
			return out
		}
		out = append(out, path[open+1:open+close])
		path = path[open+close:]
	}
}

// operationID builds a stable identifier for a generated client's method name.
func operationID(op operation) string {
	id := op.method
	for _, part := range strings.Split(strings.Trim(op.path, "/"), "/") {
		if part == "admin" {
			continue
		}
		part = strings.NewReplacer("{", "", "}", "", "-", "_").Replace(part)
		if part == "" {
			continue
		}
		id += "_" + part
	}
	return id
}

// handleOpenAPI serves the document.
//
// Unauthenticated, deliberately. It describes the SHAPE of the API and no data:
// paths, methods and which scope each needs. All of that is already in
// docs/admin-api.md, which is public. Requiring a token to read the description
// of how to use a token is the kind of gate that costs an integrator an hour and
// an attacker nothing -- the admin API's own address is not published, and
// hiding its route list is not what keeps it safe.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.openAPI()); err != nil {
		s.log.Error("rendering the OpenAPI document", "err", err)
	}
}

// routeTable returns every registered operation, sorted.
func (s *Server) routeTable() []operation {
	ops := make([]operation, len(s.ops))
	copy(ops, s.ops)
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].path != ops[j].path {
			return ops[i].path < ops[j].path
		}
		return ops[i].method < ops[j].method
	})
	return ops
}
