package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// Every mutating route must honour preconditions AND bump the configuration
// version. Neither is checkable by reading a handler, because both are
// omissions.
//
// This exists because both had already gone wrong in the same place. Before this
// change `POST /admin/subjects/{id}/erase` opened its own transaction and
// committed directly, so crypto-shredding a subject -- and, with
// `deactivate: true`, ending their account -- never bumped `core.config_version`.
// The package's own doc comment describes exactly that outcome: the write is
// durable and INVISIBLE, and running engine nodes keep serving the previous
// configuration until some unrelated write happens to move the version.
//
// It was the one handler not using the shared helper. Nothing failed, because
// nothing was looking. This is what looks.

// mutatingRoute is one route, with a body valid enough to reach the mutation.
//
// The bodies must be genuinely acceptable: the precondition is checked INSIDE
// mutateIf, which runs after request validation, so a route rejected at the body
// would report a false pass for both properties being tested.
type mutatingRoute struct {
	name   string
	method string
	// path is built per-run, because several need a fresh fixture.
	path func(t *testing.T, s *Server) string
	body func(t *testing.T, s *Server, path string) string
}

func allMutatingRoutes() []mutatingRoute {
	return []mutatingRoute{
		{
			name: "POST /admin/users", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/users" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"email":"drift-%d@example.test","org_id":%q}`,
					time.Now().UnixNano(), anyOrgID(t, s))
			},
		},
		{
			name: "PATCH /admin/users/{userID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return `{"active":false}` },
		},
		{
			// A fresh user each time: the route deletes what it is pointed at,
			// so reusing one would make the second assertion a 404 rather than
			// the precondition failure it is checking for.
			name: "DELETE /admin/users/{userID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// Keyed on the user, so no factor id in the path. The fixture
			// enrols TOTP first: the handler returns 404 when there was nothing
			// to remove, and a 404 would exempt this route from the very checks
			// the list exists to apply.
			name: "DELETE /admin/users/{userID}/factors/{kind}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUserWithTOTP(t, s) + "/factors/totp"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name:   "DELETE /admin/users/{userID}/factors/{kind}/{factorID}",
			method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				userID := newDriftUser(t, s)
				return "/admin/users/" + userID + "/factors/webauthn/" +
					newDriftPasskey(t, s, userID)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// Answered 200 with nothing to clear, so a fresh user exercises it.
			name: "DELETE /admin/users/{userID}/throttle", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s) + "/throttle"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// The fixture user is active with an address, so the link is issued.
			name: "POST /admin/users/{userID}/passkey-link", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s) + "/passkey-link"
			},
			body: func(*testing.T, *Server, string) string { return `{}` },
		},
		{
			name: "POST /admin/invitations", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/invitations" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"org_id":%q,"email":"drift-invite-%d@example.test"}`,
					anyOrgID(t, s), time.Now().UnixNano())
			},
		},
		{
			// A fresh open one each time: the route revokes what it is pointed
			// at, and a second revoke is a 404 rather than the precondition
			// failure being checked for.
			name: "DELETE /admin/invitations/{invitationID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/invitations/" + newDriftInvitation(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/users/{userID}/consents/{clientID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s) + "/consents/" + newPreconditionClient(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/batch", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/batch" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"operations":[{"method":"PATCH","path":"/admin/clients/%s","body":{"enabled":false}}]}`,
					newPreconditionClient(t, s))
			},
		},
		{
			name: "POST /admin/tokens", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/tokens" },
			body: func(t *testing.T, s *Server, _ string) string {
				name := fmt.Sprintf("drift-mint-%d", time.Now().UnixNano())
				t.Cleanup(func() {
					_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE name = $1`, name)
				})
				return fmt.Sprintf(`{"name":%q,"scopes":["config:read"]}`, name)
			},
		},
		{
			name: "POST /admin/tokens/{tokenID}/rotate", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/tokens/" + newDriftToken(t, s) + "/rotate"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/tokens/{tokenID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/tokens/" + newDriftToken(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/attributes", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + anyOrgID(t, s) + "/attributes"
			},
			body: func(*testing.T, *Server, string) string {
				// A fresh name each run: the declaration is upserted by name, and
				// a fixed one would exercise the update path only after the first
				// run, which is not the path this list is checking.
				return fmt.Sprintf(`{"name":"drift_attr_%d","personal":true}`,
					time.Now().UnixNano())
			},
		},
		{
			name: "PUT /admin/users/{userID}/attributes", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUserWithAttribute(t, s) + "/attributes"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"attributes":{"` + driftAttributeName + `":"a value"}}`
			},
		},
		{
			name:   "POST /admin/organizations/{orgID}/claim-mappers",
			method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + orgWithDriftAttribute(t, s) + "/claim-mappers"
			},
			body: func(*testing.T, *Server, string) string {
				// A fresh claim name so the upsert path is not the only one
				// exercised after the first run.
				return fmt.Sprintf(
					`{"attribute":%q,"claim_name":"drift_claim_%d","destination":"userinfo","all_clients":true}`,
					driftAttributeName, time.Now().UnixNano())
			},
		},
		{
			name:   "DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}",
			method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				orgID := orgWithDriftAttribute(t, s)
				return "/admin/organizations/" + orgID + "/claim-mappers/" +
					newDriftMapper(t, s, orgID)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/scopes", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + anyOrgID(t, s) + "/scopes"
			},
			body: func(*testing.T, *Server, string) string {
				return fmt.Sprintf(`{"name":"drift_scope_%d"}`, time.Now().UnixNano())
			},
		},
		{
			name:   "DELETE /admin/organizations/{orgID}/scopes/{scope}",
			method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				orgID := anyOrgID(t, s)
				return "/admin/organizations/" + orgID + "/scopes/" + newDriftScope(t, s, orgID)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/webauthn-policy", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + anyOrgID(t, s) + "/webauthn-policy"
			},
			// The organisation's own policy sent back, so exercising the route
			// changes nothing a test sharing this database relies on.
			body: func(t *testing.T, s *Server, _ string) string {
				p, err := store.LoadWebAuthnPolicy(context.Background(), s.db, anyOrgID(t, s))
				if err != nil {
					t.Fatal(err)
				}
				b, _ := json.Marshal(policyJSON(p))
				return string(b)
			},
		},
		{
			name: "PUT /admin/organizations/{orgID}/proxy-hosts", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + anyOrgID(t, s) + "/proxy-hosts"
			},
			body: func(*testing.T, *Server, string) string {
				return fmt.Sprintf(`{"host":"drift-%d.example.com"}`, time.Now().UnixNano())
			},
		},
		{
			// An organisation of its own: a budget on the shared one would
			// throttle every other test's sign-ins and tokens.
			name: "PUT /admin/organizations/{orgID}/budgets", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/budgets"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"tokens_per_minute":5000,"sign_ins_per_minute":900}`
			},
		},
		{
			// An organisation of its own, for the same reason: a setting on the
			// shared one changes every other test's sign-ins.
			name: "PATCH /admin/organizations/{orgID}/settings", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/settings"
			},
			body: func(*testing.T, *Server, string) string { return `{"remember_device_days":7}` },
		},
		{
			// Its own organisation: an open sign-up on the shared one would let
			// other tests' addresses make accounts.
			name: "PUT /admin/organizations/{orgID}/signup", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/signup"
			},
			body: func(*testing.T, *Server, string) string { return `{"allowed_domains":["drift.example"]}` },
		},
		{
			name: "PUT /admin/instances/{instanceID}/brand", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftInstance(t, s) + "/brand"
			},
			body: func(*testing.T, *Server, string) string { return `{"product_name":"Drift"}` },
		},
		{
			name: "DELETE /admin/instances/{instanceID}/brand", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				id := newDriftInstance(t, s)
				if err := store.SaveBrand(context.Background(), s.db, id, &brand.Brand{ProductName: "Drift"}); err != nil {
					t.Fatal(err)
				}
				return "/admin/instances/" + id + "/brand"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/instances/{instanceID}/webauthn", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftInstance(t, s) + "/webauthn"
			},
			body: func(*testing.T, *Server, string) string { return `{"rp_id":"drift.example"}` },
		},
		{
			name: "POST /admin/instances/{instanceID}/issuer-aliases", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftInstance(t, s) + "/issuer-aliases"
			},
			body: func(*testing.T, *Server, string) string {
				return fmt.Sprintf(`{"alias":"https://legacy-%d.test"}`, time.Now().UnixNano())
			},
		},
		{
			name: "PATCH /admin/instances/{instanceID}/issuer-aliases", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftInstanceWithAlias(t, s) + "/issuer-aliases"
			},
			body: func(t *testing.T, s *Server, path string) string {
				var alias string
				if err := s.db.QueryRow(context.Background(), `SELECT issuer FROM core.instance_issuer_aliases
					WHERE instance_id::text = split_part($1, '/', 4)`, path).Scan(&alias); err != nil {
					t.Fatal(err)
				}
				return `{"alias":"` + alias + `"}`
			},
		},
		{
			name: "POST /admin/organizations/{orgID}/event-subscriptions", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/event-subscriptions"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"name":"drift","url":"https://hooks.example.test/drift"}`
			},
		},
		{
			name: "DELETE /admin/organizations/{orgID}/event-subscriptions/{name}", method: http.MethodDelete,
			path: newDriftSubscription,
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/event-subscriptions/{name}/rotate-secret", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string { return newDriftSubscription(t, s) + "/rotate-secret" },
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/event-subscriptions/{name}/enable", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string { return newDriftSubscription(t, s) + "/enable" },
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/event-subscriptions/{name}/test", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string { return newDriftSubscription(t, s) + "/test" },
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/radius-clients", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/radius-clients"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"name":"drift","network":"192.0.2.0/24","secret":"a-drift-shared-secret"}`
			},
		},
		{
			name: "PATCH /admin/organizations/{orgID}/radius-clients/{deviceID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				id, _, err := store.AddRADIUSClient(context.Background(), s.db, s.root, org, "drift", "192.0.2.0/24",
					"a-drift-shared-secret")
				if err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/radius-clients/" + id
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			name: "PUT /admin/groups/{groupID}/radius", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string { return "/admin/groups/" + newDriftGroup(t, s) + "/radius" },
			body: func(*testing.T, *Server, string) string { return `{"vlan_id":42}` },
		},
		{
			name: "DELETE /admin/groups/{groupID}/radius", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				group := newDriftGroup(t, s)
				if err := store.SetRADIUSAuthorization(context.Background(), s.db, anyOrgID(t, s), group, 42, "", 0); err != nil {
					t.Fatal(err)
				}
				return "/admin/groups/" + group + "/radius"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/saml-providers", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/saml-providers"
			},
			body: func(_ *testing.T, _ *Server, path string) string {
				return `{"entity_id":"https://drift-` + strings.Split(path, "/")[3] + `.example.test",` +
					`"acs_url":"https://drift.example.test/acs"}`
			},
		},
		{
			name: "PATCH /admin/organizations/{orgID}/saml-providers/{providerID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				_, p := newDriftSAMLProvider(t, s)
				return p
			},
			body: func(*testing.T, *Server, string) string { return `{"lifetime_s":600}` },
		},
		{
			name: "PUT /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				_, p := newDriftSAMLProvider(t, s)
				return p + "/attribute-release"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"saml_attribute":"department","attribute":"department"}`
			},
		},
		{
			name: "DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org, p := newDriftSAMLProvider(t, s)
				if err := store.SetSAMLAttributeRelease(context.Background(), s.db, org, p[strings.LastIndex(p, "/")+1:],
					"department", "department"); err != nil {
					t.Fatal(err)
				}
				return p + "/attribute-release?saml_attribute=department"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/saml-providers/{providerID}/group-release", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				_, p := newDriftSAMLProvider(t, s)
				return p + "/group-release"
			},
			body: func(*testing.T, *Server, string) string { return `{"only":["drift-group"]}` },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/group-release", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org, p := newDriftSAMLProvider(t, s)
				if err := store.SetSAMLGroupRelease(context.Background(), s.db, org, p[strings.LastIndex(p, "/")+1:],
					"", nil); err != nil {
					t.Fatal(err)
				}
				return p + "/group-release"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/directories", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/directories"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"kind":"ldap","slug":"drift","ldap_url":"ldaps://ldap.example.test",` +
					`"ldap_base_dn":"dc=example,dc=test","ldap_flavour":"openldap","ldap_password":"p"}`
			},
		},
		{
			name: "PATCH /admin/organizations/{orgID}/directories/{slug}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftDirectory(t, s) + "/directories/drift"
			},
			body: func(*testing.T, *Server, string) string { return `{"dry_run":false}` },
		},
		{
			name: "PUT /admin/organizations/{orgID}/directories/{slug}/group-map", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftDirectory(t, s) + "/directories/drift/group-map"
			},
			body: func(*testing.T, *Server, string) string { return `{"remote_group":"cn=staff","group":"drift-group"}` },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/directories/{slug}/group-map", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftDirectory(t, s)
				if err := directory.MapGroup(context.Background(), s.db, org, "drift", "cn=staff", "drift-group"); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/directories/drift/group-map?remote_group=cn%3Dstaff&group=drift-group"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// A stand-in for the directory, so nothing is dialled.
			name: "POST /admin/organizations/{orgID}/directories/{slug}/sync", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				standInDirectory(s, directory.SyncReport{}, nil)
				return "/admin/organizations/" + newDriftDirectory(t, s) + "/directories/drift/sync"
			},
			body: func(*testing.T, *Server, string) string { return `{"apply":true}` },
		},
		{
			name: "POST /admin/organizations/{orgID}/scim-sources", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/scim-sources"
			},
			body: func(*testing.T, *Server, string) string { return `{"slug":"drift"}` },
		},
		{
			name: "PATCH /admin/organizations/{orgID}/scim-sources/{slug}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if _, _, err := store.AddSCIMSource(context.Background(), s.db, org, "drift", "", ""); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/scim-sources/drift"
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			name: "POST /admin/organizations/{orgID}/scim-targets", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/scim-targets"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"slug":"drift","base_url":"https://scim.example.test/v2","token":"a-token"}`
			},
		},
		{
			name: "PATCH /admin/organizations/{orgID}/scim-targets/{slug}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				org, _ := newDriftSCIMTarget(t, s, false)
				return "/admin/organizations/" + org + "/scim-targets/drift"
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			name: "PUT /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				org, _ := newDriftSCIMTarget(t, s, false)
				return "/admin/organizations/" + org + "/scim-targets/drift/groups/drift-group"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				ctx := context.Background()
				org, fake := newDriftSCIMTarget(t, s, false)
				target, err := provision.TargetForGroups(ctx, s.db, s.root, org, "drift")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := provision.ProvisionGroup(ctx, s.db, target, fake.Client(), "drift-group"); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/scim-targets/drift/groups/drift-group"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// An organisation with nobody in it, so nothing is sent.
			name: "POST /admin/organizations/{orgID}/scim-targets/{slug}/sync", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				org, _ := newDriftSCIMTarget(t, s, false)
				return "/admin/organizations/" + org + "/scim-targets/drift/sync"
			},
			body: func(*testing.T, *Server, string) string { return `{"apply":true}` },
		},
		{
			// A poll stream, which needs no endpoint or token.
			name: "POST /admin/organizations/{orgID}/ssf-streams", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				clientIn(t, s, org)
				return "/admin/organizations/" + org + "/ssf-streams"
			},
			body: func(t *testing.T, s *Server, path string) string {
				var client string
				if err := s.db.QueryRow(context.Background(), `SELECT client_id FROM core.clients
					WHERE org_id::text = split_part($1, '/', 4)`, path).Scan(&client); err != nil {
					t.Fatal(err)
				}
				return `{"client_id":"` + client + `","poll":true}`
			},
		},
		{
			name: "PATCH /admin/clients/{clientID}/ssf-stream", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				client := clientIn(t, s, org)
				if _, err := store.AddStream(context.Background(), s.db, s.root, org, store.StreamSpec{ClientID: client,
					Poll: true}); err != nil {
					t.Fatal(err)
				}
				return "/admin/clients/" + client + "/ssf-stream"
			},
			body: func(*testing.T, *Server, string) string { return `{"status":"paused"}` },
		},
		{
			// Issuer and audience are unique together across the deployment.
			name: "PUT /admin/organizations/{orgID}/ssf-sources", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/ssf-sources"
			},
			body: func(_ *testing.T, _ *Server, path string) string {
				return `{"name":"drift","issuer":"https://transmitter.example.test","jwks_uri":` +
					`"https://transmitter.example.test/jwks","audience":"https://receiver.example.test/` +
					strings.Split(path, "/")[3] + `","events":["` + ssf.EventSessionRevoked + `"]}`
			},
		},
		{
			name: "PUT /admin/instances/{instanceID}/federation", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				id := newDriftInstance(t, s)
				t.Cleanup(func() {
					_, _ = s.db.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, id)
				})
				return "/admin/instances/" + id + "/federation"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"authority_hints":["https://anchor.example.test"]}`
			},
		},
		{
			name: "POST /admin/instances/{instanceID}/trust-marks", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftFederatedInstance(t, s) + "/trust-marks"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"type":"` + driftMarkType + `","subject":"https://rp.example.test","lifetime_s":3600}`
			},
		},
		{
			name: "POST /admin/instances/{instanceID}/trust-marks/revoke", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				id := newDriftFederatedInstance(t, s)
				issuer, _, err := store.InstanceIssuer(context.Background(), s.db, id)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := store.IssueSignedTrustMark(context.Background(), s.db, s.root, id, issuer,
					oidfed.TrustMarkParams{Subject: "https://rp.example.test", Type: driftMarkType,
						Lifetime: time.Hour}, time.Now()); err != nil {
					t.Fatal(err)
				}
				return "/admin/instances/" + id + "/trust-marks/revoke"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"type":"` + driftMarkType + `","subject":"https://rp.example.test"}`
			},
		},
		{
			name: "PUT /admin/instances/{instanceID}/held-trust-marks", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftFederatedInstance(t, s) + "/held-trust-marks"
			},
			body: func(t *testing.T, s *Server, path string) string {
				mark, _ := driftTrustMarkFor(t, s, entityOf(t, s, path))
				return `{"trust_mark":"` + mark + `"}`
			},
		},
		{
			name: "DELETE /admin/instances/{instanceID}/held-trust-marks", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				id := newDriftFederatedInstance(t, s)
				path := "/admin/instances/" + id + "/held-trust-marks"
				mark, issuer := driftTrustMarkFor(t, s, entityOf(t, s, path))
				if _, err := store.AcceptTrustMark(context.Background(), s.db, id, entityOf(t, s, path), mark,
					time.Now()); err != nil {
					t.Fatal(err)
				}
				return path + "?type=" + url.QueryEscape(driftMarkType) + "&issuer=" + url.QueryEscape(issuer)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/instances/{instanceID}/trust-mark-delegations", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftFederatedInstance(t, s) + "/trust-mark-delegations"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"type":"` + driftMarkType + `","delegate":"https://delegate.example.test","lifetime_s":3600}`
			},
		},
		{
			name: "PUT /admin/organizations/{orgID}/authorization-model", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/authorization-model"
			},
			body: func(t *testing.T, _ *Server, _ string) string {
				b, err := json.Marshal(map[string]string{"source": driftModel})
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			},
		},
		{
			name: "PUT /admin/organizations/{orgID}/relations", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/relations"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"subject":"user:alice","relation":"owner","object":"document:1"}`
			},
		},
		{
			name: "DELETE /admin/organizations/{orgID}/relations", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if err := store.GrantRelation(context.Background(), s.db, org, store.Relation{SubjectType: "user",
					SubjectID: "alice", Relation: "owner", ObjectType: "document", ObjectID: "1"}, ""); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/relations?subject=user:alice&relation=owner&object=document:1"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// A group the organisation does not have, so the plan creates it.
			name: "POST /admin/organizations/{orgID}/config", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/config"
			},
			body: func(t *testing.T, _ *Server, _ string) string {
				b, err := json.Marshal(map[string]string{"document": "version: 1\ngroups:\n  - name: drift\n"})
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			},
		},
		{
			name: "PUT /admin/organizations/{orgID}/access-policy", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/access-policy"
			},
			body: func(t *testing.T, _ *Server, _ string) string {
				b, err := json.Marshal(map[string]string{"document": "version: 1\npolicies: []\ntests:\n" +
					"  - name: open\n    given: {client: anything}\n    expect: allow\n"})
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			},
		},
		{
			name: "PUT /admin/organizations/{orgID}/sign-in-flow", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/sign-in-flow"
			},
			body: func(t *testing.T, _ *Server, _ string) string {
				b, err := json.Marshal(map[string]string{"document": string(flow.DefaultDocument())})
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			},
		},
		{
			name: "POST /admin/organizations/{orgID}/rac-connections", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/rac-connections"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"slug":"drift","protocol":"ssh","host":"bastion.example.test"}`
			},
		},
		{
			name: "PATCH /admin/organizations/{orgID}/rac-connections/{slug}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if _, err := store.AddRACConnection(context.Background(), s.db, s.root, org, store.RACSpec{Slug: "drift",
					Protocol: "ssh", Host: "bastion.example.test"}); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/rac-connections/drift"
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			name: "POST /admin/organizations/{orgID}/outposts", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/outposts"
			},
			body: func(*testing.T, *Server, string) string { return `{"name":"drift","kind":"radius"}` },
		},
		{
			name: "PATCH /admin/organizations/{orgID}/outposts/{name}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if _, _, err := store.CreateOutpost(context.Background(), s.db, org, "drift", "radius", ""); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/outposts/drift"
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			name: "PUT /admin/organizations/{orgID}/providers/{hook}", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/providers/token_issue"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"url":"https://hooks.example.test/claims","mode":"fail_open"}`
			},
		},
		{
			name: "DELETE /admin/organizations/{orgID}/providers/{hook}", method: http.MethodDelete,
			path: newDriftProvider,
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/providers/{hook}/rotate-secret", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string { return newDriftProvider(t, s) + "/rotate-secret" },
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/providers/{hook}/claims", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string { return newDriftProvider(t, s) + "/claims" },
			body: func(*testing.T, *Server, string) string { return `{"claims":["department"]}` },
		},
		{
			// An instance of its own with an active key, so rotating publishes
			// a next one.
			name: "POST /admin/instances/{instanceID}/keys/rotate", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftKeyedInstance(t, s) + "/keys/rotate"
			},
			body: func(*testing.T, *Server, string) string { return `{}` },
		},
		{
			name: "POST /admin/instances/{instanceID}/keys/retire", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/instances/" + newDriftKeyedInstance(t, s) + "/keys/retire"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// A Duo stand-in, since the keys are checked against Duo first.
			name: "PUT /admin/organizations/{orgID}/duo", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				healthyDuo(t)
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/duo"
			},
			body: func(*testing.T, *Server, string) string { return duoKeys },
		},
		{
			name: "PUT /admin/users/{userID}/duo", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				sealed, err := s.root.Seal([]byte(strings.Repeat("s", 40)), "duo_secret")
				if err != nil {
					t.Fatal(err)
				}
				if err := store.SetDuoIntegration(context.Background(), s.db, org, "DIABCDEFGHIJKLMNOPQR", sealed,
					"api-1234abcd.duosecurity.com", false); err != nil {
					t.Fatal(err)
				}
				return "/admin/users/" + personIn(t, s, org) + "/duo"
			},
			body: func(*testing.T, *Server, string) string { return `{"duo_username":"drift"}` },
		},
		{
			name: "PUT /admin/organizations/{orgID}/uma", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/uma"
			},
			body: func(*testing.T, *Server, string) string { return `{"owner_intervention":true}` },
		},
		{
			name: "POST /admin/organizations/{orgID}/uma/requests/{requestID}/approve", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				org, id, _ := newDriftUMARequest(t, s)
				return "/admin/organizations/" + org + "/uma/requests/" + id + "/approve"
			},
			body: func(*testing.T, *Server, string) string { return `{"relation":"viewer"}` },
		},
		{
			name: "POST /admin/organizations/{orgID}/uma/requests/{requestID}/deny", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				org, id, _ := newDriftUMARequest(t, s)
				return "/admin/organizations/" + org + "/uma/requests/" + id + "/deny"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/attesters/{name}", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/attesters/drift"
			},
			body: func(t *testing.T, _ *Server, _ string) string { return `{"jwks":` + string(publicJWKS(t)) + `}` },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/attesters/{name}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if _, err := store.SetAttester(context.Background(), s.db, org, "drift", publicJWKS(t), ""); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/attesters/drift"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/authorization-detail-types", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/authorization-detail-types"
			},
			body: func(*testing.T, *Server, string) string { return `{"type":"drift","fields":["actions"]}` },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/authorization-detail-types", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if err := store.RegisterDetailType(context.Background(), s.db, org, store.DetailType{Type: "drift",
					Fields: []string{"actions"}}); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/authorization-detail-types?type=drift"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// Its own organisation: a prompt on the shared one is asked at
			// every other test's sign-in.
			name: "PUT /admin/organizations/{orgID}/prompts/{slug}", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/prompts/drift"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"title":"Drift","fields":[{"name":"ok","type":"checkbox","label":"OK","required":true}]}`
			},
		},
		{
			name: "PATCH /admin/organizations/{orgID}/prompts/{slug}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if _, _, err := store.SavePrompt(context.Background(), s.db, org, store.PromptDefinition{
					Slug: "drift", Title: "Drift", Once: true, Fields: []prompts.Field{
						{Name: "ok", Type: prompts.Checkbox, Label: "OK", Required: true}}}); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/prompts/drift"
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			// Its own organisation: registration open on the shared one would
			// change what the registration tests see.
			name: "PUT /admin/organizations/{orgID}/registration", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/registration"
			},
			body: func(*testing.T, *Server, string) string { return `{"max_clients":5}` },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/registration", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if err := store.SetRegistrationPolicy(context.Background(), s.db, org, store.RegistrationPolicy{}); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/registration"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations/{orgID}/registration-tokens", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/registration-tokens"
			},
			body: func(*testing.T, *Server, string) string { return `{"name":"drift","uses":1}` },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/registration-tokens/{tokenID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				_, id, err := store.NewRegistrationToken(context.Background(), s.db, org, "drift", 1, nil)
				if err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/registration-tokens/" + id
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/organizations/{orgID}/signup", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if err := store.SetSignupRule(context.Background(), s.db, store.SignupRule{OrgID: org,
					AllowedDomains: []string{"drift.example"}}); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/signup"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// A fresh person each time: a binding is once per person and role.
			name: "POST /admin/organizations/{orgID}/role-bindings", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + anyOrgID(t, s) + "/role-bindings"
			},
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"role":"auditor","user_id":%q}`, newDriftUser(t, s))
			},
		},
		{
			name:   "DELETE /admin/organizations/{orgID}/role-bindings/{bindingID}",
			method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + anyOrgID(t, s) + "/role-bindings/" + newDriftBinding(t, s, "auditor")
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name:   "DELETE /admin/organizations/{orgID}/proxy-hosts/{host}",
			method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				orgID := anyOrgID(t, s)
				return "/admin/organizations/" + orgID + "/proxy-hosts/" + newDriftProxyHost(t, s, orgID)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// An organisation of its own each time: the source is one per
			// organisation, and the shared one must not acquire a source
			// that would send its pending people's passwords somewhere.
			name: "PUT /admin/organizations/{orgID}/migration-source", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/migration-source"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"kind":"ldap","display_name":"drift","url":"ldaps://dir.example.test",` +
					`"bind_dn_template":"uid={username},dc=example"}`
			},
		},
		{
			name: "DELETE /admin/organizations/{orgID}/migration-source", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, true) + "/migration-source"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/organizations/{orgID}/resource-servers", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/resource-servers"
			},
			body: func(*testing.T, *Server, string) string {
				return `{"resource":"https://api.drift.example.test","name":"drift"}`
			},
		},
		{
			name: "DELETE /admin/organizations/{orgID}/resource-servers", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				org := newDriftMigrationOrg(t, s, false)
				if _, err := s.db.Exec(context.Background(), `INSERT INTO core.resource_servers (org_id, resource)
					VALUES ($1::uuid, 'https://api.drift.example.test')`, org); err != nil {
					t.Fatal(err)
				}
				return "/admin/organizations/" + org + "/resource-servers?resource=https://api.drift.example.test"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/organizations", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/organizations" },
			body: func(t *testing.T, s *Server, _ string) string {
				// A slug no other run has used. The uniqueness is per instance,
				// so a fixed one would make the second run a 409 and exempt the
				// route from the checks this list exists to apply.
				//
				// instance_id is named rather than inferred: the handler only
				// infers it when a deployment has exactly one instance, and a
				// test database accumulates several.
				return fmt.Sprintf(`{"slug":"drift-%d","display_name":"Drift","instance_id":%q}`,
					time.Now().UnixNano(), anyInstanceID(t, s))
			},
		},
		{
			// An organisation of its own: suspending a shared one would refuse
			// every other test's sign-ins in it.
			name: "PATCH /admin/organizations/{orgID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/organizations/" + newDriftMigrationOrg(t, s, false)
			},
			body: func(*testing.T, *Server, string) string { return `{"status":"suspended"}` },
		},
		{
			name: "POST /admin/clients", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/clients" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"client_id":"drift-%d","org_id":%q,"display_name":"d",`+
					`"redirect_uris":["https://app.example.test/cb"]}`,
					time.Now().UnixNano(), anyOrgID(t, s))
			},
		},
		{
			name: "PATCH /admin/clients/{clientID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/clients/" + newPreconditionClient(t, s)
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			name: "DELETE /admin/clients/{clientID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/clients/" + newPreconditionClient(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/clients/{clientID}/rotate-secret", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/clients/" + newPreconditionClient(t, s) + "/rotate-secret"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/clients/{clientID}/group-release", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/clients/" + newPreconditionClient(t, s) + "/group-release"
			},
			body: func(*testing.T, *Server, string) string { return `{"only_groups":[]}` },
		},
		{
			// A client already told of every group, so there is a release to stop.
			name: "DELETE /admin/clients/{clientID}/group-release", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				client := newPreconditionClient(t, s)
				if _, err := s.db.Exec(context.Background(), `INSERT INTO core.client_group_release
					(client_id, org_id, only_groups) SELECT client_id, org_id, '{}' FROM core.clients
					WHERE client_id = $1`, client); err != nil {
					t.Fatal(err)
				}
				return "/admin/clients/" + client + "/group-release"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/subjects/{subjectID}/erase", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/subjects/" + newDriftSubject(t, s) + "/erase"
			},
			body: func(t *testing.T, s *Server, path string) string {
				// confirm_subject_id must repeat the identifier in the path.
				var id string
				fmt.Sscanf(path, "/admin/subjects/%s", &id)
				id = id[:len(id)-len("/erase")]
				return fmt.Sprintf(`{"confirm_subject_id":%q,"deactivate":true}`, id)
			},
		},
		{
			name: "POST /admin/groups", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/groups" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"org_id":%q,"name":"drift-%d"}`,
					anyOrgID(t, s), time.Now().UnixNano())
			},
		},
		{
			name: "PATCH /admin/groups/{groupID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s)
			},
			body: func(*testing.T, *Server, string) string { return `{"display_name":"renamed"}` },
		},
		{
			name: "DELETE /admin/groups/{groupID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/groups/{groupID}/members/{userID}", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s) + "/members/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/groups/{groupID}/members/{userID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s) + "/members/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/users/{userID}/sessions", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s) + "/sessions"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/sessions/{sid}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/sessions/" + newDriftSession(t, s, newDriftUser(t, s))
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
	}
}

// newDriftGroup creates a group in the fixture organisation.
func newDriftGroup(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, $2)
		RETURNING id::text`,
		anyOrgID(t, s), fmt.Sprintf("drift-%d", time.Now().UnixNano())).Scan(&id); err != nil {
		t.Fatalf("creating the fixture group: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.group_members WHERE group_id = $1::uuid`, id)
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.groups WHERE id = $1::uuid`, id)
	})
	return id
}

// newDriftInstance is an instance of the test's own, so a brand put on it is
// seen by no other test's pages.
func newDriftInstance(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://drift-' || gen_random_uuid() || '.test', 'Drift') RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.brands WHERE instance_id = $1::uuid`, id)
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.instance_issuer_aliases WHERE instance_id = $1::uuid`, id)
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.instances WHERE id = $1::uuid`, id)
	})
	return id
}

// newDriftSubscription is an organisation of the test's own subscribed by name
// to every event, and the path of that subscription.
func newDriftSubscription(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.CreateSubscription(ctx, tx, s.root, org, "drift", "https://hooks.example.test/drift", nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return "/admin/organizations/" + org + "/event-subscriptions/drift"
}

// driftMarkType is the Trust Mark type the federation fixtures issue.
const driftMarkType = "https://marks.example.test/certified"

// newDriftFederatedInstance is an instance of its own enabled for federation,
// with the federation key that gives it.
func newDriftFederatedInstance(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	id := newDriftInstance(t, s)
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, id)
	})
	issuer, _, err := store.InstanceIssuer(ctx, s.db, id)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.EnableFederation(ctx, tx, s.root, id, issuer, store.FederationChange{
		AuthorityHints: []string{"https://anchor.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

// driftTrustMarkFor is a Trust Mark another federated instance issued to
// entityID, and that issuer.
func driftTrustMarkFor(t *testing.T, s *Server, entityID string) (mark, issuer string) {
	t.Helper()
	ctx := context.Background()
	other := newDriftFederatedInstance(t, s)
	issuer, _, err := store.InstanceIssuer(ctx, s.db, other)
	if err != nil {
		t.Fatal(err)
	}
	mark, _, err = store.IssueSignedTrustMark(ctx, s.db, s.root, other, issuer, oidfed.TrustMarkParams{
		Subject: entityID, Type: driftMarkType, Lifetime: time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return mark, issuer
}

// entityOf is the Entity Identifier of the instance an /admin/instances path
// names.
func entityOf(t *testing.T, s *Server, path string) string {
	t.Helper()
	issuer, _, err := store.InstanceIssuer(context.Background(), s.db, strings.Split(path, "/")[3])
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

// driftModel is the smallest authorization model with a test, which a model
// must have to load.
const driftModel = `types:
  document:
    relations:
      owner: []
    permissions:
      read: [owner]
tests:
  - name: an owner may read
    subject: user:alice
    action: read
    resource: document:1
    relations: [owner]
    allow: true
`

// newDriftProvider registers a token_issue provider for an organisation of
// its own and returns its path.
func newDriftProvider(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, err := store.SaveProvider(ctx, tx, s.root, org, provider.Provider{Name: "provider-token_issue",
		Hook: provider.HookTokenIssue, URL: "https://hooks.example.test/claims", Mode: provider.FailOpen,
		Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return "/admin/organizations/" + org + "/providers/token_issue"
}

// newDriftKeyedInstance is newDriftInstance with one active ES256 key.
func newDriftKeyedInstance(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	id := newDriftInstance(t, s)
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, err := keys.WithState(k, keys.StateActive)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := keys.Save(ctx, tx, id, active, s.root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, id)
	})
	return id
}

// newDriftInstanceWithAlias is newDriftInstance claiming one legacy issuer.
func newDriftInstanceWithAlias(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	id := newDriftInstance(t, s)
	alias := fmt.Sprintf("https://legacy-%d.test", time.Now().UnixNano())
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.AddIssuerAlias(ctx, tx, id, alias, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.instance_issuer_aliases WHERE issuer = $1`, alias)
	})
	return id
}

// newDriftSession creates a live session for a user.
func newDriftSession(t *testing.T, s *Server, userID string) string {
	t.Helper()
	sid := fmt.Sprintf("drift-sess-%d", time.Now().UnixNano())
	var orgID string
	if err := s.db.QueryRow(context.Background(),
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatalf("reading the fixture user's organisation: %v", err)
	}
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '1 hour')`,
		sid, orgID, userID); err != nil {
		t.Fatalf("creating the fixture session: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.sessions WHERE sid = $1`, sid)
	})
	return sid
}

func newDriftUser(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4)
		RETURNING id::text`,
		anyOrgID(t, s), fmt.Sprint(time.Now().UnixNano()),
		fmt.Sprint(time.Now().UnixNano()+1),
		fmt.Sprintf("drift-%d@example.test", time.Now().UnixNano())).Scan(&id); err != nil {
		t.Fatalf("creating the fixture user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id)
	})
	return id
}

// newDriftBinding gives a fresh person in the fixture organisation a role and
// returns the binding's id; the person's removal takes the binding with it.
func newDriftBinding(t *testing.T, s *Server, role string) string {
	t.Helper()
	id, err := store.GrantRole(context.Background(), s.db, store.RoleBinding{
		OrgID: anyOrgID(t, s), UserID: newDriftUser(t, s), Role: role})
	if err != nil {
		t.Fatalf("granting the fixture role: %v", err)
	}
	return id
}

// newDriftToken makes a token for the rotate and revoke routes, removed by
// name with whatever replacement a rotation made.
func newDriftToken(t *testing.T, s *Server) string {
	t.Helper()
	name := fmt.Sprintf("drift-token-%d", time.Now().UnixNano())
	expires := time.Now().Add(time.Hour)
	_, id, err := NewToken(context.Background(), s.db, name, "", []string{ScopeConfigRead}, &expires, nil, nil)
	if err != nil {
		t.Fatalf("creating the fixture token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE name = $1`, name)
	})
	return id
}

// newDriftInvitation makes an open invitation for the revoke route to close.
func newDriftInvitation(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, _, _, err := store.NewInvitation(ctx, tx, store.InvitationSpec{OrgID: anyOrgID(t, s), TTL: time.Hour})
	if err != nil {
		t.Fatalf("creating the fixture invitation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.invitations WHERE id = $1::uuid`, id)
	})
	return id
}

// newDriftSubject creates a subject key that erasure can destroy.
//
// Columns taken from the live schema (subject_id, wrapped_dek, wrap_key_ref),
// not from what a fixture elsewhere happens to use. The first version of this
// helper guessed `org_id` and `dek`, the insert failed, and the erasure route --
// the one whose missing version bump prompted this whole test -- skipped itself
// while the suite reported PASS. A skip in a coverage test is a hole with a
// friendly name.
// newDriftUserWithTOTP creates a user who has something to reset.
//
// secret_enc is a placeholder: nothing in these tests decrypts it, and the
// factor routes deliberately never return it. Columns taken from the live
// schema rather than guessed -- a failing INSERT here would make the route skip
// itself while the suite reported PASS.
// driftAttributeName is declared once for the whole package.
//
// A fixed name because the value-setting route needs an attribute that already
// exists, and declaring one per call would make the drift test's fixture depend
// on the order tests happen to run in.
const driftAttributeName = "drift_fixture_attribute"

// newDriftUserWithAttribute creates a user in an org that declares the fixture
// attribute, so the value-setting route has something to write.
func newDriftUserWithAttribute(t *testing.T, s *Server) string {
	t.Helper()
	userID := newDriftUser(t, s)
	var orgID string
	if err := s.db.QueryRow(context.Background(),
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatalf("reading the fixture user's organisation: %v", err)
	}
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.user_attribute_schema (org_id, name, value_type, personal)
		VALUES ($1::uuid, $2, 'string', true)
		ON CONFLICT (org_id, name) DO NOTHING`, orgID, driftAttributeName); err != nil {
		t.Fatalf("declaring the fixture attribute: %v", err)
	}
	return userID
}

// orgWithDriftAttribute returns an organisation that declares the fixture
// attribute, so a mapper has something to point at.
func orgWithDriftAttribute(t *testing.T, s *Server) string {
	t.Helper()
	orgID := anyOrgID(t, s)
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.user_attribute_schema (org_id, name, value_type, personal)
		VALUES ($1::uuid, $2, 'string', true)
		ON CONFLICT (org_id, name) DO NOTHING`, orgID, driftAttributeName); err != nil {
		t.Fatalf("declaring the fixture attribute: %v", err)
	}
	return orgID
}

// newDriftMapper creates a mapper to delete, and returns its id.
//
// A fresh claim name each time: the unique constraint is on (org, client,
// attribute, destination), so reusing one would upsert rather than insert and
// the delete case would race the create case above.
func newDriftMapper(t *testing.T, s *Server, orgID string) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.claim_mappers
			(org_id, client_id, attribute_id, claim_name, destination, required_scope)
		SELECT $1::uuid, NULL, id, $2, 'id_token', ''
		FROM core.user_attribute_schema WHERE org_id = $1::uuid AND name = $3
		RETURNING id::text`,
		orgID, fmt.Sprintf("drift_del_%d", time.Now().UnixNano()), driftAttributeName).
		Scan(&id); err != nil {
		t.Fatalf("creating the fixture mapper: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.claim_mappers WHERE id = $1::uuid`, id)
	})
	return id
}

// newDriftScope declares a scope for the delete case to remove.
func newDriftScope(t *testing.T, s *Server, orgID string) string {
	t.Helper()
	name := fmt.Sprintf("drift_del_scope_%d", time.Now().UnixNano())
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.scopes (org_id, name) VALUES ($1::uuid, $2)`,
		orgID, name); err != nil {
		t.Fatalf("declaring the fixture scope: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.scopes WHERE org_id = $1::uuid AND name = $2`, orgID, name)
	})
	return name
}

// newDriftProxyHost registers a protected host for the delete case to remove.
func newDriftProxyHost(t *testing.T, s *Server, orgID string) string {
	t.Helper()
	host := fmt.Sprintf("drift-del-%d.example.com", time.Now().UnixNano())
	if _, err := s.db.Exec(context.Background(),
		`INSERT INTO core.proxy_hosts (org_id, host) VALUES ($1::uuid, $2)`, orgID, host); err != nil {
		t.Fatalf("registering the fixture host: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.proxy_hosts WHERE org_id = $1::uuid AND host = $2`, orgID, host)
	})
	return host
}

func anyInstanceID(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(),
		`SELECT id::text FROM core.instances ORDER BY created_at LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("no instance to attach an organisation to: %v", err)
	}
	return id
}

func newDriftUserWithTOTP(t *testing.T, s *Server) string {
	t.Helper()
	userID := newDriftUser(t, s)
	var orgID string
	if err := s.db.QueryRow(context.Background(),
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatalf("reading the fixture user's organisation: %v", err)
	}
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, $3, now())`,
		userID, orgID, []byte("not-a-real-secret")); err != nil {
		t.Fatalf("enrolling the fixture TOTP credential: %v", err)
	}
	return userID
}

// newDriftPasskey gives a user one WebAuthn credential and returns its id.
func newDriftPasskey(t *testing.T, s *Server, userID string) string {
	t.Helper()
	var orgID string
	if err := s.db.QueryRow(context.Background(),
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatalf("reading the fixture user's organisation: %v", err)
	}
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.webauthn_credentials
			(user_id, org_id, credential_id, public_key, rp_id, friendly_name)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
		RETURNING id::text`,
		userID, orgID,
		[]byte(fmt.Sprintf("cred-%d", time.Now().UnixNano())),
		[]byte("not-a-real-key"), "localhost", "fixture key").Scan(&id); err != nil {
		t.Fatalf("enrolling the fixture passkey: %v", err)
	}
	return id
}

func newDriftSubject(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.subject_keys (subject_id, wrapped_dek, wrap_key_ref)
		VALUES (gen_random_uuid(), $1, 'drift-test')
		RETURNING subject_id::text`,
		[]byte("drift-fixture-key-material")).Scan(&id); err != nil {
		t.Fatalf("creating the subject-key fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.subject_keys WHERE subject_id = $1::uuid`, id)
	})
	return id
}

// Property 1: a stale If-Match must be refused, on every mutating route.
//
// 412 specifically. A 500 means the handler ran the mutation and then failed to
// map the error, which would mean the write happened.
// The list below must cover every mutating route the server registers.
//
// # Why this guard is the important one
//
// `allMutatingRoutes` is hand-written, and the two tests under it are what
// guarantee the product's headline property: every administrative write honours
// an If-Match precondition and bumps the configuration version. A route missing
// from the list is not caught by those tests -- it is silently exempt from both,
// and they still report success.
//
// That is a green suite meaning less than it appears, which this codebase has
// been caught by before. Adding `DELETE /admin/clients/{clientID}` demonstrated
// it: both tests passed with the new route entirely unexercised.
//
// Derived from the actual registrations rather than a second hand-written list,
// so the only way to satisfy it is to write the case.
func TestTheMutatingRouteListCoversEveryRegisteredRoute(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}

	// A route pattern for a method that writes, as the first argument of any
	// call. It does not depend on the wrapper's name.
	//
	// This regex went blind twice. The first time, Routes() moved from
	// mux.HandleFunc to route() and it matched nothing, which the count check
	// below reported. The second time, writes on users and groups moved to
	// privileged() and it stopped seeing ten of them. The count stayed above the
	// floor, so nothing reported it. The router's own operation table is
	// therefore read as well, and the two must agree.
	re := regexp.MustCompile(`\("(POST|PATCH|PUT|DELETE) (/admin/[^"]*)"`)
	found := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		found[m[1]+" "+m[2]] = true
	}
	if len(found) < 8 {
		t.Fatalf("only %d mutating registrations parsed out of server.go; the regex "+
			"has stopped matching and this guard is checking nothing", len(found))
	}
	s := routerOnly(t)
	for _, op := range s.ops {
		if op.method == "get" {
			continue
		}
		name := strings.ToUpper(op.method) + " " + op.path
		if !found[name] {
			t.Errorf("%s is registered and the source scan did not see it, so the "+
				"scan has gone blind to a registration form", name)
		}
	}

	listed := map[string]bool{}
	for _, rt := range allMutatingRoutes() {
		listed[rt.name] = true
	}

	var missing []string
	for name := range found {
		if !listed[name] {
			missing = append(missing, "  "+name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d mutating route(s) are registered but absent from "+
			"allMutatingRoutes():\n%s\n\nEach is currently exempt from both the "+
			"precondition test and the config-version test, and those tests pass "+
			"without exercising it. Add a case rather than trusting the route.",
			len(missing), strings.Join(missing, "\n"))
	}
}

func TestEveryMutatingRouteHonoursPreconditions(t *testing.T) {
	s, _ := newTestServer(t)

	for _, rt := range allMutatingRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			path := rt.path(t, s)
			body := rt.body(t, s, path)

			// The version is global, and other packages' tests move it while
			// this runs, so one move proves nothing about this route. A
			// refused write that commits moves it every time; up to eight
			// tries, and a move on every one is the failure (4.19). Three
			// were once all moved by other packages in a parallel run (0.22).
			const tries = 8
			moved := 0
			var before, got int64
			for i := 0; i < tries; i++ {
				before = currentVersion(t, s)
				stale := fmt.Sprintf(`"%d"`, before-1)

				rec := httptest.NewRecorder()
				s.Routes().ServeHTTP(rec, adminReq(t, rt.method, path, body, stale))

				if rec.Code != http.StatusPreconditionFailed {
					t.Fatalf("stale If-Match gave %d, want 412. This route does not thread "+
						"the precondition through to mutateIf, so a caller asking for a "+
						"conditional write gets an unconditional one: %s",
						rec.Code, rec.Body.String())
				}
				if got = currentVersion(t, s); got == before {
					break
				}
				moved++
			}
			if moved == tries {
				t.Errorf("a refused conditional write still moved the version, %d times out of %d: "+
					"%d -> %d", moved, tries, before, got)
			}
		})
	}
}

// Property 2: a successful mutation must bump the configuration version.
//
// The invariant in this package's doc comment, checked rather than asserted.
// This is the test that would have caught the erasure handler.
func TestEveryMutatingRouteBumpsTheConfigVersion(t *testing.T) {
	s, _ := newTestServer(t)

	for _, rt := range allMutatingRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			path := rt.path(t, s)
			body := rt.body(t, s, path)

			before := currentVersion(t, s)

			rec := httptest.NewRecorder()
			s.Routes().ServeHTTP(rec, adminReq(t, rt.method, path, body, ""))

			if rec.Code >= 400 {
				t.Fatalf("the route did not succeed (%d), so this test proves nothing "+
					"about it. Fix the fixture rather than the assertion: %s",
					rec.Code, rec.Body.String())
			}
			after := currentVersion(t, s)
			if after <= before {
				t.Errorf("config version %d -> %d: this mutation does not move the "+
					"counter If-Match compares, so a client that read before it still "+
					"matches and its conditional write overwrites this one unseen",
					before, after)
			}
			// And the caller is told, so it can confirm propagation without polling.
			// Another package's test can move the global version between the
			// response and the read of after, so the tag must name a version
			// this write could have committed: past before, not past after.
			var tagged int64
			tag := rec.Header().Get("ETag")
			if _, err := fmt.Sscanf(tag, `"%d"`, &tagged); err != nil || tagged <= before || tagged > after {
				t.Errorf("ETag = %q, want a version in (%d, %d]: a mutation that does "+
					"not return its version forces a second round trip before the "+
					"next conditional write", tag, before, after)
			}
		})
	}
}
