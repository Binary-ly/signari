package docsync

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every command that changes the configuration has an Admin API route that
// makes the same change, or a stated reason it does not (6.07). The console,
// the Terraform provider and any automation can do only what the Admin API
// does, and a write that exists only as a command is one they cannot make:
// about 115 of them once did, which left most of the product manageable only
// from a shell with the database's credentials.
//
// The table is read in both directions against what main.go dispatches and the
// admin router registers: a new command must be placed in it, and a route it
// names must exist.

const (
	// reads is a command that changes nothing.
	reads = "reads only"
	// pending is a write whose route is still to be built.
	pending = "pending"
)

// orgSettings is where every organisation-wide sign-in and session setting is
// changed.
const orgSettings = "PATCH /admin/organizations/{orgID}/settings"

// cliOnly is a write that stays a command, and why.
func cliOnly(why string) string { return "command only: " + why }

var cliAPI = map[string]string{
	// The engine and its schema.
	"serve":               cliOnly("runs the engine the API is part of"),
	"verify":              reads,
	"doctor":              reads,
	"version":             reads,
	"migrate bootstrap":   cliOnly("needs a superuser connection, before the engine exists"),
	"migrate up":          cliOnly("changes the schema the engine serving the API depends on"),
	"migrate all":         cliOnly("changes the schema the engine serving the API depends on"),
	"migrate status":      reads,
	"migrate fingerprint": reads,
	"janitor once":        cliOnly("the janitor's own pass, run by hand on the host"),
	"restore finalize":    cliOnly("run against a restored database before anything serves it"),
	"passwords calibrate": cliOnly("measures the host it runs on"),
	"keys rewrap-root":    cliOnly("handles the root key itself, which never reaches the API"),

	// Declarative configuration: files read and applied from where they are kept.
	"plan":  reads,
	"apply": "POST /admin/organizations/{orgID}/config",

	// Instances and organisations.
	"instance create":            cliOnly("a new issuer is a deployment decision, made where its root key is"),
	"instance add-alias":         "POST /admin/instances/{instanceID}/issuer-aliases",
	"instance retire-alias":      "PATCH /admin/instances/{instanceID}/issuer-aliases",
	"instance aliases":           reads,
	"instance session-limit":     orgSettings,
	"instance remember-device":   orgSettings,
	"instance org-status":        "PATCH /admin/organizations/{orgID}",
	"instance org-delete":        cliOnly("deleting an organisation is done with the database in front of you, two-phase, as admin-api.md says"),
	"instance org-budgets":       "PUT /admin/organizations/{orgID}/budgets",
	"instance new-device-notice": orgSettings,
	"instance reauth-window":     orgSettings,
	"instance session-lifetime":  orgSettings,
	"instance password-binds":    orgSettings,
	"instance related-origins":   "PUT /admin/instances/{instanceID}/webauthn",
	"instance webauthn":          "PUT /admin/instances/{instanceID}/webauthn",
	"instance sms-numbers":       orgSettings,
	"instance totp-policy":       orgSettings,
	"instance login-throttle":    orgSettings,

	// People.
	"user create":        "POST /admin/users",
	"user locale":        "PATCH /admin/users/{userID}",
	"user remove-factor": "DELETE /admin/users/{userID}/factors/{kind}",
	"user passkey-link":  "POST /admin/users/{userID}/passkey-link",
	"user approve":       "PATCH /admin/users/{userID}",
	"user unlock":        "DELETE /admin/users/{userID}/throttle",
	"user assign-otp":    cliOnly("reads a seed file from the operator's disk, the hardware token's, which should not cross a network"),
	"erase subject":      "POST /admin/subjects/{subjectID}/erase",
	"export subject":     "GET /admin/subjects/{subjectID}/export",
	"export audit":       reads,
	"export org":         reads,
	"invite create":      "POST /admin/invitations",
	"invite list":        reads,
	"invite revoke":      "DELETE /admin/invitations/{invitationID}",
	"signup enable":      "PUT /admin/organizations/{orgID}/signup",
	"signup disable":     "DELETE /admin/organizations/{orgID}/signup",
	"signup show":        reads,
	"import keycloak":    cliOnly("reads another product's export from the operator's disk"),
	"import authentik":   cliOnly("reads another product's export from the operator's disk"),
	"import shadow":      cliOnly("reads /etc/shadow from the operator's disk"),

	// Groups.
	"group create":        "POST /admin/groups",
	"group list":          reads,
	"group member":        "PUT /admin/groups/{groupID}/members/{userID}",
	"group release":       "PUT /admin/clients/{clientID}/group-release",
	"group impersonation": cliOnly("deliberately not in the Admin API: a groups:write token must not be able to make anyone able to act as anyone"),

	// Applications.
	"client create":                   "POST /admin/clients",
	"client set-keys":                 "PATCH /admin/clients/{clientID}",
	"client set-tls":                  "PATCH /admin/clients/{clientID}",
	"client set-dpop":                 "PATCH /admin/clients/{clientID}",
	"client set-pkce":                 "PATCH /admin/clients/{clientID}",
	"client set-logout":               "PATCH /admin/clients/{clientID}",
	"client set-lifetimes":            "PATCH /admin/clients/{clientID}",
	"client set-alg":                  "PATCH /admin/clients/{clientID}",
	"client set-issuer-alias":         "PATCH /admin/clients/{clientID}",
	"client set-par":                  "PATCH /admin/clients/{clientID}",
	"client set-admin-api":            "PATCH /admin/clients/{clientID}",
	"client set-first-party":          "PATCH /admin/clients/{clientID}",
	"client set-acr":                  "PATCH /admin/clients/{clientID}",
	"client set-exchange":             "PATCH /admin/clients/{clientID}",
	"client set-exchange-containment": "PATCH /admin/clients/{clientID}",
	"client set-hybrid":               "PATCH /admin/clients/{clientID}",
	"client set-claims-redirects":     "PATCH /admin/clients/{clientID}",
	"client set-grants":               "PATCH /admin/clients/{clientID}",
	"client set-ciba":                 "PATCH /admin/clients/{clientID}",
	"client set-assertion-issuers":    "PATCH /admin/clients/{clientID}",
	"registration enable":             "PUT /admin/organizations/{orgID}/registration",
	"registration token":              "POST /admin/organizations/{orgID}/registration-tokens",
	"registration revoke":             "DELETE /admin/organizations/{orgID}/registration-tokens/{tokenID}",
	"resource add":                    "PUT /admin/organizations/{orgID}/resource-servers",
	"resource list":                   reads,
	"resource remove":                 "DELETE /admin/organizations/{orgID}/resource-servers",
	"logout-test":                     cliOnly("runs a relying party on the operator's host to watch a logout arrive"),

	// Credentials (OID4VCI).
	"credential define":       pending,
	"credential list":         reads,
	"credential offer":        pending,
	"credential trust-root":   pending,
	"credential roots":        reads,
	"credential untrust-root": pending,

	// Keys and the audit trail.
	"keys list":        reads,
	"keys rotate":      "POST /admin/instances/{instanceID}/keys/rotate",
	"keys retire":      "POST /admin/instances/{instanceID}/keys/retire",
	"audit checkpoint": cliOnly("anchors the chain from the host, signed by whoever runs it"),
	"audit verify":     reads,
	"audit archive":    cliOnly("writes a file on the operator's disk"),

	// Administration.
	"admin-token create": "POST /admin/tokens",
	"admin-token list":   reads,
	"admin-token revoke": "DELETE /admin/tokens/{tokenID}",
	"role grant":         "POST /admin/organizations/{orgID}/role-bindings",
	"role list":          reads,
	"role revoke":        "DELETE /admin/organizations/{orgID}/role-bindings/{bindingID}",

	// Upstream providers.
	"idp add":            "POST /admin/organizations/{orgID}/identity-providers",
	"idp disable":        "PATCH /admin/organizations/{orgID}/identity-providers/{slug}",
	"idp enable":         "PATCH /admin/organizations/{orgID}/identity-providers/{slug}",
	"idp list":           reads,
	"idp assertions":     "PATCH /admin/organizations/{orgID}/identity-providers/{slug}",
	"idp link":           "PUT /admin/users/{userID}/identity-links/{slug}",
	"idp unlink":         "DELETE /admin/users/{userID}/identity-links/{slug}",
	"idp links":          reads,
	"idp add-issuer":     "POST /admin/organizations/{orgID}/identity-providers",
	"idp apple-secret":   cliOnly("signs with the .p8 key Apple issued, read from the operator's disk"),
	"idp trust-mfa":      "PATCH /admin/organizations/{orgID}/identity-providers/{slug}",
	"idp verified-email": "PATCH /admin/organizations/{orgID}/identity-providers/{slug}",
	"idp attribute-map":  "PUT /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map",

	// SAML service providers.
	"saml add-sp":            "POST /admin/organizations/{orgID}/saml-providers",
	"saml list":              reads,
	"saml attribute-release": "PUT /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release",
	"saml signing":           "PATCH /admin/organizations/{orgID}/saml-providers/{providerID}",
	"saml group-release":     "PUT /admin/organizations/{orgID}/saml-providers/{providerID}/group-release",

	// Provisioning and directories.
	"scim-source add":          "POST /admin/organizations/{orgID}/scim-sources",
	"scim-source disable":      "PATCH /admin/organizations/{orgID}/scim-sources/{slug}",
	"scim-source enable":       "PATCH /admin/organizations/{orgID}/scim-sources/{slug}",
	"scim-source list":         reads,
	"scim add":                 "POST /admin/organizations/{orgID}/scim-targets",
	"scim enable":              "PATCH /admin/organizations/{orgID}/scim-targets/{slug}",
	"scim disable":             "PATCH /admin/organizations/{orgID}/scim-targets/{slug}",
	"scim list":                reads,
	"scim scope":               "PATCH /admin/organizations/{orgID}/scim-targets/{slug}",
	"scim provision-group":     "PUT /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}",
	"scim deprovision-group":   "DELETE /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}",
	"scim sync":                "POST /admin/organizations/{orgID}/scim-targets/{slug}/sync",
	"scim verify":              reads,
	"provision add":            "POST /admin/organizations/{orgID}/scim-targets",
	"dir add":                  "POST /admin/organizations/{orgID}/directories",
	"dir list":                 reads,
	"dir group-map":            "PUT /admin/organizations/{orgID}/directories/{slug}/group-map",
	"dir set":                  "PATCH /admin/organizations/{orgID}/directories/{slug}",
	"dir sync":                 "POST /admin/organizations/{orgID}/directories/{slug}/sync",
	"kerberos sync":            cliOnly("asks the realm's admin server with a keytab on the operator's host"),
	"kerberos check":           reads,
	"kerberos principals":      reads,
	"migration-source add":     "PUT /admin/organizations/{orgID}/migration-source",
	"migration-source enable":  "PUT /admin/organizations/{orgID}/migration-source",
	"migration-source disable": "PUT /admin/organizations/{orgID}/migration-source",
	"migration-source show":    reads,
	"migration-source remove":  "DELETE /admin/organizations/{orgID}/migration-source",

	// Signals and events.
	"ssf add-stream":   "POST /admin/organizations/{orgID}/ssf-streams",
	"ssf set-status":   "PATCH /admin/clients/{clientID}/ssf-stream",
	"ssf add-source":   "PUT /admin/organizations/{orgID}/ssf-sources",
	"ssf list":         reads,
	"ssf received":     reads,
	"events subscribe": "POST /admin/organizations/{orgID}/event-subscriptions",
	"events remove":    "DELETE /admin/organizations/{orgID}/event-subscriptions/{name}",
	"events rotate":    "POST /admin/organizations/{orgID}/event-subscriptions/{name}/rotate-secret",
	"events enable":    "POST /admin/organizations/{orgID}/event-subscriptions/{name}/enable",
	"events list":      reads,
	"events test":      "POST /admin/organizations/{orgID}/event-subscriptions/{name}/test",

	// Authorization, federation and UMA.
	"authz set-model":     "PUT /admin/organizations/{orgID}/authorization-model",
	"authz show-model":    reads,
	"authz grant":         "PUT /admin/organizations/{orgID}/relations",
	"authz revoke":        "DELETE /admin/organizations/{orgID}/relations",
	"authz check":         reads,
	"trust-mark issue":    "POST /admin/instances/{instanceID}/trust-marks",
	"trust-mark revoke":   "POST /admin/instances/{instanceID}/trust-marks/revoke",
	"trust-mark list":     reads,
	"trust-mark accept":   "PUT /admin/instances/{instanceID}/held-trust-marks",
	"trust-mark drop":     "DELETE /admin/instances/{instanceID}/held-trust-marks",
	"trust-mark delegate": "POST /admin/instances/{instanceID}/trust-mark-delegations",
	"trust-mark owners":   reads,
	"trust-mark issuers":  reads,
	"federation enable":   "PUT /admin/instances/{instanceID}/federation",
	"federation show":     reads,
	"uma settings":        "PUT /admin/organizations/{orgID}/uma",
	"uma requests":        reads,
	"uma approve":         "POST /admin/organizations/{orgID}/uma/requests/{requestID}/approve",
	"uma deny":            "POST /admin/organizations/{orgID}/uma/requests/{requestID}/deny",
	"rar register":        "PUT /admin/organizations/{orgID}/authorization-detail-types",
	"rar allow":           "PATCH /admin/clients/{clientID}",
	"rar list":            reads,

	// Extension hooks and outposts.
	"provider add":         "PUT /admin/organizations/{orgID}/providers/{hook}",
	"provider list":        reads,
	"provider claims":      "PUT /admin/organizations/{orgID}/providers/{hook}/claims",
	"provider remove":      "DELETE /admin/organizations/{orgID}/providers/{hook}",
	"provider rotate":      "POST /admin/organizations/{orgID}/providers/{hook}/rotate-secret",
	"outpost create":       "POST /admin/organizations/{orgID}/outposts",
	"outpost disable":      "PATCH /admin/organizations/{orgID}/outposts/{name}",
	"outpost enable":       "PATCH /admin/organizations/{orgID}/outposts/{name}",
	"outpost list":         reads,
	"outpost search-group": "PATCH /admin/organizations/{orgID}/outposts/{name}",
	"outpost run":          cliOnly("runs an outpost, which holds no database credentials"),
	"attester add":         "PUT /admin/organizations/{orgID}/attesters/{name}",
	"attester list":        reads,

	// Network access.
	"radius add-client":     "POST /admin/organizations/{orgID}/radius-clients",
	"radius authorize":      "PUT /admin/groups/{groupID}/radius",
	"radius disable-client": "PATCH /admin/organizations/{orgID}/radius-clients/{deviceID}",
	"radius enable-client":  "PATCH /admin/organizations/{orgID}/radius-clients/{deviceID}",
	"radius list":           reads,
	"proxy check":           reads,
	"proxy add-host":        "PUT /admin/organizations/{orgID}/proxy-hosts",
	"proxy disable-host":    "PUT /admin/organizations/{orgID}/proxy-hosts",
	"proxy enable-host":     "PUT /admin/organizations/{orgID}/proxy-hosts",
	"proxy remove-host":     "DELETE /admin/organizations/{orgID}/proxy-hosts/{host}",
	"proxy list":            reads,
	// Except -recording-path and a parameter naming a path, which choose where
	// the machine guacd runs on writes and stay with the command.
	"rac add":            "POST /admin/organizations/{orgID}/rac-connections",
	"rac disable":        "PATCH /admin/organizations/{orgID}/rac-connections/{slug}",
	"rac enable":         "PATCH /admin/organizations/{orgID}/rac-connections/{slug}",
	"rac list":           reads,
	"rac set-parameters": "PATCH /admin/organizations/{orgID}/rac-connections/{slug}",

	// Policy, flows, prompts and appearance.
	"policy apply":    "PUT /admin/organizations/{orgID}/access-policy",
	"policy show":     reads,
	"policy test":     reads,
	"policy graph":    reads,
	"flow apply":      "PUT /admin/organizations/{orgID}/sign-in-flow",
	"flow show":       reads,
	"flow test":       reads,
	"flow paths":      reads,
	"prompt set":      "PUT /admin/organizations/{orgID}/prompts/{slug}",
	"prompt list":     reads,
	"prompt enable":   "PATCH /admin/organizations/{orgID}/prompts/{slug}",
	"prompt disable":  "PATCH /admin/organizations/{orgID}/prompts/{slug}",
	"brand set":       "PUT /admin/instances/{instanceID}/brand",
	"brand show":      reads,
	"brand check":     reads,
	"theme eject":     cliOnly("writes the built-in pages to the operator's disk"),
	"theme check":     reads,
	"theme list":      reads,
	"i18n list":       reads,
	"i18n status":     reads,
	"i18n keys":       reads,
	"webauthn policy": "PUT /admin/organizations/{orgID}/webauthn-policy",
	"webauthn show":   reads,
	"duo set":         "PUT /admin/organizations/{orgID}/duo",
	"duo show":        reads,
	"duo enroll":      "PUT /admin/users/{userID}/duo",
}

func TestEveryCLIWriteHasAnAdminAPIRoute(t *testing.T) {
	root := repoRoot(t)
	dispatched := dispatchedCommands(t, readSource(t, filepath.Join(root, "engine", "cmd", "signari", "main.go")))
	routes := adminRoutes(t, root)

	var unplaced, stale, unrouted, open []string
	for cmd := range dispatched {
		if _, ok := cliAPI[cmd]; !ok {
			unplaced = append(unplaced, cmd)
		}
	}
	for cmd, where := range cliAPI {
		switch {
		case !dispatched[cmd]:
			stale = append(stale, cmd)
		case where == pending:
			open = append(open, cmd)
		case where == reads, strings.HasPrefix(where, "command only: ") && len(where) > len("command only: "):
		case !routes[where]:
			unrouted = append(unrouted, cmd+" -> "+where)
		}
	}
	for _, l := range [][]string{unplaced, stale, unrouted, open} {
		sort.Strings(l)
	}
	for _, c := range unplaced {
		t.Errorf("%q is a command and is not in cliAPI: say which Admin API route makes the same "+
			"change, that it only reads, or why it stays a command", c)
	}
	for _, c := range stale {
		t.Errorf("cliAPI places %q, which main.go does not dispatch", c)
	}
	for _, c := range unrouted {
		t.Errorf("cliAPI says %s, and the admin router registers no such route", c)
	}
	if len(open) > 0 {
		t.Logf("%d command writes have no Admin API route yet:\n  %s", len(open), strings.Join(open, "\n  "))
	}
}
