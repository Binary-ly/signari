package adminapi

import (
	"net/url"
	"testing"
)

// readRoute is a GET with a path that answers 200, for the schema drift test:
// the counterpart of allMutatingRoutes for reads.
type readRoute struct {
	name string
	path func(t *testing.T, s *Server) string
}

func allReadRoutes() []readRoute {
	org := func(rest string) func(t *testing.T, s *Server) string {
		return func(t *testing.T, s *Server) string { return "/admin/organizations/" + anyOrgID(t, s) + rest }
	}
	return []readRoute{
		{"GET /admin/audit-events", func(*testing.T, *Server) string { return "/admin/audit-events?limit=5" }},
		{"GET /admin/clients", func(*testing.T, *Server) string { return "/admin/clients?limit=5" }},
		{"GET /admin/clients/{clientID}", func(t *testing.T, s *Server) string {
			return "/admin/clients/" + url.PathEscape(newPreconditionClient(t, s))
		}},
		{"GET /admin/clients/{clientID}/group-release", func(t *testing.T, s *Server) string {
			return "/admin/clients/" + url.PathEscape(newPreconditionClient(t, s)) + "/group-release"
		}},
		{"GET /admin/instances", func(*testing.T, *Server) string { return "/admin/instances" }},
		{"GET /admin/instances/{instanceID}/brand", func(t *testing.T, s *Server) string {
			return "/admin/instances/" + newDriftInstance(t, s) + "/brand"
		}},
		{"GET /admin/instances/{instanceID}/webauthn", func(t *testing.T, s *Server) string {
			return "/admin/instances/" + newDriftInstance(t, s) + "/webauthn"
		}},
		{"GET /admin/instances/{instanceID}/issuer-aliases", func(t *testing.T, s *Server) string {
			return "/admin/instances/" + newDriftInstance(t, s) + "/issuer-aliases"
		}},
		{"GET /admin/config-version", func(*testing.T, *Server) string { return "/admin/config-version" }},
		{"GET /admin/groups", func(*testing.T, *Server) string { return "/admin/groups?limit=5" }},
		{"GET /admin/groups/{groupID}", func(t *testing.T, s *Server) string { return "/admin/groups/" + newDriftGroup(t, s) }},
		{"GET /admin/groups/{groupID}/members", func(t *testing.T, s *Server) string {
			return "/admin/groups/" + newDriftGroup(t, s) + "/members"
		}},
		{"GET /admin/invitations", func(*testing.T, *Server) string { return "/admin/invitations" }},
		{"GET /admin/me", func(*testing.T, *Server) string { return "/admin/me" }},
		{"GET /admin/organizations", func(*testing.T, *Server) string { return "/admin/organizations" }},
		{"GET /admin/organizations/{orgID}", org("")},
		{"GET /admin/organizations/{orgID}/attributes", org("/attributes")},
		{"GET /admin/organizations/{orgID}/budgets", org("/budgets")},
		{"GET /admin/organizations/{orgID}/settings", org("/settings")},
		{"GET /admin/organizations/{orgID}/signup", org("/signup")},
		{"GET /admin/organizations/{orgID}/registration", org("/registration")},
		{"GET /admin/organizations/{orgID}/prompts", org("/prompts")},
		{"GET /admin/organizations/{orgID}/registration-tokens", org("/registration-tokens")},
		{"GET /admin/organizations/{orgID}/claim-mappers", org("/claim-mappers")},
		{"GET /admin/organizations/{orgID}/migration-source", func(t *testing.T, s *Server) string {
			return "/admin/organizations/" + newDriftMigrationOrg(t, s, true) + "/migration-source"
		}},
		{"GET /admin/organizations/{orgID}/proxy-hosts", org("/proxy-hosts")},
		{"GET /admin/organizations/{orgID}/resource-servers", org("/resource-servers")},
		{"GET /admin/organizations/{orgID}/role-bindings", func(t *testing.T, s *Server) string {
			newDriftBinding(t, s, "auditor")
			return "/admin/organizations/" + anyOrgID(t, s) + "/role-bindings"
		}},
		{"GET /admin/organizations/{orgID}/scopes", org("/scopes")},
		{"GET /admin/organizations/{orgID}/webauthn-policy", org("/webauthn-policy")},
		{"GET /admin/subjects/{subjectID}/export", func(t *testing.T, s *Server) string {
			return "/admin/subjects/" + newDriftUser(t, s) + "/export"
		}},
		{"GET /admin/system", func(*testing.T, *Server) string { return "/admin/system" }},
		{"GET /admin/tokens", func(*testing.T, *Server) string { return "/admin/tokens" }},
		{"GET /admin/users", func(*testing.T, *Server) string { return "/admin/users?limit=5" }},
		{"GET /admin/users/{userID}", func(t *testing.T, s *Server) string { return "/admin/users/" + newDriftUser(t, s) }},
		{"GET /admin/users/{userID}/attributes", func(t *testing.T, s *Server) string {
			return "/admin/users/" + newDriftUserWithAttribute(t, s) + "/attributes"
		}},
		{"GET /admin/users/{userID}/factors", func(t *testing.T, s *Server) string {
			return "/admin/users/" + newDriftUserWithTOTP(t, s) + "/factors"
		}},
		{"GET /admin/users/{userID}/consents", func(t *testing.T, s *Server) string {
			return "/admin/users/" + newDriftUser(t, s) + "/consents"
		}},
		{"GET /admin/users/{userID}/sessions", func(t *testing.T, s *Server) string {
			u := newDriftUser(t, s)
			newDriftSession(t, s, u)
			return "/admin/users/" + u + "/sessions"
		}},
	}
}
