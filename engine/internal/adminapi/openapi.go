package adminapi

import (
	"encoding/json"
	"net/http"
	"sort"
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
// Not derived: request and response schemas. Those live in Go structs, and
// reflecting over them would produce a document that describes the JSON tags
// rather than the meaning — `{"active": true}` with no hint that omitting the
// field is different from sending false. The descriptions here are written, and
// `TestEveryAdminAPIRouteIsDocumented` keeps the prose in `docs/admin-api.md`
// aligned with the same route table. Two derivations from one source beats one
// derivation and one memory.

// operation is one method on one path.
type operation struct {
	method  string
	path    string
	scope   string
	summary string
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
	"PATCH /admin/clients/{clientID}":                        "Enable or disable a client.",
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
	"POST /admin/organizations":                              "Provision a tenant. Requires an unscoped token.",
	"POST /admin/subjects/{subjectID}/erase":                 "Crypto-shred a subject. Permanent.",
	"GET /admin/audit-events":                                "Read the audit trail. Does not verify the hash chain.",
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

		entry := map[string]any{
			"summary":     op.summary,
			"operationId": operationID(op),
			"security":    []any{map[string]any{"bearerAuth": []any{op.scope}}},
			"responses": map[string]any{
				"200": map[string]any{"description": "Success."},
				"401": map[string]any{"description": "No usable bearer token."},
				"403": map[string]any{"description": "The token lacks " + op.scope + ", or is scoped to another organisation."},
			},
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
			resp["412"] = map[string]any{
				"description": "The configuration version moved; nothing was written.",
			}
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
