package httpapi

import (
	"context"
	"net/http"
	"strings"

	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// SCIM schema discovery, RFC 7644 §4.
//
//	"/Schemas: An HTTP GET to this endpoint is used to retrieve information
//	about resource schemas supported by a SCIM service provider. An HTTP GET to
//	the endpoint "/Schemas" SHALL return all supported schemas in ListResponse
//	format... Individual schema definitions can be returned by appending the
//	schema URI to the /Schemas endpoint."
//
// This endpoint did not exist. §4 names three discovery endpoints and we served
// two, so a provisioning client doing the ordinary thing -- fetch
// /ServiceProviderConfig, /ResourceTypes and /Schemas before its first sync --
// got a 404 on the one that tells it which attributes it may send.
//
// # The schemas describe what we actually store
//
// Not RFC 7643's example documents. Publishing the full core User schema would
// advertise `name.givenName`, `phoneNumbers`, `addresses`, `photos` and a dozen
// more attributes this engine does not persist -- and a client reading that
// document would map them, send them, and watch them vanish.
//
// So each attribute listed here is one `scimUserResource` or
// `scimGroupResource` actually returns. That is the same rule this project
// applies to OIDC discovery and to the SSF and OID4VCI metadata documents: a
// capability enters a discovery document once it works.
const (
	schemaURIUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaURIGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

func attr(name, typ string, multi bool, opts ...func(map[string]any)) map[string]any {
	a := map[string]any{
		"name":        name,
		"type":        typ,
		"multiValued": multi,
		"required":    false,
		"caseExact":   false,
		"mutability":  "readWrite",
		"returned":    "default",
		"uniqueness":  "none",
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

func required(a map[string]any)     { a["required"] = true }
func readOnly(a map[string]any)     { a["mutability"] = "readOnly" }
func serverUnique(a map[string]any) { a["uniqueness"] = "server" }

// caseExact says what a filter does (specs/rfc7644.txt:1216, it "SHALL be
// determined by the attribute's "caseExact" characteristic"). An upstream's
// identifier is opaque and matched as stored: `ab` and `AB` are two people.
func caseExact(a map[string]any) { a["caseExact"] = true }
func subAttrs(subs ...map[string]any) func(map[string]any) {
	return func(a map[string]any) { a["subAttributes"] = subs }
}

func scimSchemaDefinitions() []map[string]any {
	return []map[string]any{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          schemaURIUser,
			"name":        "User",
			"description": "User Account",
			"attributes": []map[string]any{
				attr("userName", "string", false, required, serverUnique),
				attr("externalId", "string", false, caseExact),
				attr("displayName", "string", false),
				attr("active", "boolean", false),
				attr("emails", "complex", true, subAttrs(
					attr("value", "string", false),
					attr("primary", "boolean", false),
				)),
			},
			"meta": map[string]any{
				"resourceType": "Schema",
				"location":     "/scim/v2/Schemas/" + schemaURIUser,
			},
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          schemaURIGroup,
			"name":        "Group",
			"description": "Group",
			"attributes": []map[string]any{
				attr("displayName", "string", false, required),
				attr("externalId", "string", false, caseExact),
				attr("members", "complex", true, subAttrs(
					attr("value", "string", false),
					attr("display", "string", false, readOnly),
					attr("$ref", "reference", false),
				)),
			},
			"meta": map[string]any{
				"resourceType": "Schema",
				"location":     "/scim/v2/Schemas/" + schemaURIGroup,
			},
		},
	}
}

// scimEnterpriseSchema is the extension as this organisation can hold it, nil
// when it declares none of the attributes: the rule above, per organisation, so
// that a client is not told a department is kept where it would vanish.
func (s *Server) scimEnterpriseSchema(ctx context.Context, src *store.SCIMSource) map[string]any {
	declared, err := store.DeclaredSCIMEnterprise(ctx, s.db, src.OrgID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading what the SCIM enterprise extension can hold", "err", err)
		return nil
	}
	if len(declared) == 0 {
		return nil
	}
	attributes := make([]map[string]any, 0, len(declared))
	for _, name := range declared {
		if name == "manager" {
			attributes = append(attributes, attr(name, "complex", false, subAttrs(attr("value", "string", false))))
			continue
		}
		attributes = append(attributes, attr(name, "string", false))
	}
	return map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"id":          scim.EnterpriseSchema,
		"name":        "EnterpriseUser",
		"description": "Enterprise User",
		"attributes":  attributes,
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/scim/v2/Schemas/" + scim.EnterpriseSchema,
		},
	}
}

// handleSCIMSchemas serves /Schemas and /Schemas/{id}.
func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	src, err := s.scimAuth(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !discoveryQueryOK(w, r) {
		return
	}

	defs := scimSchemaDefinitions()
	if extension := s.scimEnterpriseSchema(r.Context(), src); extension != nil {
		defs = append(defs, extension)
	}

	// An individual schema by URI: "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User".
	if id := strings.TrimPrefix(r.PathValue("id"), "/"); id != "" {
		for _, d := range defs {
			if d["id"] == id {
				// §4: "the single JSON object is returned in the same way that a
				// single User or Group is retrieved" -- not wrapped in a
				// ListResponse.
				writeSCIM(w, http.StatusOK, d)
				return
			}
		}
		writeSCIMError(w, http.StatusNotFound, "no schema "+id)
		return
	}

	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(defs),
		"itemsPerPage": len(defs),
		"startIndex":   1,
		"Resources":    defs,
	})
}

// discoveryQueryOK applies §4's rule about query parameters on the discovery
// endpoints, and reports whether the caller should continue.
//
//	"Query parameters described in Section 3.4.2, such as filtering, sorting,
//	and pagination, SHALL be ignored. If a "filter" is provided, the service
//	provider SHOULD respond with HTTP status code 403 (Forbidden) to ensure that
//	clients cannot incorrectly assume that any matching conditions specified in
//	a filter are true."
//
// The reasoning in that sentence is the whole point, and it is a good one: a
// client that filters and receives 200 with every resource concludes they all
// matched. Silently ignoring the filter is the failure mode -- 403 is the only
// answer that cannot be misread.
func discoveryQueryOK(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Query().Get("filter") != "" {
		writeSCIMError(w, http.StatusForbidden,
			"filtering is not supported on the discovery endpoints (RFC 7644 §4); "+
				"a filtered response here would let you assume the results matched")
		return false
	}
	return true
}
