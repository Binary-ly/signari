package adminapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
)

// Typed request and response schemas for every operation (6.02).
//
// Requests are derived from the Go type each handler decodes into, so the
// document cannot describe a field the handler does not read. Responses are
// declared here, because most handlers answer with maps; what keeps a
// declaration honest is TestEveryResponseMatchesItsSchema, which calls every
// route through a fixture and holds the body to its schema, an undeclared
// field included. This document carried paths, methods and scopes only, so a
// generated client knew where to send a request and nothing of what to send
// or what came back.

// jsonSchema is a JSON Schema object, the subset OpenAPI 3.1 takes.
type jsonSchema = map[string]any

func str() jsonSchema      { return jsonSchema{"type": "string"} }
func boolean() jsonSchema  { return jsonSchema{"type": "boolean"} }
func integer() jsonSchema  { return jsonSchema{"type": "integer"} }
func dateTime() jsonSchema { return jsonSchema{"type": "string", "format": "date-time"} }
func uuidStr() jsonSchema  { return jsonSchema{"type": "string", "format": "uuid"} }
func anyValue() jsonSchema { return jsonSchema{} }
func openObject() jsonSchema {
	return jsonSchema{"type": "object", "additionalProperties": true}
}
func arrayOf(item jsonSchema) jsonSchema { return jsonSchema{"type": "array", "items": item} }
func mapOf(value jsonSchema) jsonSchema {
	return jsonSchema{"type": "object", "additionalProperties": value}
}

// nullable admits JSON null as well.
func nullable(s jsonSchema) jsonSchema {
	out := jsonSchema{}
	for k, v := range s {
		out[k] = v
	}
	if t, ok := s["type"].(string); ok {
		out["type"] = []any{t, "null"}
	}
	return out
}

// object is a closed object: its properties, the named ones required, nothing
// else. Closed, so a field a handler starts sending without its schema is a
// failing test rather than something a generated client silently drops.
func object(required []string, props map[string]jsonSchema) jsonSchema {
	p := map[string]any{}
	for k, v := range props {
		p[k] = v
	}
	s := jsonSchema{"type": "object", "properties": p, "additionalProperties": false}
	if len(required) > 0 {
		r := make([]any, len(required))
		for i, k := range required {
			r[i] = k
		}
		s["required"] = r
	}
	return s
}

// with adds config_version, which every write answers with, to props.
func withVersion(props map[string]jsonSchema) map[string]jsonSchema {
	props["config_version"] = integer()
	return props
}

// requestSchema derives a body's schema from the type its handler decodes.
// Every field is optional: a pointer is "absent leaves it as it is", and the
// handler names what it requires when it refuses.
func requestSchema(t reflect.Type) jsonSchema {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(json.RawMessage(nil)) {
		return anyValue()
	}
	switch t.Kind() {
	case reflect.String:
		return str()
	case reflect.Bool:
		return boolean()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return integer()
	case reflect.Float32, reflect.Float64:
		return jsonSchema{"type": "number"}
	case reflect.Slice, reflect.Array:
		return arrayOf(requestSchema(t.Elem()))
	case reflect.Map:
		return mapOf(requestSchema(t.Elem()))
	case reflect.Struct:
		props := map[string]jsonSchema{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			props[name] = requestSchema(f.Type)
		}
		return object(nil, props)
	}
	return anyValue()
}

// opSchema is one operation's contract: the success status, the body the
// handler decodes (nil for none) and what it answers (nil for no body).
type opSchema struct {
	Status   int
	Request  reflect.Type
	Response jsonSchema
}

func typeOf[T any]() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

// The shapes several operations share.
var (
	clientSummarySchema = object([]string{"client_id", "org_id", "display_name", "client_type", "enabled", "created_at"},
		map[string]jsonSchema{"client_id": str(), "org_id": uuidStr(), "display_name": str(),
			"client_type": str(), "enabled": boolean(), "created_at": dateTime()})
	userSummarySchema = object([]string{"id", "org_id", "email", "username", "status", "created_at"},
		map[string]jsonSchema{"id": uuidStr(), "org_id": uuidStr(), "email": str(), "username": str(),
			"status": str(), "created_at": dateTime()})
	groupSummarySchema = object([]string{"id", "org_id", "name", "display_name", "description", "may_impersonate", "created_at"},
		map[string]jsonSchema{"id": uuidStr(), "org_id": uuidStr(), "name": str(), "display_name": str(),
			"description": str(), "may_impersonate": boolean(), "created_at": dateTime()})
	organizationSchema = object([]string{"id", "instance_id", "slug", "display_name", "status", "created_at"},
		map[string]jsonSchema{"id": uuidStr(), "instance_id": uuidStr(), "slug": str(), "display_name": str(),
			"status": str(), "created_at": dateTime()})
	webauthnPolicySchema = map[string]jsonSchema{
		"algorithms": arrayOf(integer()), "allowed_aaguids": arrayOf(str()), "attachment": str(),
		"attestation": str(), "hints": arrayOf(str()), "refuse_cloned": boolean(), "resident_key": str(),
		"timeout_seconds": integer(), "user_verification": str()}
	migrationSourceSchema = object([]string{"kind", "display_name", "url", "has_client_secret", "start_tls",
		"has_ca", "enabled", "delegated_successes", "delegated_failures", "users_pending", "users_migrated"},
		map[string]jsonSchema{"kind": str(), "display_name": str(), "url": str(), "client_id": str(),
			"has_client_secret": boolean(), "scope": str(), "bind_dn_template": str(), "start_tls": boolean(),
			"has_ca": boolean(), "enabled": boolean(), "delegated_successes": integer(),
			"delegated_failures": integer(), "last_error": str(), "users_pending": integer(),
			"users_migrated": integer()})
	// A client's whole configuration, every column but the secret hashes.
	clientConfigSchema = object([]string{"client_id", "org_id", "display_name", "client_type", "enabled",
		"redirect_uris", "grant_types", "scopes", "created_at"},
		map[string]jsonSchema{
			"access_token_ttl_s": integer(), "admin_api": boolean(), "allow_hybrid": boolean(),
			"backchannel_client_notification_endpoint": nullable(str()),
			"backchannel_logout_session_required":      boolean(), "backchannel_logout_uri": nullable(str()),
			"backchannel_token_delivery_mode": str(), "claims_redirect_uris": nullable(arrayOf(str())),
			"client_id": str(), "client_type": str(), "consent_lifetime_s": nullable(integer()),
			"created_at": dateTime(), "display_name": str(), "dpop_bound_access_tokens": boolean(),
			"dynamically_registered": boolean(), "enabled": boolean(), "exchange_audiences": arrayOf(str()),
			"exchange_requires_audience_match": boolean(), "first_party": boolean(),
			"frontchannel_logout_session_required": boolean(), "frontchannel_logout_uri": nullable(str()),
			"grant_types": arrayOf(str()), "hybrid_review_by": nullable(str()), "id_token_signed_alg": str(),
			"initiate_login_uri": nullable(str()), "issuer_alias": nullable(str()),
			"jwks": nullable(openObject()), "jwt_bearer_providers": arrayOf(str()), "logo_uri": nullable(str()),
			"may_exchange": boolean(), "minimum_acr": str(), "org_id": uuidStr(), "portal_hidden": boolean(),
			"redirect_uris": arrayOf(str()), "refresh_token_ttl_s": integer(),
			"registered_at": nullable(dateTime()), "require_pkce": boolean(),
			"require_pushed_authorization": boolean(), "response_types": arrayOf(str()),
			"scopes": arrayOf(str()), "tls_bound_tokens": boolean(), "tls_san_dns": nullable(str()),
			"tls_san_email": nullable(str()), "tls_san_ip": nullable(str()), "tls_san_uri": nullable(str()),
			"tls_subject_dn": nullable(str()), "tls_thumbprint": nullable(str()),
			"token_endpoint_auth_method": str()})
	sessionsEndedSchema = map[string]jsonSchema{"sessions_ended": integer(), "notices_queued": integer()}
)

// errorSchema is every refusal's body: a code to branch on and words to read.
var errorSchema = object([]string{"error"}, map[string]jsonSchema{
	"error": str(), "detail": str(), "expected_version": integer(), "current_version": integer(),
	// A refused batch: which operation, what it answered.
	"failed_index": integer(), "status": integer(), "response": anyValue()})

func merge(maps ...map[string]jsonSchema) map[string]jsonSchema {
	out := map[string]jsonSchema{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// opSchemas is every operation's contract, by pattern.
// TestEveryOperationHasASchema derives the list from the router.
var opSchemas = map[string]opSchema{
	"GET /admin/audit-events": {http.StatusOK, nil, object([]string{"events", "chain_verified"}, map[string]jsonSchema{
		"chain_note": str(), "chain_verified": boolean(), "next_cursor": str(),
		"events": arrayOf(object([]string{"id", "org_id", "occurred_at", "event_type"}, map[string]jsonSchema{
			"id": str(), "org_id": nullable(uuidStr()), "occurred_at": dateTime(), "event_type": str(),
			"subject_id": str(), "actor_id": str(), "client_id": str(), "correlation_id": str(),
			"retention_class": str(), "admin_token_id": str(), "detail": openObject()}))})},
	"GET /admin/clients": {http.StatusOK, nil, object([]string{"clients", "next_cursor"}, map[string]jsonSchema{
		"clients": arrayOf(clientSummarySchema), "next_cursor": str()})},
	"GET /admin/clients/{clientID}": {http.StatusOK, nil, clientConfigSchema},
	"GET /admin/config-version":     {http.StatusOK, nil, object([]string{"config_version"}, map[string]jsonSchema{"config_version": integer()})},
	"GET /admin/groups": {http.StatusOK, nil, object([]string{"groups"}, map[string]jsonSchema{
		"groups": arrayOf(groupSummarySchema), "next_cursor": str()})},
	"GET /admin/groups/{groupID}": {http.StatusOK, nil, groupSummarySchema},
	"GET /admin/groups/{groupID}/members": {http.StatusOK, nil, object([]string{"members"}, map[string]jsonSchema{
		"members": arrayOf(userSummarySchema), "next_cursor": str()})},
	"GET /admin/invitations": {http.StatusOK, nil, object([]string{"invitations"}, map[string]jsonSchema{
		"next_cursor": str(),
		"invitations": arrayOf(object([]string{"id", "org_id", "groups", "state", "created_at", "expires_at"},
			map[string]jsonSchema{"id": uuidStr(), "org_id": uuidStr(), "email": str(), "groups": arrayOf(str()),
				"state": str(), "created_at": dateTime(), "expires_at": dateTime(), "used_by": str()}))})},
	"GET /admin/organizations": {http.StatusOK, nil, object([]string{"organizations"}, map[string]jsonSchema{
		"organizations": arrayOf(organizationSchema)})},
	"GET /admin/organizations/{orgID}": {http.StatusOK, nil, organizationSchema},
	"GET /admin/organizations/{orgID}/attributes": {http.StatusOK, nil, object([]string{"attributes"}, map[string]jsonSchema{
		"attributes": arrayOf(object([]string{"id", "name", "value_type"}, map[string]jsonSchema{
			"id": uuidStr(), "name": str(), "display_name": str(), "value_type": str(), "personal": boolean(),
			"user_readable": boolean(), "user_writable": boolean(), "required": boolean()}))})},
	"GET /admin/organizations/{orgID}/claim-mappers": {http.StatusOK, nil, object([]string{"mappers"}, map[string]jsonSchema{
		"mappers": arrayOf(object([]string{"id", "attribute", "claim_name", "destination", "all_clients"}, map[string]jsonSchema{
			"id": uuidStr(), "attribute": str(), "personal": boolean(), "claim_name": str(), "destination": str(),
			"required_scope": str(), "all_clients": boolean(), "client_id": str()}))})},
	"GET /admin/organizations/{orgID}/migration-source": {http.StatusOK, nil, migrationSourceSchema},
	"GET /admin/organizations/{orgID}/proxy-hosts": {http.StatusOK, nil, object([]string{"proxy_hosts"}, map[string]jsonSchema{
		"proxy_hosts": arrayOf(object([]string{"host", "enabled"}, map[string]jsonSchema{"host": str(), "enabled": boolean()}))})},
	// A bare array, unlike every other list, kept for the callers it has.
	"GET /admin/organizations/{orgID}/resource-servers": {http.StatusOK, nil, arrayOf(object([]string{"resource"},
		map[string]jsonSchema{"resource": str(), "name": str(), "created_at": dateTime()}))},
	"GET /admin/organizations/{orgID}/scopes": {http.StatusOK, nil, object([]string{"scopes", "standard"}, map[string]jsonSchema{
		"standard": arrayOf(str()),
		"scopes": arrayOf(object([]string{"name", "advertise"}, map[string]jsonSchema{
			"name": str(), "display_name": str(), "description": str(), "advertise": boolean()}))})},
	"GET /admin/organizations/{orgID}/webauthn-policy": {http.StatusOK, nil, object([]string{"attestation"}, webauthnPolicySchema)},
	"GET /admin/subjects/{subjectID}/export": {http.StatusOK, nil, object([]string{"format", "subject_id", "exported_at", "tables"}, map[string]jsonSchema{
		"format": str(), "subject_id": uuidStr(), "exported_at": dateTime(),
		"tables":   mapOf(arrayOf(openObject())),
		"withheld": mapOf(arrayOf(str())),
		"attributes": nullable(arrayOf(object([]string{"name", "value"}, map[string]jsonSchema{
			"name": str(), "display_name": str(), "value": str(), "readable": boolean()})))})},
	"GET /admin/tokens": {http.StatusOK, nil, object([]string{"tokens"}, map[string]jsonSchema{
		"tokens": arrayOf(object([]string{"id", "name", "scopes", "created_at"}, map[string]jsonSchema{
			"id": uuidStr(), "name": str(), "org_id": nullable(uuidStr()), "scopes": arrayOf(str()),
			"client_ids": nullable(arrayOf(str())), "group_ids": nullable(arrayOf(str())),
			"created_at": dateTime(), "expires_at": nullable(dateTime()), "revoked_at": nullable(dateTime()),
			"last_used_at": nullable(dateTime())}))})},
	"GET /admin/users": {http.StatusOK, nil, object([]string{"users"}, map[string]jsonSchema{
		"users": arrayOf(userSummarySchema), "next_cursor": str()})},
	"GET /admin/users/{userID}": {http.StatusOK, nil, object([]string{"id", "org_id", "email", "username", "status",
		"created_at", "display_name", "given_name", "surname", "email_verified", "require_password_change", "updated_at"},
		map[string]jsonSchema{"id": uuidStr(), "org_id": uuidStr(), "email": str(), "username": str(),
			"status": str(), "created_at": dateTime(), "display_name": str(), "given_name": str(), "surname": str(),
			"email_verified": boolean(), "require_password_change": boolean(), "updated_at": dateTime()})},
	"GET /admin/users/{userID}/attributes": {http.StatusOK, nil, object([]string{"user_id", "attributes"}, map[string]jsonSchema{
		"user_id": uuidStr(), "attributes": arrayOf(openObject())})},
	"GET /admin/users/{userID}/factors": {http.StatusOK, nil, object([]string{"user_id", "factors"}, map[string]jsonSchema{
		"user_id": uuidStr(), "has_second_factor": boolean(), "recovery_codes_unused": integer(),
		"recovery_codes_disabled": boolean(),
		"factors": arrayOf(object([]string{"type", "confirmed"}, map[string]jsonSchema{
			"type": str(), "id": str(), "label": str(), "confirmed": boolean(), "disabled": boolean(),
			"created_at": dateTime(), "last_used_at": dateTime()}))})},
	"GET /admin/users/{userID}/sessions": {http.StatusOK, nil, object([]string{"sessions"}, map[string]jsonSchema{
		"next_cursor": str(),
		"sessions": arrayOf(object([]string{"sid", "user_id", "org_id", "auth_time", "not_after", "created_at"}, map[string]jsonSchema{
			"sid": str(), "user_id": uuidStr(), "org_id": uuidStr(), "acr": str(), "amr": arrayOf(str()),
			"auth_time": dateTime(), "not_after": dateTime(), "user_agent": str(), "has_address": boolean(),
			"created_at": dateTime()}))})},

	"GET /admin/system": {http.StatusOK, nil, object([]string{"release", "schema", "organizations", "rate_limits"}, map[string]jsonSchema{
		"release": str(), "commit": str(), "go": str(), "instances": integer(), "organizations": integer(),
		"suspended_organizations": integer(),
		"schema": object([]string{"applied", "binary", "fingerprint_pinned"}, map[string]jsonSchema{
			"applied": integer(), "binary": integer(), "fingerprint_pinned": boolean()}),
		"rate_limits": object([]string{"arrivals_per_second", "per_token_per_second"}, map[string]jsonSchema{
			"arrivals_per_second": integer(), "per_token_per_second": integer()})})},
	"POST /admin/batch": {http.StatusOK, typeOf[batchRequest](), object([]string{"config_version", "results"},
		withVersion(map[string]jsonSchema{"results": arrayOf(object([]string{"status"},
			map[string]jsonSchema{"status": integer(), "body": anyValue()}))}))},
	"GET /admin/users/{userID}/consents": {http.StatusOK, nil, object([]string{"user_id", "consents"}, map[string]jsonSchema{
		"user_id": uuidStr(),
		"consents": arrayOf(object([]string{"client_id", "display_name", "scopes", "granted_at", "active_refresh_grants"},
			map[string]jsonSchema{"client_id": str(), "display_name": str(), "scopes": arrayOf(str()),
				"granted_at": dateTime(), "active_refresh_grants": integer(), "offline_until": nullable(dateTime())}))})},
	"DELETE /admin/users/{userID}/consents/{clientID}": {http.StatusOK, nil, object([]string{"user_id", "client_id", "refresh_grants_revoked", "config_version"},
		withVersion(map[string]jsonSchema{"user_id": uuidStr(), "client_id": str(), "refresh_grants_revoked": integer()}))},

	"POST /admin/users": {http.StatusCreated, typeOf[createUserRequest](), object([]string{"id", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr()}))},
	"PATCH /admin/users/{userID}": {http.StatusOK, typeOf[patchUserRequest](), object([]string{"id", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "sessions_ended": integer()}))},
	"DELETE /admin/users/{userID}": {http.StatusOK, nil, object([]string{"id", "config_version"},
		withVersion(merge(sessionsEndedSchema, map[string]jsonSchema{"id": uuidStr(), "refresh_families_revoked": integer()})))},
	"DELETE /admin/users/{userID}/factors/{kind}":            {http.StatusOK, nil, factorRemovedSchema},
	"DELETE /admin/users/{userID}/factors/{kind}/{factorID}": {http.StatusOK, nil, factorRemovedSchema},
	"DELETE /admin/users/{userID}/throttle": {http.StatusOK, nil, object([]string{"user_id", "config_version"},
		withVersion(map[string]jsonSchema{"user_id": uuidStr(), "counts_cleared": integer()}))},
	"POST /admin/users/{userID}/passkey-link": {http.StatusOK, typeOf[passkeyLinkRequest](), object([]string{"user_id", "link_id", "expires_at"},
		withVersion(map[string]jsonSchema{"user_id": uuidStr(), "link_id": uuidStr(), "expires_at": dateTime()}))},
	"POST /admin/invitations": {http.StatusCreated, typeOf[createInvitationRequest](), object([]string{"id", "org_id", "expires_at", "sent"},
		map[string]jsonSchema{"id": uuidStr(), "org_id": uuidStr(), "expires_at": dateTime(), "sent": boolean(), "link": str()})},
	"DELETE /admin/invitations/{invitationID}": {http.StatusNoContent, nil, nil},
	"POST /admin/tokens": {http.StatusCreated, typeOf[createTokenRequest](), object([]string{"id", "name", "secret", "scopes", "expires_at", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "name": str(), "secret": str(), "scopes": arrayOf(str()),
			"org_id": str(), "expires_at": dateTime()}))},
	"POST /admin/tokens/{tokenID}/rotate": {http.StatusOK, typeOf[rotateTokenRequest](), object([]string{"id", "secret", "replaces", "replaced_works_until", "expires_at", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "secret": str(), "replaces": uuidStr(),
			"replaced_works_until": dateTime(), "expires_at": dateTime()}))},
	"DELETE /admin/tokens/{tokenID}": {http.StatusOK, nil, object([]string{"id", "revoked", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "revoked": boolean()}))},
	"PUT /admin/organizations/{orgID}/attributes": {http.StatusOK, typeOf[declareAttributeRequest](), object([]string{"id", "name", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "name": str(), "personal": boolean()}))},
	"PUT /admin/users/{userID}/attributes": {http.StatusOK, typeOf[setAttributesRequest](), object([]string{"user_id", "config_version"},
		withVersion(map[string]jsonSchema{"user_id": uuidStr()}))},
	"POST /admin/organizations/{orgID}/claim-mappers": {http.StatusOK, typeOf[mapperRequest](), object([]string{"id", "claim_name", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "claim_name": str(), "destination": str()}))},
	"DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}": {http.StatusOK, nil, object([]string{"id", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr()}))},
	"PUT /admin/organizations/{orgID}/scopes": {http.StatusOK, typeOf[scopeRequest](), object([]string{"name", "config_version"},
		withVersion(map[string]jsonSchema{"name": str(), "advertise": boolean()}))},
	"DELETE /admin/organizations/{orgID}/scopes/{scope}": {http.StatusOK, nil, object([]string{"name", "config_version"},
		withVersion(map[string]jsonSchema{"name": str()}))},
	"PUT /admin/organizations/{orgID}/webauthn-policy": {http.StatusOK, typeOf[webauthnPolicyBody](), object([]string{"attestation", "config_version"},
		withVersion(merge(webauthnPolicySchema)))},
	"PUT /admin/organizations/{orgID}/proxy-hosts": {http.StatusOK, typeOf[proxyHostRequest](), object([]string{"host", "config_version"},
		withVersion(map[string]jsonSchema{"host": str(), "enabled": boolean()}))},
	"DELETE /admin/organizations/{orgID}/proxy-hosts/{host}": {http.StatusOK, nil, object([]string{"host", "config_version"},
		withVersion(map[string]jsonSchema{"host": str()}))},
	"GET /admin/organizations/{orgID}/role-bindings": {http.StatusOK, nil, object([]string{"role_bindings"}, map[string]jsonSchema{
		"role_bindings": arrayOf(object([]string{"id", "org_id", "role", "created_at"}, map[string]jsonSchema{
			"id": uuidStr(), "org_id": uuidStr(), "role": str(), "user_id": uuidStr(), "client_id": str(),
			"group_id": uuidStr(), "created_at": dateTime()}))})},
	"POST /admin/organizations/{orgID}/role-bindings": {http.StatusCreated, typeOf[grantRoleRequest](), object([]string{"id", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr()}))},
	"DELETE /admin/organizations/{orgID}/role-bindings/{bindingID}": {http.StatusOK, nil, removedSchema},
	"GET /admin/me": {http.StatusOK, nil, object([]string{"kind", "name", "org_id", "scopes", "expires_at"}, map[string]jsonSchema{
		"kind": str(), "name": str(), "org_id": nullable(uuidStr()), "scopes": arrayOf(str()),
		"delegated": openObject(), "expires_at": nullable(dateTime()), "client_id": str(),
		"user": object([]string{"id", "email", "display_name"}, map[string]jsonSchema{
			"id": uuidStr(), "email": str(), "display_name": str()})})},

	"PUT /admin/organizations/{orgID}/migration-source":    {http.StatusOK, typeOf[migrationSourceRequest](), migrationSourceSchema},
	"DELETE /admin/organizations/{orgID}/migration-source": {http.StatusOK, nil, removedSchema},
	"PUT /admin/organizations/{orgID}/resource-servers": {http.StatusOK, typeOf[resourceServerRequest](), object([]string{"resource", "config_version"},
		withVersion(map[string]jsonSchema{"resource": str(), "name": str()}))},
	"DELETE /admin/organizations/{orgID}/resource-servers": {http.StatusOK, nil, removedSchema},
	"POST /admin/organizations": {http.StatusCreated, typeOf[createOrganizationRequest](), object([]string{"id", "slug", "instance_id", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "slug": str(), "display_name": str(), "instance_id": uuidStr()}))},
	"PATCH /admin/organizations/{orgID}": {http.StatusOK, typeOf[patchOrganizationRequest](), object([]string{"id", "status", "was", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "status": str(), "was": str()}))},
	"POST /admin/clients": {http.StatusCreated, typeOf[createClientRequest](), object([]string{"client_id", "type", "config_version"},
		withVersion(map[string]jsonSchema{"client_id": str(), "type": str(), "require_pkce": boolean(),
			"client_secret": str(), "notice": str()}))},
	"PATCH /admin/clients/{clientID}": {http.StatusOK, typeOf[patchClientRequest](), object([]string{"client_id", "enabled", "require_pkce", "config_version"},
		withVersion(map[string]jsonSchema{"client_id": str(), "enabled": boolean(), "require_pkce": boolean(),
			"may_exchange": boolean(), "exchange_audiences": arrayOf(str()),
			"post_logout_redirect_uris": arrayOf(str()), "frontchannel_logout_uri": str(),
			"frontchannel_logout_session_required": boolean(), "access_token_ttl_s": integer(),
			"refresh_token_ttl_s": integer(), "id_token_signed_response_alg": str(),
			"require_pushed_authorization_requests": boolean(), "first_party": boolean(),
			"issuer_alias": str(), "minimum_acr": str(), "consent_lifetime_s": integer()}))},
	"DELETE /admin/clients/{clientID}": {http.StatusOK, nil, object([]string{"client_id", "config_version"},
		withVersion(map[string]jsonSchema{"client_id": str(), "refresh_families_revoked": integer()}))},
	"POST /admin/clients/{clientID}/rotate-secret": {http.StatusOK, nil, object([]string{"client_id", "client_secret", "config_version"},
		withVersion(map[string]jsonSchema{"client_id": str(), "client_secret": str(), "notice": str()}))},
	"POST /admin/subjects/{subjectID}/erase": {http.StatusOK, typeOf[eraseSubjectRequest](), object([]string{"subject_id", "erased", "config_version"},
		withVersion(merge(sessionsEndedSchema, map[string]jsonSchema{"subject_id": uuidStr(), "erased": boolean(),
			"key_shredded": boolean(), "account_deleted": boolean(), "deactivated": boolean(),
			"totp_credentials": integer()})))},
	"POST /admin/groups":            {http.StatusCreated, typeOf[createGroupRequest](), idVersionSchema},
	"PATCH /admin/groups/{groupID}": {http.StatusOK, typeOf[patchGroupRequest](), idVersionSchema},
	"DELETE /admin/groups/{groupID}": {http.StatusOK, nil, object([]string{"id", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr(), "members_removed": integer()}))},
	"PUT /admin/groups/{groupID}/members/{userID}":    {http.StatusOK, nil, membershipSchema},
	"DELETE /admin/groups/{groupID}/members/{userID}": {http.StatusOK, nil, membershipSchema},
	"DELETE /admin/users/{userID}/sessions": {http.StatusOK, nil, object([]string{"user_id", "sessions_ended", "config_version"},
		withVersion(merge(sessionsEndedSchema, map[string]jsonSchema{"user_id": uuidStr()})))},
	"DELETE /admin/sessions/{sid}": {http.StatusOK, nil, object([]string{"sid", "sessions_ended", "config_version"},
		withVersion(merge(sessionsEndedSchema, map[string]jsonSchema{"sid": str(), "user_id": uuidStr()})))},
}

var (
	factorRemovedSchema = object([]string{"user_id", "factor", "removed", "config_version"},
		withVersion(merge(sessionsEndedSchema, map[string]jsonSchema{"user_id": uuidStr(), "factor": str(),
			"removed": integer()})))
	removedSchema = object([]string{"removed", "config_version"},
		withVersion(map[string]jsonSchema{"removed": boolean()}))
	idVersionSchema = object([]string{"id", "config_version"},
		withVersion(map[string]jsonSchema{"id": uuidStr()}))
	membershipSchema = object([]string{"group_id", "user_id", "member", "changed", "config_version"},
		withVersion(map[string]jsonSchema{"group_id": uuidStr(), "user_id": uuidStr(), "member": boolean(),
			"changed": boolean()}))
)
