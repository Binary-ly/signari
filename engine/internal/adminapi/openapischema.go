package adminapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
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
// budgetsProps is an organisation's budgets as read and as set (6.10), fresh
// each call because withVersion adds to the map it is given.
func budgetsProps() map[string]jsonSchema {
	return map[string]jsonSchema{"org_id": uuidStr(), "tokens_per_minute": integer(),
		"sign_ins_per_minute": integer(), "tokens_default": boolean(), "sign_ins_default": boolean()}
}

// orgSettingsProps is an organisation's settings as read and as changed
// (6.07), fresh each call for the same reason.
func orgSettingsProps() map[string]jsonSchema {
	return map[string]jsonSchema{"org_id": uuidStr(), "max_concurrent_sessions": integer(),
		"session_limit_behaviour": str(), "password_only_binds": str(), "remember_device_days": integer(),
		"new_device_notice": boolean(), "reauth_window_s": integer(), "session_lifetime_s": integer(),
		"session_idle_s": integer(), "offline_lifetime_s": integer(), "persistent_sessions": boolean(),
		"sms_numbers": str(), "totp_algorithm": str(), "totp_digits": integer(), "totp_period_s": integer(),
		"login_free_attempts": integer(), "login_max_delay_s": integer()}
}

// signupProps is an organisation's self-sign-up rule as read and set (6.07).
func signupProps() map[string]jsonSchema {
	return map[string]jsonSchema{"org_id": uuidStr(), "enabled": boolean(), "allowed_domains": arrayOf(str()),
		"any_domain": boolean(), "default_groups": arrayOf(str()), "require_verified_email": boolean(),
		"require_approval": boolean()}
}

// umaDecisionSchema is a UMA request approved or denied (6.07).
var umaDecisionSchema = object([]string{"id", "state", "config_version"},
	withVersion(map[string]jsonSchema{"id": uuidStr(), "state": str()}))

// webauthnProps is an instance's Relying Party identity (6.07).
func webauthnProps() map[string]jsonSchema {
	return map[string]jsonSchema{"instance_id": uuidStr(), "rp_id": str(), "rp_display_name": str(),
		"related_origins": arrayOf(str())}
}

// withProp adds one property to props.
func withProp(props map[string]jsonSchema, name string, s jsonSchema) map[string]jsonSchema {
	props[name] = s
	return props
}

// brandProps is an instance's appearance (6.07).
func brandProps() map[string]jsonSchema {
	return map[string]jsonSchema{"instance_id": uuidStr(), "branded": boolean(), "product_name": str(),
		"logo_url": str(), "support_url": str(), "colour_primary": str(), "colour_on_primary": str(),
		"colour_background": str(), "colour_text": str()}
}

var brandFields = []string{"instance_id", "branded", "product_name", "logo_url", "support_url",
	"colour_primary", "colour_on_primary", "colour_background", "colour_text"}

// registrationProps is an organisation's registration policy (6.07).
func registrationProps() map[string]jsonSchema {
	return map[string]jsonSchema{"org_id": uuidStr(), "enabled": boolean(), "open": boolean(),
		"max_clients": integer(), "allowed_scopes": arrayOf(str()), "allow_confidential": boolean()}
}

var registrationFields = []string{"org_id", "enabled", "open", "max_clients", "allowed_scopes", "allow_confidential"}

var signupFields = []string{"org_id", "enabled", "allowed_domains", "any_domain", "default_groups",
	"require_verified_email", "require_approval"}

// orgSettingsFields is every one of them, each always present.
func orgSettingsFields() []string {
	var out []string
	for k := range orgSettingsProps() {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

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
	appliedDocumentSchema = object([]string{"org_id", "document", "applied_at"}, map[string]jsonSchema{
		"org_id": uuidStr(), "document": str(), "applied_at": nullable(dateTime())})
	idpMappingSchema = object([]string{"slug", "claim", "attribute", "mapped", "config_version"},
		withVersion(map[string]jsonSchema{"slug": str(), "claim": str(), "attribute": str(), "mapped": boolean()}))
	groupMapSchema = object([]string{"slug", "remote_group", "group", "mapped", "config_version"},
		withVersion(map[string]jsonSchema{"slug": str(), "remote_group": str(), "group": str(), "mapped": boolean()}))
	scimGroupSchema = object([]string{"slug", "group", "remote_id", "provisioned", "config_version"},
		withVersion(map[string]jsonSchema{"slug": str(), "group": str(), "remote_id": str(), "provisioned": boolean()}))
	relationSchema = object([]string{"subject", "relation", "object", "granted", "config_version"},
		withVersion(map[string]jsonSchema{"subject": str(), "relation": str(), "object": str(), "granted": boolean()}))
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
			"authorization_detail_types":               arrayOf(str()),
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
		"created_at", "display_name", "given_name", "surname", "email_verified", "require_password_change", "updated_at",
		"locale"},
		map[string]jsonSchema{"id": uuidStr(), "org_id": uuidStr(), "email": str(), "username": str(),
			"status": str(), "created_at": dateTime(), "display_name": str(), "given_name": str(), "surname": str(),
			"email_verified": boolean(), "require_password_change": boolean(), "updated_at": dateTime(),
			"locale": str()})},
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
	"GET /admin/organizations/{orgID}/budgets": {http.StatusOK, nil, object(
		[]string{"org_id", "tokens_per_minute", "sign_ins_per_minute", "tokens_default", "sign_ins_default"},
		budgetsProps())},
	"PUT /admin/organizations/{orgID}/budgets": {http.StatusOK, typeOf[putBudgetsRequest](), object(
		[]string{"org_id", "tokens_per_minute", "sign_ins_per_minute", "tokens_default", "sign_ins_default", "config_version"},
		withVersion(budgetsProps()))},
	"GET /admin/organizations/{orgID}/settings": {http.StatusOK, nil, object(orgSettingsFields(), orgSettingsProps())},
	"GET /admin/clients/{clientID}/group-release": {http.StatusOK, nil, object([]string{"client_id", "released", "only_groups"},
		map[string]jsonSchema{"client_id": str(), "released": boolean(), "only_groups": arrayOf(str())})},
	"PUT /admin/clients/{clientID}/group-release": {http.StatusOK, typeOf[putGroupReleaseRequest](), object(
		[]string{"client_id", "released", "only_groups", "config_version"},
		withVersion(map[string]jsonSchema{"client_id": str(), "released": boolean(), "only_groups": arrayOf(str())}))},
	"DELETE /admin/clients/{clientID}/group-release": {http.StatusOK, nil, removedSchema},
	"GET /admin/organizations/{orgID}/signup":        {http.StatusOK, nil, object(signupFields, signupProps())},
	"PUT /admin/organizations/{orgID}/signup": {http.StatusOK, typeOf[putSignupRequest](), object(
		append(append([]string{}, signupFields...), "config_version"), withVersion(signupProps()))},
	"DELETE /admin/organizations/{orgID}/signup": {http.StatusOK, nil, removedSchema},
	"GET /admin/instances": {http.StatusOK, nil, object([]string{"instances"}, map[string]jsonSchema{
		"instances": arrayOf(object([]string{"id", "issuer", "display_name", "created_at"}, map[string]jsonSchema{
			"id": uuidStr(), "issuer": str(), "display_name": str(), "created_at": dateTime()}))})},
	"GET /admin/instances/{instanceID}/brand": {http.StatusOK, nil, object(brandFields, brandProps())},
	"PUT /admin/instances/{instanceID}/brand": {http.StatusOK, typeOf[putBrandRequest](), object(
		append(append([]string{}, brandFields...), "config_version"), withVersion(brandProps()))},
	"DELETE /admin/instances/{instanceID}/brand": {http.StatusOK, nil, removedSchema},
	"GET /admin/instances/{instanceID}/webauthn": {http.StatusOK, nil, object(
		[]string{"instance_id", "rp_id", "rp_display_name", "related_origins"}, webauthnProps())},
	"PUT /admin/instances/{instanceID}/webauthn": {http.StatusOK, typeOf[putWebAuthnRequest](), object(
		[]string{"instance_id", "rp_id", "rp_display_name", "related_origins", "replaced_rp_id", "config_version"},
		withVersion(withProp(webauthnProps(), "replaced_rp_id", str())))},
	"GET /admin/instances/{instanceID}/issuer-aliases": {http.StatusOK, nil, object([]string{"instance_id", "issuer_aliases"},
		map[string]jsonSchema{"instance_id": uuidStr(), "issuer_aliases": arrayOf(object(
			[]string{"issuer", "retire_after", "pinned_clients"}, map[string]jsonSchema{"issuer": str(),
				"retire_after": nullable(dateTime()), "pinned_clients": integer()}))})},
	"POST /admin/instances/{instanceID}/issuer-aliases": {http.StatusCreated, typeOf[issuerAliasRequest](), object(
		[]string{"alias", "config_version"}, withVersion(map[string]jsonSchema{"alias": str()}))},
	"PATCH /admin/instances/{instanceID}/issuer-aliases": {http.StatusOK, typeOf[issuerAliasRequest](), object(
		[]string{"alias", "config_version"}, withVersion(map[string]jsonSchema{"alias": str()}))},
	"GET /admin/organizations/{orgID}/event-subscriptions": {http.StatusOK, nil, object([]string{"org_id", "subscriptions"},
		map[string]jsonSchema{"org_id": uuidStr(), "subscriptions": arrayOf(object([]string{"id", "name", "url",
			"event_types", "enabled", "disabled_reason", "delivered", "outstanding"}, map[string]jsonSchema{
			"id": uuidStr(), "name": str(), "url": str(), "event_types": arrayOf(str()), "enabled": boolean(),
			"disabled_reason": str(), "delivered": integer(), "outstanding": integer()}))})},
	"POST /admin/organizations/{orgID}/event-subscriptions": {http.StatusCreated, typeOf[createSubscriptionRequest](),
		object([]string{"id", "name", "secret", "config_version"}, withVersion(map[string]jsonSchema{
			"id": uuidStr(), "name": str(), "secret": str()}))},
	"DELETE /admin/organizations/{orgID}/event-subscriptions/{name}": {http.StatusOK, nil, object(
		[]string{"name", "removed", "config_version"}, withVersion(map[string]jsonSchema{"name": str(), "removed": boolean()}))},
	"POST /admin/organizations/{orgID}/event-subscriptions/{name}/rotate-secret": {http.StatusOK, nil, object(
		[]string{"name", "secret", "config_version"}, withVersion(map[string]jsonSchema{"name": str(), "secret": str()}))},
	"POST /admin/organizations/{orgID}/event-subscriptions/{name}/enable": {http.StatusOK, nil, object(
		[]string{"name", "enabled", "config_version"}, withVersion(map[string]jsonSchema{"name": str(), "enabled": boolean()}))},
	"POST /admin/organizations/{orgID}/event-subscriptions/{name}/test": {http.StatusOK, nil, object(
		[]string{"name", "event_id", "config_version"}, withVersion(map[string]jsonSchema{"name": str(), "event_id": str()}))},
	"GET /admin/organizations/{orgID}/radius-clients": {http.StatusOK, nil, object([]string{"org_id", "clients"},
		map[string]jsonSchema{"org_id": uuidStr(), "clients": arrayOf(object([]string{"id", "name", "network", "enabled"},
			map[string]jsonSchema{"id": uuidStr(), "name": str(), "network": str(), "enabled": boolean()}))})},
	"POST /admin/organizations/{orgID}/radius-clients": {http.StatusCreated, typeOf[addRADIUSClientRequest](), object(
		[]string{"id", "name", "network", "config_version"}, withVersion(map[string]jsonSchema{
			"id": uuidStr(), "name": str(), "network": str()}))},
	"PATCH /admin/organizations/{orgID}/radius-clients/{deviceID}": {http.StatusOK, typeOf[patchRADIUSClientRequest](),
		object([]string{"id", "enabled", "config_version"}, withVersion(map[string]jsonSchema{"id": uuidStr(),
			"enabled": boolean()}))},
	"GET /admin/organizations/{orgID}/radius-authorizations": {http.StatusOK, nil, object(
		[]string{"org_id", "authorizations"}, map[string]jsonSchema{"org_id": uuidStr(), "authorizations": arrayOf(
			object([]string{"group_id", "group", "vlan_id", "filter_id", "priority"}, map[string]jsonSchema{
				"group_id": uuidStr(), "group": str(), "vlan_id": nullable(integer()), "filter_id": str(),
				"priority": integer()}))})},
	"PUT /admin/groups/{groupID}/radius": {http.StatusOK, typeOf[putRADIUSAuthorizationRequest](), object(
		[]string{"group_id", "config_version"}, withVersion(map[string]jsonSchema{"group_id": uuidStr()}))},
	"DELETE /admin/groups/{groupID}/radius": {http.StatusOK, nil, object(
		[]string{"group_id", "removed", "config_version"}, withVersion(map[string]jsonSchema{"group_id": uuidStr(),
			"removed": boolean()}))},
	"GET /admin/organizations/{orgID}/identity-providers": {http.StatusOK, nil, object([]string{"org_id", "providers"},
		map[string]jsonSchema{"org_id": uuidStr(), "providers": arrayOf(object([]string{"id", "slug", "name", "kind",
			"issuer", "enabled", "allow_signup", "allow_linking", "allow_assertions", "trust_email_verification",
			"require_verified_email", "mfa_amr", "mfa_acr", "linked", "attribute_map"}, map[string]jsonSchema{
			"id": uuidStr(), "slug": str(), "name": str(), "kind": str(), "issuer": str(), "enabled": boolean(),
			"allow_signup": boolean(), "allow_linking": boolean(), "allow_assertions": boolean(),
			"trust_email_verification": boolean(), "require_verified_email": boolean(), "mfa_amr": arrayOf(str()), "mfa_acr": arrayOf(str()), "linked": integer(),
			"attribute_map": arrayOf(object([]string{"claim", "attribute", "overwrite", "max_length"},
				map[string]jsonSchema{"claim": str(), "attribute": str(), "overwrite": boolean(),
					"max_length": integer()}))}))})},
	"PATCH /admin/organizations/{orgID}/identity-providers/{slug}": {http.StatusOK,
		typeOf[patchIdentityProviderRequest](), object([]string{"slug", "config_version"},
			withVersion(map[string]jsonSchema{"slug": str()}))},
	"PUT /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map": {http.StatusOK,
		typeOf[idpAttributeMapRequest](), idpMappingSchema},
	"DELETE /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map": {http.StatusOK, nil, idpMappingSchema},
	"GET /admin/organizations/{orgID}/saml-providers": {http.StatusOK, nil, object([]string{"org_id", "providers"},
		map[string]jsonSchema{"org_id": uuidStr(), "providers": arrayOf(object([]string{"id", "entity_id", "name",
			"name_id_format", "signature_alg", "enabled", "sign_assertions", "sign_responses", "want_signed_requests",
			"encrypted", "has_signing_cert", "lifetime_s", "acs_urls", "slo_urls", "attribute_release",
			"group_release"}, map[string]jsonSchema{"id": uuidStr(), "entity_id": str(), "name": str(),
			"name_id_format": str(), "signature_alg": str(), "enabled": boolean(), "sign_assertions": boolean(),
			"sign_responses": boolean(), "want_signed_requests": boolean(), "encrypted": boolean(),
			"has_signing_cert": boolean(), "lifetime_s": integer(), "acs_urls": arrayOf(str()),
			"slo_urls": arrayOf(str()), "attribute_release": mapOf(str()),
			"group_release": nullable(object([]string{"attribute_name", "only"}, map[string]jsonSchema{
				"attribute_name": str(), "only": arrayOf(str())}))}))})},
	"POST /admin/organizations/{orgID}/saml-providers": {http.StatusCreated, typeOf[addSAMLProviderRequest](), object(
		[]string{"id", "entity_id", "name_id_format", "config_version"}, withVersion(map[string]jsonSchema{
			"id": uuidStr(), "entity_id": str(), "name_id_format": str()}))},
	"PATCH /admin/organizations/{orgID}/saml-providers/{providerID}": {http.StatusOK, typeOf[patchSAMLProviderRequest](),
		object([]string{"id", "sign_assertions", "sign_responses", "signature_alg", "config_version"},
			withVersion(map[string]jsonSchema{"id": uuidStr(), "sign_assertions": boolean(),
				"sign_responses": boolean(), "signature_alg": str(), "metadata_changed": boolean()}))},
	"PUT /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release": {http.StatusOK,
		typeOf[samlAttributeRequest](), object([]string{"id", "saml_attribute", "attribute", "config_version"},
			withVersion(map[string]jsonSchema{"id": uuidStr(), "saml_attribute": str(), "attribute": str()}))},
	"DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release": {http.StatusOK, nil, object(
		[]string{"id", "saml_attribute", "removed", "config_version"}, withVersion(map[string]jsonSchema{
			"id": uuidStr(), "saml_attribute": str(), "removed": boolean()}))},
	"PUT /admin/organizations/{orgID}/saml-providers/{providerID}/group-release": {http.StatusOK,
		typeOf[samlGroupReleaseRequest](), object([]string{"id", "attribute_name", "only", "config_version"},
			withVersion(map[string]jsonSchema{"id": uuidStr(), "attribute_name": str(), "only": arrayOf(str())}))},
	"DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/group-release": {http.StatusOK, nil, object(
		[]string{"id", "removed", "config_version"}, withVersion(map[string]jsonSchema{"id": uuidStr(),
			"removed": boolean()}))},
	"GET /admin/organizations/{orgID}/directories": {http.StatusOK, nil, object([]string{"org_id", "sources"},
		map[string]jsonSchema{"org_id": uuidStr(), "sources": arrayOf(object([]string{"id", "slug", "name", "kind",
			"on_missing", "enabled", "dry_run", "fetch_groups", "max_deactivate_percent", "last_sync_at",
			"last_created", "last_updated", "last_deactivated", "last_error", "group_map"}, map[string]jsonSchema{
			"id": uuidStr(), "slug": str(), "name": str(), "kind": str(), "on_missing": str(), "enabled": boolean(),
			"dry_run": boolean(), "fetch_groups": boolean(), "max_deactivate_percent": integer(),
			"last_sync_at": nullable(dateTime()), "last_created": integer(), "last_updated": integer(),
			"last_deactivated": integer(), "last_error": str(), "group_map": arrayOf(object(
				[]string{"remote_group", "group"}, map[string]jsonSchema{"remote_group": str(), "group": str()}))}))})},
	"POST /admin/organizations/{orgID}/directories": {http.StatusCreated, typeOf[addDirectoryRequest](), object(
		[]string{"id", "slug", "kind", "dry_run", "config_version"}, withVersion(map[string]jsonSchema{
			"id": uuidStr(), "slug": str(), "kind": str(), "dry_run": boolean()}))},
	"PATCH /admin/organizations/{orgID}/directories/{slug}": {http.StatusOK, typeOf[patchDirectoryRequest](), object(
		[]string{"slug", "config_version"}, withVersion(map[string]jsonSchema{"slug": str()}))},
	"PUT /admin/organizations/{orgID}/directories/{slug}/group-map":    {http.StatusOK, typeOf[groupMapRequest](), groupMapSchema},
	"DELETE /admin/organizations/{orgID}/directories/{slug}/group-map": {http.StatusOK, nil, groupMapSchema},
	"POST /admin/organizations/{orgID}/directories/{slug}/sync": {http.StatusOK, typeOf[syncRequest](), object(
		[]string{"slug", "upstream", "active_before", "plan", "groups", "applied", "dry_run_configured",
			"groups_skipped", "config_version"}, withVersion(map[string]jsonSchema{"slug": str(),
			"upstream": integer(), "active_before": integer(), "plan": str(), "groups": str(), "applied": boolean(),
			"dry_run_configured": boolean(), "groups_skipped": boolean(), "error": str(), "error_detail": str()}))},
	"GET /admin/organizations/{orgID}/scim-sources": {http.StatusOK, nil, object([]string{"org_id", "sources"},
		map[string]jsonSchema{"org_id": uuidStr(), "sources": arrayOf(object([]string{"id", "slug", "name",
			"on_delete", "enabled", "last_seen_at", "linked"}, map[string]jsonSchema{"id": uuidStr(), "slug": str(),
			"name": str(), "on_delete": str(), "enabled": boolean(), "last_seen_at": nullable(dateTime()),
			"linked": integer()}))})},
	"POST /admin/organizations/{orgID}/scim-sources": {http.StatusCreated, typeOf[addSCIMSourceRequest](), object(
		[]string{"id", "slug", "token", "config_version"}, withVersion(map[string]jsonSchema{"id": uuidStr(),
			"slug": str(), "token": str()}))},
	"PATCH /admin/organizations/{orgID}/scim-sources/{slug}": {http.StatusOK, typeOf[patchSCIMSourceRequest](), object(
		[]string{"slug", "enabled", "config_version"}, withVersion(map[string]jsonSchema{"slug": str(),
			"enabled": boolean()}))},
	"GET /admin/organizations/{orgID}/scim-targets": {http.StatusOK, nil, object([]string{"org_id", "targets"},
		map[string]jsonSchema{"org_id": uuidStr(), "targets": arrayOf(object([]string{"id", "slug", "name", "kind",
			"base_url", "on_deactivate", "scope_group", "dry_run", "enabled", "linked", "should_be_gone",
			"created_at"}, map[string]jsonSchema{"id": uuidStr(), "slug": str(), "name": str(), "kind": str(),
			"base_url": str(), "on_deactivate": str(), "scope_group": str(), "dry_run": boolean(), "enabled": boolean(),
			"linked": integer(), "should_be_gone": integer(), "created_at": dateTime()}))})},
	"POST /admin/organizations/{orgID}/scim-targets": {http.StatusCreated, typeOf[addSCIMTargetRequest](), object(
		[]string{"slug", "kind", "dry_run", "config_version"}, withVersion(map[string]jsonSchema{"slug": str(),
			"kind": str(), "dry_run": boolean()}))},
	"PATCH /admin/organizations/{orgID}/scim-targets/{slug}": {http.StatusOK, typeOf[patchSCIMTargetRequest](), object(
		[]string{"slug", "config_version"}, withVersion(map[string]jsonSchema{"slug": str(), "enabled": boolean(),
			"scope_group": str()}))},
	"PUT /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}":    {http.StatusOK, nil, scimGroupSchema},
	"DELETE /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}": {http.StatusOK, nil, scimGroupSchema},
	"POST /admin/organizations/{orgID}/scim-targets/{slug}/sync": {http.StatusOK, typeOf[syncRequest](), object(
		[]string{"slug", "applied", "created", "deactivated", "deleted", "failed", "failures", "groups",
			"config_version"}, withVersion(map[string]jsonSchema{"slug": str(), "applied": boolean(),
			"created": integer(), "deactivated": integer(), "deleted": integer(), "failed": integer(),
			"failures": arrayOf(str()), "error": str(), "error_detail": str(),
			"groups": arrayOf(object([]string{"name", "add", "remove", "unreadable", "members_synced"},
				map[string]jsonSchema{"name": str(), "add": integer(), "remove": integer(), "unreadable": str(),
					"members_synced": boolean()}))}))},
	"GET /admin/organizations/{orgID}/ssf-streams": {http.StatusOK, nil, object([]string{"org_id", "streams"},
		map[string]jsonSchema{"org_id": uuidStr(), "streams": arrayOf(object([]string{"id", "client_id",
			"delivery_method", "endpoint", "status", "events", "has_receiver_token"}, map[string]jsonSchema{
			"id": uuidStr(), "client_id": str(), "delivery_method": str(), "endpoint": str(), "status": str(),
			"events": arrayOf(str()), "has_receiver_token": boolean()}))})},
	"POST /admin/organizations/{orgID}/ssf-streams": {http.StatusCreated, typeOf[addStreamRequest](), object(
		[]string{"id", "client_id", "events", "config_version"}, withVersion(map[string]jsonSchema{"id": uuidStr(),
			"client_id": str(), "events": arrayOf(str())}))},
	"PATCH /admin/clients/{clientID}/ssf-stream": {http.StatusOK, typeOf[streamStatusRequest](), object(
		[]string{"client_id", "status", "was", "config_version"}, withVersion(map[string]jsonSchema{"client_id": str(),
			"status": str(), "was": str()}))},
	"GET /admin/organizations/{orgID}/ssf-sources": {http.StatusOK, nil, object([]string{"org_id", "sources"},
		map[string]jsonSchema{"org_id": uuidStr(), "sources": arrayOf(object([]string{"id", "name", "issuer",
			"jwks_uri", "audience", "events", "critical_members", "enabled"}, map[string]jsonSchema{"id": uuidStr(),
			"name": str(), "issuer": str(), "jwks_uri": str(), "audience": str(), "events": arrayOf(str()),
			"critical_members": arrayOf(str()), "enabled": boolean()}))})},
	"PUT /admin/organizations/{orgID}/ssf-sources": {http.StatusOK, typeOf[putSourceRequest](), object(
		[]string{"name", "issuer", "config_version"}, withVersion(map[string]jsonSchema{"name": str(),
			"issuer": str()}))},
	"GET /admin/instances/{instanceID}/federation": {http.StatusOK, nil, object([]string{"instance_id", "entity_id",
		"enabled", "authority_hints", "trust_anchor_hints", "organization_name", "homepage_uri", "contacts",
		"lifetime_s"}, map[string]jsonSchema{"instance_id": uuidStr(), "entity_id": str(), "enabled": boolean(),
		"authority_hints": arrayOf(str()), "trust_anchor_hints": arrayOf(str()), "organization_name": str(),
		"homepage_uri": str(), "contacts": arrayOf(str()), "lifetime_s": integer()})},
	"PUT /admin/instances/{instanceID}/federation": {http.StatusOK, typeOf[putFederationRequest](), object(
		[]string{"instance_id", "entity_id", "generated_key", "restart_required", "config_version"},
		withVersion(map[string]jsonSchema{"instance_id": uuidStr(), "entity_id": str(), "generated_key": str(),
			"restart_required": boolean()}))},
	"GET /admin/instances/{instanceID}/trust-marks": {http.StatusOK, nil, object([]string{"instance_id", "entity_id",
		"issued", "held"}, map[string]jsonSchema{"instance_id": uuidStr(), "entity_id": str(),
		"issued": arrayOf(object([]string{"type", "subject", "status", "issued_at", "expires_at", "revoked_at",
			"reason"}, map[string]jsonSchema{"type": str(), "subject": str(), "status": str(), "issued_at": dateTime(),
			"expires_at": nullable(dateTime()), "revoked_at": nullable(dateTime()), "reason": str()})),
		"held": arrayOf(object([]string{"type", "issuer", "published", "added_at", "expires_at"},
			map[string]jsonSchema{"type": str(), "issuer": str(), "published": boolean(), "added_at": dateTime(),
				"expires_at": nullable(dateTime())}))})},
	"POST /admin/instances/{instanceID}/trust-marks": {http.StatusCreated, typeOf[issueTrustMarkRequest](), object(
		[]string{"type", "subject", "trust_mark", "expires_at", "config_version"}, withVersion(map[string]jsonSchema{
			"type": str(), "subject": str(), "trust_mark": str(), "expires_at": nullable(dateTime())}))},
	"POST /admin/instances/{instanceID}/trust-marks/revoke": {http.StatusOK, typeOf[revokeTrustMarkRequest](), object(
		[]string{"type", "subject", "revoked", "config_version"}, withVersion(map[string]jsonSchema{"type": str(),
			"subject": str(), "revoked": boolean()}))},
	"PUT /admin/instances/{instanceID}/held-trust-marks": {http.StatusOK, typeOf[acceptTrustMarkRequest](), object(
		[]string{"type", "issuer", "published", "config_version"}, withVersion(map[string]jsonSchema{"type": str(),
			"issuer": str(), "published": boolean()}))},
	"DELETE /admin/instances/{instanceID}/held-trust-marks": {http.StatusOK, nil, object(
		[]string{"type", "issuer", "removed", "config_version"}, withVersion(map[string]jsonSchema{"type": str(),
			"issuer": str(), "removed": boolean()}))},
	"POST /admin/instances/{instanceID}/trust-mark-delegations": {http.StatusCreated, typeOf[delegateRequest](),
		object([]string{"type", "delegate", "delegation", "config_version"}, withVersion(map[string]jsonSchema{
			"type": str(), "delegate": str(), "delegation": str()}))},
	"GET /admin/organizations/{orgID}/authorization-model": {http.StatusOK, nil, object([]string{"org_id", "source"},
		map[string]jsonSchema{"org_id": uuidStr(), "source": str()})},
	"PUT /admin/organizations/{orgID}/authorization-model": {http.StatusOK, typeOf[putModelRequest](), object(
		[]string{"org_id", "types", "actions", "tests_passed", "config_version"}, withVersion(map[string]jsonSchema{
			"org_id": uuidStr(), "types": integer(), "actions": integer(), "tests_passed": integer()}))},
	"PUT /admin/organizations/{orgID}/relations":    {http.StatusOK, typeOf[relationRequest](), relationSchema},
	"DELETE /admin/organizations/{orgID}/relations": {http.StatusOK, nil, relationSchema},
	"POST /admin/organizations/{orgID}/config": {http.StatusOK, typeOf[applyConfigRequest](), object(
		[]string{"dry_run", "changes", "create", "update", "delete", "config_version"}, withVersion(
			map[string]jsonSchema{"dry_run": boolean(), "changes": arrayOf(object([]string{"action", "kind", "name",
				"detail", "destructive"}, map[string]jsonSchema{"action": str(), "kind": str(), "name": str(),
				"detail": str(), "destructive": boolean()})), "create": integer(), "update": integer(),
				"delete": integer()}))},
	"GET /admin/organizations/{orgID}/access-policy": {http.StatusOK, nil, appliedDocumentSchema},
	"PUT /admin/organizations/{orgID}/access-policy": {http.StatusOK, typeOf[putDocumentRequest](), object(
		[]string{"org_id", "summary", "config_version"}, withVersion(map[string]jsonSchema{"org_id": uuidStr(),
			"summary": str()}))},
	"GET /admin/organizations/{orgID}/sign-in-flow": {http.StatusOK, nil, appliedDocumentSchema},
	"PUT /admin/organizations/{orgID}/sign-in-flow": {http.StatusOK, typeOf[putDocumentRequest](), object(
		[]string{"org_id", "summary", "not_executed", "config_version"}, withVersion(map[string]jsonSchema{
			"org_id": uuidStr(), "summary": str(), "not_executed": arrayOf(str())}))},
	"GET /admin/organizations/{orgID}/rac-connections": {http.StatusOK, nil, object([]string{"org_id", "connections"},
		map[string]jsonSchema{"org_id": uuidStr(), "connections": arrayOf(object([]string{"id", "slug", "name",
			"protocol", "host", "port", "require_group", "recorded", "enabled", "has_credentials", "parameters"},
			map[string]jsonSchema{"id": uuidStr(), "slug": str(), "name": str(), "protocol": str(), "host": str(),
				"port": integer(), "require_group": str(), "recorded": boolean(), "enabled": boolean(),
				"has_credentials": boolean(), "parameters": mapOf(str())}))})},
	"POST /admin/organizations/{orgID}/rac-connections": {http.StatusCreated, typeOf[addRACRequest](), object(
		[]string{"id", "slug", "config_version"}, withVersion(map[string]jsonSchema{"id": uuidStr(), "slug": str()}))},
	"PATCH /admin/organizations/{orgID}/rac-connections/{slug}": {http.StatusOK, typeOf[patchRACRequest](), object(
		[]string{"slug", "config_version"}, withVersion(map[string]jsonSchema{"slug": str(), "enabled": boolean(),
			"parameters": mapOf(str())}))},
	"GET /admin/organizations/{orgID}/outposts": {http.StatusOK, nil, object([]string{"org_id", "outposts"},
		map[string]jsonSchema{"org_id": uuidStr(), "outposts": arrayOf(object([]string{"id", "name", "kind", "enabled",
			"search_group", "last_seen_at", "last_seen_ip"}, map[string]jsonSchema{"id": uuidStr(), "name": str(),
			"kind": str(), "enabled": boolean(), "search_group": str(), "last_seen_at": nullable(dateTime()),
			"last_seen_ip": str()}))})},
	"POST /admin/organizations/{orgID}/outposts": {http.StatusCreated, typeOf[createOutpostRequest](), object(
		[]string{"id", "name", "kind", "token", "config_version"}, withVersion(map[string]jsonSchema{
			"id": uuidStr(), "name": str(), "kind": str(), "token": str()}))},
	"PATCH /admin/organizations/{orgID}/outposts/{name}": {http.StatusOK, typeOf[patchOutpostRequest](), object(
		[]string{"name", "config_version"}, withVersion(map[string]jsonSchema{"name": str(), "enabled": boolean(),
			"search_group": str()}))},
	"GET /admin/organizations/{orgID}/providers": {http.StatusOK, nil, object([]string{"org_id", "providers"},
		map[string]jsonSchema{"org_id": uuidStr(), "providers": arrayOf(object([]string{"id", "hook", "url", "mode",
			"timeout_ms", "enabled", "signed", "called", "allowed_claims"}, map[string]jsonSchema{
			"id": uuidStr(), "hook": str(), "url": str(), "mode": str(), "timeout_ms": integer(), "enabled": boolean(),
			"signed": boolean(), "called": boolean(), "allowed_claims": arrayOf(str())}))})},
	"PUT /admin/organizations/{orgID}/providers/{hook}": {http.StatusOK, typeOf[putProviderRequest](), object(
		[]string{"id", "hook", "secret", "called", "config_version"}, withVersion(map[string]jsonSchema{
			"id": uuidStr(), "hook": str(), "secret": str(), "called": boolean()}))},
	"DELETE /admin/organizations/{orgID}/providers/{hook}": {http.StatusOK, nil, object(
		[]string{"hook", "removed", "config_version"}, withVersion(map[string]jsonSchema{"hook": str(), "removed": boolean()}))},
	"POST /admin/organizations/{orgID}/providers/{hook}/rotate-secret": {http.StatusOK, nil, object(
		[]string{"hook", "secret", "config_version"}, withVersion(map[string]jsonSchema{"hook": str(), "secret": str()}))},
	"PUT /admin/organizations/{orgID}/providers/{hook}/claims": {http.StatusOK, typeOf[providerClaimsRequest](), object(
		[]string{"hook", "allowed_claims", "config_version"}, withVersion(map[string]jsonSchema{"hook": str(),
			"allowed_claims": arrayOf(str())}))},
	"GET /admin/instances/{instanceID}/keys": {http.StatusOK, nil, object([]string{"instance_id", "keys"},
		map[string]jsonSchema{"instance_id": uuidStr(), "keys": arrayOf(object(
			[]string{"kid", "algorithm", "state", "published_at", "demoted_at"}, map[string]jsonSchema{
				"kid": str(), "algorithm": str(), "state": str(), "published_at": dateTime(),
				"demoted_at": nullable(dateTime()), "retirable_in_s": integer()}))})},
	"POST /admin/instances/{instanceID}/keys/rotate": {http.StatusOK, typeOf[rotateKeysRequest](), object(
		[]string{"instance_id", "steps", "config_version"}, withVersion(map[string]jsonSchema{
			"instance_id": uuidStr(), "steps": arrayOf(object([]string{"algorithm"}, map[string]jsonSchema{
				"algorithm": str(), "published": str(), "promoted": str(), "demoted": str(), "forced": boolean(),
				"wait_s": integer()}))}))},
	"POST /admin/instances/{instanceID}/keys/retire": {http.StatusOK, nil, object(
		[]string{"instance_id", "retired", "config_version"}, withVersion(map[string]jsonSchema{
			"instance_id": uuidStr(), "retired": arrayOf(str())}))},
	"GET /admin/organizations/{orgID}/duo": {http.StatusOK, nil, object([]string{"org_id", "configured", "enabled",
		"client_id", "api_host", "fail_open", "enrolled"}, map[string]jsonSchema{"org_id": uuidStr(),
		"configured": boolean(), "enabled": boolean(), "client_id": str(), "api_host": str(), "fail_open": boolean(),
		"enrolled": integer()})},
	"PUT /admin/organizations/{orgID}/duo": {http.StatusOK, typeOf[putDuoRequest](), object(
		[]string{"org_id", "client_id", "api_host", "fail_open", "config_version"}, withVersion(map[string]jsonSchema{
			"org_id": uuidStr(), "client_id": str(), "api_host": str(), "fail_open": boolean()}))},
	"PUT /admin/users/{userID}/duo": {http.StatusOK, typeOf[enrollDuoRequest](), object(
		[]string{"user_id", "duo_username", "config_version"}, withVersion(map[string]jsonSchema{
			"user_id": uuidStr(), "duo_username": str()}))},
	"GET /admin/organizations/{orgID}/uma": {http.StatusOK, nil, object([]string{"org_id", "owner_intervention", "poll_interval_s"},
		map[string]jsonSchema{"org_id": uuidStr(), "owner_intervention": boolean(), "poll_interval_s": integer()})},
	"PUT /admin/organizations/{orgID}/uma": {http.StatusOK, typeOf[putUMASettingsRequest](), object(
		[]string{"org_id", "owner_intervention", "poll_interval_s", "config_version"}, withVersion(map[string]jsonSchema{
			"org_id": uuidStr(), "owner_intervention": boolean(), "poll_interval_s": integer()}))},
	"GET /admin/organizations/{orgID}/uma/requests": {http.StatusOK, nil, object([]string{"org_id", "requests"},
		map[string]jsonSchema{"org_id": uuidStr(), "requests": arrayOf(object([]string{"id", "client_id",
			"resource_server", "requesting_party", "permissions", "relations", "created_at", "expires_at"},
			map[string]jsonSchema{"id": uuidStr(), "client_id": str(), "resource_server": str(),
				"requesting_party": str(), "permissions": arrayOf(object([]string{"resource_type", "resource_id",
					"resource_scopes"}, map[string]jsonSchema{"resource_type": str(), "resource_id": str(),
					"resource_scopes": arrayOf(str())})),
				"relations": arrayOf(str()), "created_at": dateTime(), "expires_at": dateTime()}))})},
	"POST /admin/organizations/{orgID}/uma/requests/{requestID}/approve": {http.StatusOK, typeOf[approveUMARequest](),
		umaDecisionSchema},
	"POST /admin/organizations/{orgID}/uma/requests/{requestID}/deny": {http.StatusOK, nil, umaDecisionSchema},
	"GET /admin/organizations/{orgID}/attesters": {http.StatusOK, nil, object([]string{"org_id", "attesters"},
		map[string]jsonSchema{"org_id": uuidStr(), "attesters": arrayOf(object(
			[]string{"name", "keys", "description", "created_at"}, map[string]jsonSchema{"name": str(),
				"keys": integer(), "description": str(), "created_at": dateTime()}))})},
	"PUT /admin/organizations/{orgID}/attesters/{name}": {http.StatusOK, typeOf[putAttesterRequest](), object(
		[]string{"name", "keys", "config_version"}, withVersion(map[string]jsonSchema{"name": str(), "keys": integer()}))},
	"DELETE /admin/organizations/{orgID}/attesters/{name}": {http.StatusOK, nil, removedSchema},
	"GET /admin/organizations/{orgID}/authorization-detail-types": {http.StatusOK, nil, object(
		[]string{"org_id", "authorization_detail_types"}, map[string]jsonSchema{"org_id": uuidStr(),
			"authorization_detail_types": arrayOf(object([]string{"type", "fields", "required", "description", "clients"},
				map[string]jsonSchema{"type": str(), "fields": arrayOf(str()), "required": arrayOf(str()),
					"description": str(), "clients": arrayOf(str())}))})},
	"PUT /admin/organizations/{orgID}/authorization-detail-types": {http.StatusOK, typeOf[putDetailTypeRequest](),
		object([]string{"type", "config_version"}, withVersion(map[string]jsonSchema{"type": str()}))},
	"DELETE /admin/organizations/{orgID}/authorization-detail-types": {http.StatusOK, nil, removedSchema},
	"GET /admin/organizations/{orgID}/prompts": {http.StatusOK, nil, object([]string{"org_id", "prompts"},
		map[string]jsonSchema{"org_id": uuidStr(), "prompts": arrayOf(object(
			[]string{"slug", "title", "body", "once", "order", "fields", "enabled", "version", "answered"},
			map[string]jsonSchema{"slug": str(), "title": str(), "body": str(), "once": boolean(), "order": integer(),
				"fields": arrayOf(object([]string{"name", "type", "label"}, map[string]jsonSchema{"name": str(),
					"type": str(), "label": str(), "help": str(), "required": boolean(), "options": arrayOf(str()),
					"attribute": str()})),
				"enabled": boolean(), "version": integer(), "answered": integer()}))})},
	"PUT /admin/organizations/{orgID}/prompts/{slug}": {http.StatusOK, typeOf[putPromptRequest](), object(
		[]string{"slug", "version", "asked_again", "config_version"}, withVersion(map[string]jsonSchema{
			"slug": str(), "version": integer(), "asked_again": integer()}))},
	"PATCH /admin/organizations/{orgID}/prompts/{slug}": {http.StatusOK, typeOf[patchPromptRequest](), object(
		[]string{"slug", "enabled", "config_version"}, withVersion(map[string]jsonSchema{"slug": str(), "enabled": boolean()}))},
	"GET /admin/organizations/{orgID}/registration": {http.StatusOK, nil, object(registrationFields,
		registrationProps())},
	"PUT /admin/organizations/{orgID}/registration": {http.StatusOK, typeOf[putRegistrationRequest](), object(
		append(append([]string{}, registrationFields...), "config_version"), withVersion(registrationProps()))},
	"DELETE /admin/organizations/{orgID}/registration": {http.StatusOK, nil, removedSchema},
	"GET /admin/organizations/{orgID}/registration-tokens": {http.StatusOK, nil, object(
		[]string{"org_id", "registration_tokens"}, map[string]jsonSchema{"org_id": uuidStr(),
			"registration_tokens": arrayOf(object([]string{"id", "name", "remaining", "expires_at", "revoked_at", "created_at"},
				map[string]jsonSchema{"id": uuidStr(), "name": str(), "remaining": nullable(integer()),
					"expires_at": nullable(dateTime()), "revoked_at": nullable(dateTime()), "created_at": dateTime()}))})},
	"POST /admin/organizations/{orgID}/registration-tokens": {http.StatusCreated, typeOf[createRegistrationTokenRequest](),
		object([]string{"id", "token", "config_version"}, withVersion(map[string]jsonSchema{"id": uuidStr(), "token": str()}))},
	"DELETE /admin/organizations/{orgID}/registration-tokens/{tokenID}": {http.StatusOK, nil, removedSchema},
	"PATCH /admin/organizations/{orgID}/settings": {http.StatusOK, typeOf[patchOrgSettingsRequest](), object(
		append(orgSettingsFields(), "config_version"), withVersion(orgSettingsProps()))},
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
