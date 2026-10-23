package config

import (
	"sort"
	"testing"
)

// Every table holding an organisation's rows is one a configuration file
// declares, or this says why not (6.19). The list of tables is the schema's,
// so a table added later is named by this test until it is one or the other:
// a setting an operator can change by command and not by file is the drift a
// file exists to end, and finding it is cheaper here than in an export that
// silently left it behind.

// declaredBy is the kind a table's rows are written by.
var declaredBy = map[string]string{
	"access_policies": "access_policy", "claim_mappers": "claim_mapper", "clients": "client",
	"event_subscriptions": "event_subscription", "groups": "group", "identity_providers": "identity_provider",
	"idp_attribute_map": "identity_provider", "saml_sources": "identity_provider", "prompts": "prompt",
	"providers": "provider", "proxy_hosts": "proxy_host", "rac_connections": "rac_connection",
	"radius_clients": "radius_client", "resource_servers": "resource", "saml_providers": "saml_provider",
	"scim_targets": "scim_target", "scopes": "scope", "sign_in_flows": "sign_in_flow", "signup_rules": "signup",
	"user_attribute_schema": "attribute",
}

const (
	person = "a person's own: who they are, what they hold or answered, written by them or for them as they " +
		"sign up, sign in and enrol, never by a file describing the organisation"
	running = "what happened or is under way: a sign-in, a code, a token, a delivery, the audit trail; it is " +
		"made by use and expires or is kept as the record"
	found = "what a sync or a federation found and keeps so it can be undone, not a setting: an export of it " +
		"would claim accounts at the far end that a fresh deployment never made"
	credential = "a credential minted and shown once, hashed here; a file would either hold it or print a new " +
		"one into a CI log"
)

// notConfiguration is a table whose rows are not the organisation's
// configuration, and why.
var notConfiguration = map[string]string{
	"admin_role_bindings": "who may administer the deployment: granted by the privileged routes, never by a " +
		"file that a token holding organizations:write may apply",
	"admin_tokens": credential, "registration_tokens": credential,
	"relations": "authorization data the application writes as people and objects come and go, as group " +
		"membership is: the model they are checked against is configuration, the tuples are not",

	"auth_locations": person, "duo_enrollments": person, "email_changes": person, "email_otp_credentials": person,
	"federated_identities": person, "group_members": person, "passkey_links": person,
	"password_credentials": person, "password_history": person, "prompt_responses": person,
	"recovery_codes": person, "saml_name_ids": person, "sms_otp_credentials": person,
	"totp_credentials": person, "totp_enrolments": person, "trusted_devices": person,
	"user_attributes": person, "users": person, "webauthn_credentials": person,

	"attestation_challenges": running, "audit_events": running, "authorization_codes": running,
	"device_authorizations": running, "duo_challenges": running, "email_sign_in_codes": running,
	"email_verifications": running, "event_deliveries": running, "federated_logins": running,
	"impersonations": running, "invitations": running, "preauthorized_codes": running,
	"pushed_requests": running, "rac_sessions": running, "recovery_code_failures": running,
	"recovery_requests": running, "refresh_token_families": running, "saml_logout_progress": running,
	"saml_seen_requests": running, "saml_session_participants": running, "sessions": running,
	"ssf_received": running, "uma_claims_interactions": running, "uma_pending_requests": running,
	"uma_permission_tickets": running,

	"directory_links": found, "scim_group_links": found, "scim_links": found,
}

// notYet is configuration a file does not declare yet, each set by its own
// command and Admin API route meanwhile: ROADMAP 6.25.
var notYet = map[string]bool{
	"authorization_detail_types": true, "authorization_models": true, "client_attesters": true,
	"client_authorization_detail_types": true, "client_group_release": true, "credential_configurations": true,
	"credential_proof_roots": true, "directory_group_map": true, "directory_sources": true,
	"duo_integrations": true, "migration_sources": true, "outposts": true, "radius_group_authorization": true,
	"registration_policies": true, "saml_group_release": true, "scim_sources": true, "ssf_sources": true,
	"ssf_streams": true, "uma_settings": true, "webauthn_policy": true,
}

func TestEveryOrganisationTableIsDeclarableOrSaysWhyNot(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	rows, err := pool.Query(ctx, `
		SELECT c.table_name FROM information_schema.columns c
		  JOIN information_schema.tables t USING (table_schema, table_name)
		 WHERE c.table_schema = 'core' AND c.column_name = 'org_id' AND t.table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables[name] = true
	}
	rows.Close()
	if len(tables) == 0 {
		t.Fatal("no organisation tables found; the query, not the schema, is wrong")
	}

	builtin := map[string]bool{"group": true, "client": true, "saml_provider": true, "radius_client": true,
		"proxy_host": true}
	var names []string
	for n := range tables {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		kind, declared := declaredBy[name]
		_, exempt := notConfiguration[name]
		places := 0
		for _, in := range []bool{declared, exempt, notYet[name]} {
			if in {
				places++
			}
		}
		switch {
		case places == 0:
			t.Errorf("core.%s holds an organisation's rows and nothing here says whether a configuration file "+
				"declares them: give it a kind, or a reason in notConfiguration", name)
		case places > 1:
			t.Errorf("core.%s is listed in more than one place", name)
		case declared && sectionOf(kind) == nil && !builtin[kind]:
			t.Errorf("core.%s is said to be declared by %q, which is no kind a file has", name, kind)
		}
	}
	for _, list := range []map[string]bool{keySet(declaredBy), keySet(notConfiguration), notYet} {
		for name := range list {
			if !tables[name] {
				t.Errorf("%s is listed here and is no organisation table", name)
			}
		}
	}
}

func keySet[V any](m map[string]V) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}
