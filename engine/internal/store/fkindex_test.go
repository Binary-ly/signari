package store

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// Every foreign key in core has an index leading with its columns, or is in
// knownUnindexedFKs with why (3.30). A foreign key with no index makes every
// delete of the row it points at, and every lookup by it, scan the table:
// refresh_token_families had only its primary key, so ending a session, a
// consent withdrawal and the janitor's expired-session sweep each read every
// refresh family there was. A partial index does not count: the cascade from
// a delete has no predicate to match it.
//
// The backlog may only shrink. A foreign key added without an index fails
// here, naming it.

const (
	unindexedOrg = "an organisation is deleted rarely, by an operator, and its cascade may " +
		"scan this table; the request path filters by a key that is indexed"
	unindexedUser    = "backlog: deleting or erasing a person scans this table for their rows"
	unindexedClient  = "backlog: deleting a client scans this table for its rows"
	unindexedSession = "backlog: each expired session the janitor deletes scans this table"
	unindexedBacklog = "backlog: deleting the referenced row scans this table"
)

var knownUnindexedFKs = map[string]string{
	"attestation_challenges.org_id":             unindexedOrg,
	"auth_locations.org_id":                     unindexedOrg,
	"authorization_codes.client_id":             unindexedClient,
	"authorization_codes.org_id":                unindexedOrg,
	"authorization_codes.sid":                   unindexedSession,
	"authorization_codes.user_id":               unindexedUser,
	"authorization_models.updated_by":           unindexedUser,
	"claim_mappers.attribute_id":                unindexedBacklog,
	"claim_mappers.client_id":                   unindexedClient,
	"client_authorization_detail_types.org_id":  unindexedOrg,
	"client_group_release.org_id":               unindexedOrg,
	"consents.client_id":                        unindexedClient,
	"device_authorizations.client_id":           unindexedClient,
	"device_authorizations.org_id":              unindexedOrg,
	"device_authorizations.user_id":             unindexedUser,
	"directory_group_map.group_id":              unindexedBacklog,
	"directory_group_map.org_id":                unindexedOrg,
	"directory_links.org_id":                    unindexedOrg,
	"duo_challenges.org_id":                     unindexedOrg,
	"duo_challenges.user_id":                    unindexedUser,
	"duo_enrollments.org_id":                    unindexedOrg,
	"event_deliveries.subscription_id":          unindexedBacklog,
	"federated_identities.org_id":               unindexedOrg,
	"federated_logins.link_user_id":             unindexedUser,
	"federated_logins.org_id":                   unindexedOrg,
	"federated_logins.provider_id":              unindexedBacklog,
	"federation_trust_marks_issued.instance_id": unindexedBacklog,
	"group_members.added_by":                    unindexedUser,
	"group_members.org_id":                      unindexedOrg,
	"identity_providers.org_id":                 unindexedOrg,
	"idp_attribute_map.attribute_id":            unindexedBacklog,
	"idp_attribute_map.org_id":                  unindexedOrg,
	"impersonations.actor_id":                   unindexedUser,
	"impersonations.org_id":                     unindexedOrg,
	"impersonations.sid":                        unindexedSession,
	"invitations.created_by":                    unindexedUser,
	"invitations.used_by":                       unindexedUser,
	"password_credentials.org_id":               unindexedOrg,
	"password_history.org_id":                   unindexedOrg,
	"preauthorized_codes.client_id":             unindexedClient,
	"preauthorized_codes.org_id":                unindexedOrg,
	"preauthorized_codes.user_id":               unindexedUser,
	"prompt_responses.org_id":                   unindexedOrg,
	"pushed_requests.client_id":                 unindexedClient,
	"pushed_requests.org_id":                    unindexedOrg,
	"rac_sessions.connection_id":                unindexedBacklog,
	"rac_sessions.org_id":                       unindexedOrg,
	"radius_group_authorization.group_id":       unindexedBacklog,
	"recovery_code_failures.org_id":             unindexedOrg,
	"recovery_codes.org_id":                     unindexedOrg,
	"recovery_codes.user_id":                    unindexedUser,
	"recovery_requests.org_id":                  unindexedOrg,
	"recovery_requests.user_id":                 unindexedUser,
	"refresh_token_families.client_id":          unindexedClient,
	"refresh_token_families.org_id":             unindexedOrg,
	// The live families by person and client are indexed (0156); this is the
	// cascade from deleting the person, which reads revoked families too.
	"refresh_token_families.user_id":        unindexedUser,
	"registration_tokens.org_id":            unindexedOrg,
	"relations.granted_by":                  unindexedUser,
	"revoked_jtis.client_id":                unindexedClient,
	"saml_group_release.org_id":             unindexedOrg,
	"saml_logout_progress.org_id":           unindexedOrg,
	"saml_logout_progress.user_id":          unindexedUser,
	"saml_name_ids.org_id":                  unindexedOrg,
	"saml_name_ids.user_id":                 unindexedUser,
	"saml_seen_requests.org_id":             unindexedOrg,
	"saml_seen_requests.provider_id":        unindexedBacklog,
	"saml_session_participants.org_id":      unindexedOrg,
	"saml_session_participants.provider_id": unindexedBacklog,
	"saml_source_requests.provider_id":      unindexedBacklog,
	"saml_sources.org_id":                   unindexedOrg,
	"scim_group_links.org_id":               unindexedOrg,
	"scim_links.org_id":                     unindexedOrg,
	"scim_source_links.user_id":             unindexedUser,
	"scim_targets.scope_group_id":           unindexedBacklog,
	"session_clients.client_id":             unindexedClient,
	"sessions.impersonator_id":              unindexedUser,
	"sessions.org_id":                       unindexedOrg,
	// Live sessions by person are indexed (sessions_user_live_idx); this is
	// the cascade from deleting the person.
	"sessions.user_id":                          unindexedUser,
	"sms_otp_credentials.org_id":                unindexedOrg,
	"ssf_received.user_id":                      unindexedUser,
	"ssf_streams.org_id":                        unindexedOrg,
	"totp_credentials.org_id":                   unindexedOrg,
	"totp_enrolments.org_id":                    unindexedOrg,
	"uma_claims_interactions.client_id":         unindexedClient,
	"uma_claims_interactions.org_id":            unindexedOrg,
	"uma_claims_interactions.requesting_party":  unindexedUser,
	"uma_pending_requests.client_id":            unindexedClient,
	"uma_pending_requests.decided_by":           unindexedUser,
	"uma_pending_requests.org_id":               unindexedOrg,
	"uma_pending_requests.requesting_party":     unindexedUser,
	"uma_pending_requests.resource_server":      unindexedClient,
	"uma_permission_tickets.bound_client":       unindexedClient,
	"uma_permission_tickets.org_id":             unindexedOrg,
	"uma_permission_tickets.pending_request_id": unindexedBacklog,
	"uma_permission_tickets.requesting_party":   unindexedUser,
	"uma_permission_tickets.resource_server":    unindexedClient,
	"user_attributes.attribute_id":              unindexedBacklog,
	"user_attributes.org_id":                    unindexedOrg,
	"users.migration_source_id":                 unindexedBacklog,
	"webauthn_credentials.org_id":               unindexedOrg,
}

func TestEveryForeignKeyIsIndexedOrExplained(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	rows, err := conn.Query(ctx, `
		WITH fk AS (
		  SELECT c.conrelid, c.conkey, replace(c.conrelid::regclass::text, 'core.', '') AS tbl,
		         (SELECT string_agg(a.attname, ',' ORDER BY k.ord)
		            FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
		            JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum) AS cols
		    FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
		   WHERE c.contype = 'f' AND n.nspname = 'core')
		SELECT fk.tbl || '.' || fk.cols FROM fk
		 WHERE NOT EXISTS (
		   SELECT 1 FROM pg_index i
		    WHERE i.indrelid = fk.conrelid AND i.indpred IS NULL
		      AND (i.indkey::int2[])[0:array_length(fk.conkey, 1) - 1] = fk.conkey)`)
	must(t, err)
	unindexed := map[string]bool{}
	for rows.Next() {
		var key string
		must(t, rows.Scan(&key))
		unindexed[key] = true
	}
	rows.Close()
	must(t, rows.Err())

	var missing, stale []string
	for key := range unindexed {
		if _, known := knownUnindexedFKs[key]; !known {
			missing = append(missing, key)
		}
	}
	for key := range knownUnindexedFKs {
		if !unindexed[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("foreign keys with no index leading with their columns: %s\n\nEvery delete of the "+
			"row they point at, and every lookup by them, scans the table. Index them in a "+
			"`-- signari:no-transaction` migration, or add them to knownUnindexedFKs with why.",
			strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("knownUnindexedFKs lists %s, which now have an index; remove them, so the backlog "+
			"only shrinks", strings.Join(stale, ", "))
	}
}
