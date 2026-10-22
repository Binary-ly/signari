package audit

import "sort"

// EventTypes is every event type the engine audits, which is every type an
// event subscription can receive: Write publishes each one it records.
//
// `signari events subscribe` checks a name against this, so a typo is refused
// instead of creating a subscription to nothing. docsync's
// TestEveryEventTypeIsRegisteredAndCatalogued keeps it equal to the types the
// source actually writes and to the catalogue in docs/events.md. Sorted.
var EventTypes = []string{
	"account.deleted", "account.exported", "account.migrated", "account.password_reset", "account.recovery_cancelled",
	"account.recovery_factor_proven",
	"account.recovery_requested",
	"admin.attribute_declared", "admin.attributes_set", "admin.claim_mapper_created",
	"admin.claim_mapper_deleted", "admin.cli_command", "admin.client_created",
	"admin.client_deleted", "admin.client_secret_rotated", "admin.client_updated",
	"admin.factor_removed", "admin.group_created", "admin.group_deleted",
	"admin.group_member_added", "admin.group_member_removed", "admin.group_updated",
	"admin.identity_provider_updated", "admin.invitation_created", "admin.invitation_revoked",
	"admin.migration_source_removed", "admin.migration_source_set",
	"admin.organization_created", "admin.passkey_link_issued", "admin.privileged_refused",
	"admin.proxy_host_removed",
	"admin.proxy_host_set", "admin.resource_server_removed", "admin.resource_server_set",
	"admin.scim_source_updated", "admin.scope_declared",
	"admin.scope_deleted", "admin.session_revoked", "admin.sessions_revoked",
	"admin.subject_erased", "admin.subject_exported", "admin.user_approved", "admin.user_created",
	"admin.user_deleted", "admin.user_unlocked",
	"admin.user_updated",
	"admin.webauthn_policy_set",
	"audit.archived", "audit.checkpoint", "audit.head_signed",
	"ciba.approved", "ciba.denied", "ciba.requested", "ciba.step_up_required",
	"ciba.unknown_subject",
	"config.applied",
	"consent.withdrawn",
	"desktop.login",
	"directory.groups_synced", "directory.privileged_skipped",
	"federation.account_linked", "federation.account_unlinked", "federation.refused",
	"federation.user_created",
	"impersonation.ended", "impersonation.refused", "impersonation.started",
	"keys.rotated",
	"ldap.entry_created", "ldap.entry_deleted", "ldap.entry_modified", "ldap.entry_renamed",
	"ldap.password_set", "ldap.write_refused",
	"login.failed", "login.succeeded",
	"mfa.device_forgotten", "mfa.device_remembered",
	"mfa.duo_failed", "mfa.duo_succeeded", "mfa.duo_unavailable", "mfa.email_otp_enrolled",
	"mfa.email_otp_removed", "mfa.factor_disabled", "mfa.otp_token_assigned", "mfa.passkey_backup_lost", "mfa.passkey_counter_regression",
	"mfa.passkey_link_used", "mfa.passkey_notice_failed", "mfa.passkey_refused", "mfa.passkey_registered",
	"mfa.passkey_removed", "mfa.recovery_codes_regenerated", "mfa.skipped_duo_unavailable",
	"mfa.sms_enrolled", "mfa.sms_removed", "mfa.totp_enrolled", "mfa.totp_removed",
	"oauth.code_reused", "oauth.consent_denied", "oauth.consent_granted",
	"oauth.refresh_reused", "oauth.token_exchanged", "oauth.token_revoked",
	"oid4vci.credential_issued",
	"org.login_throttle_set", "org.new_device_notice_set", "org.password_only_binds_set", "org.reauth_window_set",
	"org.remember_device_set", "org.session_lifetime_set", "org.sms_numbers_set", "org.totp_policy_set",
	"password.breached", "password.changed",
	"prompt.answered",
	"proxy.host_added", "proxy.host_disabled", "proxy.host_enabled", "proxy.host_removed",
	"proxy.session_issued",
	"rac.session_ended", "rac.session_requested",
	"restore.finalized",
	"saml.assertion_issued", "saml.logout_completed", "saml.logout_propagated",
	"scim.group_deprovisioned", "scim.group_membership_changed", "scim.group_provisioned",
	"scim.group_replaced", "scim.privileged_kept", "scim.privileged_refused",
	"scim.user_deprovisioned", "scim.user_patched", "scim.user_provisioned",
	"scim.user_replaced",
	"session.logout", "session.user_revoked",
	"sms.refused",
	"ssf.received",
	"token.vetoed",
	"txntoken.issued",
	"uma.claims_gathered", "uma.denied", "uma.granted", "uma.submitted",
	"user.attributes_updated", "user.created", "user.email_changed", "user.email_verified",
	"user.password_removed",
	"wsfed.token_issued",
}

// InstanceEventTypes are recorded for the instance, never an organisation, so
// Write's fan-out, which is per organisation, sends them to no subscription.
// They are read from the audit trail; subscribing to one is refused rather
// than stored to receive nothing.
var InstanceEventTypes = []string{"keys.rotated"}

// IsEventType reports whether t is a type the engine records.
func IsEventType(t string) bool {
	i := sort.SearchStrings(EventTypes, t)
	return i < len(EventTypes) && EventTypes[i] == t
}
