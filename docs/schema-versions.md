# Schema versions

Each release's binary expects one schema version and refuses to start against another, unless
the migrations between them were each declared compatible with the release before. This page
is what each version did, in its own words: the first paragraph of each migration's header.
It is generated from the migrations the binary embeds, by `engine/internal/migrate`'s
`TestTheSchemaVersionNotesAreCurrent`; do not edit it by hand. How to upgrade, and what
"compatible" lets you do during one, is in [upgrading.md](upgrading.md).

## 0195 user_handle_any_length

Not compatible with the release before: stop it before migrating.

A user handle of 1 to 64 bytes, as WebAuthn defines one (Web Authentication Level 3, §4 "User Handle", and §5.1.3, which refuses one "not between 1 and 64 bytes"), rather than exactly the 64 this server generates (0.44). An authenticator returns the handle a passkey was registered under, and that handle has to be the account's for either sign-in to accept the passkey. An import gives a person the handle their previous provider registered their passkeys under, and those are other lengths: a handle made from a user's UUID as text is 36 bytes. Handles this server makes are still 64 random bytes.

## 0194 claim_mapper_one_per_audience

Not compatible with the release before: stop it before migrating.

One mapper per audience, attribute and destination, the every-client audience included (0.39). 0113's UNIQUE (org_id, client_id, attribute_id, destination) took a NULL client_id, which is what "every client" is, as distinct from every other NULL, so the upsert declaring a mapper never found an all-clients one to replace: declared again under a new claim name, the attribute was released under both, the name meant to be retired included.

## 0193 organization_budgets

Compatible with the release before: its binary may still serve this schema.

Each organisation's own budget (6.10): how many tokens its clients may be issued, and how many sign-ins its pages may take, a minute. Counted per organisation in core.rate_limits, so one tenant's batch job or sign-in rush spends its own budget and not the deployment's: before, the only limit on sign-in was one bucket in each process that every tenant shared.

## 0192 client_admin_api

Compatible with the release before: its binary may still serve this schema.

Which applications may obtain tokens for the Admin API (6.01): the console, an automation acting as itself. Such a token carries the audience &lt;issuer&gt;/admin, and the Admin API acts on it with the roles its holder is bound to (0191), read per request.

## 0191 admin_role_bindings

Compatible with the release before: its binary may still serve this schema.

Administrative roles (6.01). A binding gives a person, or an application acting as itself, one of the built-in roles in one organisation; what each role may do is the engine's (adminapi.Roles), not a column, so a role means the same thing in every deployment and a release can never widen one by a migration nobody reads.

## 0190 maintenance_reads_ledger

Compatible with the release before: its binary may still serve this schema.

signari_maintenance may read which schema version is applied (6.08). Every other core table it can read by the default privileges 0001 set, and the ledger, made by the bootstrap before them, it could not, so GET /admin/system failed for anything holding that role. Read only: the ledger is written by `signari migrate` alone.

## 0189 user_lookup_indexes

Compatible with the release before: its binary may still serve this schema.

signari:no-transaction

## 0188 consent_lifetime

Not compatible with the release before: stop it before migrating.

How long a person's consent to an application lasts before they are asked again (5.22).

## 0187 new_device_notice

Compatible with the release before: its binary may still serve this schema.

Whether a sign-in from a device the person has not used is told to them (5.21).

## 0186 signup_approval

Not compatible with the release before: stop it before migrating.

An organisation may hold its self-sign-ups for an administrator's approval (5.19).

## 0185 session_persistent

Compatible with the release before: its binary may still serve this schema.

Whether a session was signed in with "stay signed in on this device" ticked (5.17).

## 0184 email_sign_in_codes

Compatible with the release before: its binary may still serve this schema.

A code emailed to the account's address as the first factor (5.16), where an organisation's sign-in flow takes one.

## 0183 prompt_versions

Not compatible with the release before: stop it before migrating.

A prompt that is edited is asked again, and every answer is kept with the version it answered (5.13).

## 0182 persistent_sessions

Compatible with the release before: its binary may still serve this schema.

Whether an organisation offers "stay signed in on this device" (5.11).

## 0181 offline_grants

Not compatible with the release before: stop it before migrating.

A grant of offline_access outlives the session it was given in.

## 0180 session_lifetimes

Not compatible with the release before: stop it before migrating.

How long a session lasts, per organisation, and how long it lasts unused.

## 0179 relations_follow_their_subject

Not compatible with the release before: stop it before migrating.

A deleted person or group takes its relation tuples with it.

## 0178 email_changes

Compatible with the release before: its binary may still serve this schema.

A person changing their own address (5.06). The account keeps its address until a code sent to the new one comes back, so a typo, or somebody holding a session who names a mailbox of theirs and cannot read the code, changes nothing; when it does come back the new address is verified by that proof and the old one is told.

## 0177 email_verifications

Compatible with the release before: its binary may still serve this schema.

An address a person must prove before they are signed in (5.01). A row is written when self-sign-up creates an account under a rule with require_verified_email, which defaulted to true and was consulted by nothing, so a rule naming @example.com let anybody claim any address there. While the row exists the sign-in flow's verify_email stage holds the sign-in and sends a code to the address; the right code sets users.email_verified_at and deletes the row. Accounts an administrator made have none and are not held.

## 0176 passkey_links

Compatible with the release before: its binary may still serve this schema.

An emailed link that lets a person register a passkey without a session (4.24): a new starter with no password, or somebody whose only way in is lost. An administrator issues it; it reaches the account's own email.

## 0175 webauthn_related_origins

Compatible with the release before: its binary may still serve this schema.

Other origins a passkey made under this instance's RP ID may be used from (4.23; WebAuthn Level 3 §5.11, related origin requests): a country domain, a brand domain, an application on another host. The browser checks the list at https://&lt;rp_id&gt;/.well-known/webauthn, which the engine serves when the RP ID is its own host, and the engine accepts a ceremony from each origin listed.

## 0174 acr_ladder

Not compatible with the release before: stop it before migrating.

Two rungs above multi-factor (4.15): "3", multi-factor that includes a WebAuthn assertion, which is bound to this server's origin so a page relaying the sign-in cannot obtain one; and "4", the same with a device-bound key. A client may require either as its floor, and a relying party may ask for either in acr_values.

## 0173 sms_hashed_numbers

Not compatible with the release before: stop it before migrating.

An organisation may keep only a keyed hash of each person's phone number (4.28). The number was stored in the clear, so a read of this table gave every person's number, which is what a SIM swap starts from.

## 0172 sms_delegated_codes

Compatible with the release before: its binary may still serve this schema.

A text-message code a delegated verification service made, sent and will check (4.13, SIGNARI_SMS_GATEWAY=verify-webhook). This engine never holds it: the outstanding code's code_hash is random bytes, the hash of no code, so the purpose-and-hash constraint keeps holding, and code_delegated says the service is to be asked instead.

## 0171 otp_parameters

Compatible with the release before: its binary may still serve this schema.

One-time-code authenticators beyond SHA-1, six digits and thirty seconds (4.12). An organisation chooses what new authenticator apps are enrolled with, and every credential keeps what it was enrolled with, so changing the choice never breaks a phone that already works. A credential is time-based (an app, or a hardware TOTP token) or counter-based (a hardware HOTP token, whose last accepted press is last_used_counter).

## 0170 webauthn_ceremony

Compatible with the release before: its binary may still serve this schema.

What an organisation asks of an authenticator (4.11): user verification at a passkey sign-in, whether registration makes a discoverable credential, which kind of authenticator, which algorithms, how long the browser waits, and the hints it is given. Every one was fixed in code, so an organisation issuing roaming security keys without PINs could not use them, and one that wanted only platform authenticators could not say so.

## 0169 org_login_throttle

Compatible with the release before: its binary may still serve this schema.

The password step's backoff, per organisation (4.06): how many wrong passwords are free before a delay, and the longest the delay grows to. They were constants of three and fifteen minutes. It stays a decaying delay, not a lockout (0011): a lockout is a button that disables any account somebody can name.

## 0168 trusted_devices

Compatible with the release before: its binary may still serve this schema.

A device a person chose to remember after a second factor (4.05), so the organisation's sign-in flow does not ask for one there again for a while.

## 0167 org_reauth_window

Compatible with the release before: its binary may still serve this schema.

How recently a session must have been authenticated for its holder to change the account (4.04): its sign-in methods, its password, which sessions and applications hold it. It was a constant of ten minutes, applied to the sign-in methods only.

## 0166 client_minimum_acr

Compatible with the release before: its binary may still serve this schema.

The weakest authentication a client accepts (4.02). '1' accepts a password alone, which is what every client accepted before; '2' requires multi-factor, whatever the client's own request asks for. A relying party could ask with acr_values, and nothing let the operator require it of an application that does not ask, or that a user could reach with the parameter removed.

## 0165 drop_audit_detail_enc

Not compatible with the release before: stop it before migrating.

core.audit_events.detail_enc is dropped (3.23). It was created for personal detail sealed under the subject's key, so a shred would leave the record and remove its content, and nothing ever wrote it, read it, or hashed it. The trail keeps personal data out instead: rows name people by subject id only, and a test reads the detail every audit write is given and refuses one that names a person. A column that suggests encryption the trail does not have made two documents say the chain covered ciphertext.

## 0164 saml_signature_alg

Compatible with the release before: its binary may still serve this schema.

Which signature algorithm a service provider is signed with (3.15).

## 0163 audit_hash_version

Not compatible with the release before: stop it before migrating.

Which hash each audit row was written under (3.19). Version 2 hashes occurred_at; version 1, every row before this, did not, so a row's time could be rewritten and the chain still verified. The engine now sets occurred_at itself and writes 2. A release before this one writes the default, 1, and its rows keep verifying as 1.

## 0162 restored_reason

Not compatible with the release before: stop it before migrating.

A session ended because the database was restored (3.10). A restore brings back every session as it was at the backup, including the ones ended since, so `signari restore finalize` ends all of them, tells the applications, and records why.

## 0161 relation_check_survives_restore

Not compatible with the release before: stop it before migrating.

A restored database must match its own ledger (3.03). pg_dump writes each CHECK as PostgreSQL renders it and the restore parses that text again; for relation_ids_are_present (0072) the two trees differed, because BETWEEN expands into an AND nested inside the outer one, and the parser flattens a nested AND when it reads the rendering back. So a database restored by the runbook rendered the constraint differently, its fingerprint no longer matched what the ledger recorded, and the engine refused to start on it as drift.

## 0160 ledger_compatibility

Not compatible with the release before: stop it before migrating.

The ledger records whether a binary built for the version before a migration may run against the database it leaves, and which fingerprint scheme computed its fingerprint (3.03).

## 0159 ledger_server_version

Not compatible with the release before: stop it before migrating.

The ledger records which PostgreSQL version computed each fingerprint (3.04). A binary built without a pinned fingerprint now compares the live schema with the ledger's latest row, and refuses to start when they differ: before this it compared nothing, so a hand change within a version went unnoticed by every build that was not pinned, which was every shipped build.

## 0158 users_identifier_cross_field

Not compatible with the release before: stop it before migrating.

One person's username may not be another's email in the same organisation (2.59). Sign-in matches an identifier against either field and refuses when two people match, so a username equal to somebody's address refused both of them. Each field was unique on its own (0002); nothing compared the two, at any of the writers -- the CLI, the Admin API, SCIM, LDAP, federation, sign-up, directory sync and the importers -- so it is refused here, once.

## 0157 resource_servers

Not compatible with the release before: stop it before migrating.

The resource servers an organisation's access tokens may be audienced to.

## 0156 refresh_family_indexes

Not compatible with the release before: stop it before migrating.

signari:no-transaction

## 0155 directory_group_fetch

Not compatible with the release before: stop it before migrating.

Whether a directory source fetches group memberships, and for LDAP from which attribute (2.02).

## 0154 migration_source_ldap

Not compatible with the release before: stop it before migrating.

A migration source can be the directory being migrated from, not only an OAuth provider's password grant.

## 0153 credential_nonce_unscoped

Not compatible with the release before: stop it before migrating.

A c_nonce belongs to no organisation, so the column that said otherwise goes.

## 0152 idp_trusted_mfa

Not compatible with the release before: stop it before migrating.

Which upstream authentication claims an identity provider is trusted to assert multi-factor with.

## 0151 credential_requires_key_attestation

Not compatible with the release before: stop it before migrating.

Whether a credential is issued only on a key proof a trusted attester vouches for (OID4VCI 1.0 Appendix D).

## 0150 credential_proof_roots

Not compatible with the release before: stop it before migrating.

The roots an OID4VCI key proof's `x5c` chain must verify to.

## 0149 drop_access_tokens

Not compatible with the release before: stop it before migrating.

Drops core.access_tokens.

## 0148 drop_projects

Not compatible with the release before: stop it before migrating.

Drops core.projects and clients.project_id.

## 0147 saml_acs_post_only

Not compatible with the release before: stop it before migrating.

An assertion consumer URL's binding may be HTTP-POST only.

## 0146 drop_access_token_format

Not compatible with the release before: stop it before migrating.

Drops clients.access_token_format.

## 0145 drop_pkce_methods

Not compatible with the release before: stop it before migrating.

Drops clients.pkce_methods.

## 0144 client_token_lifetime_bounds

Not compatible with the release before: stop it before migrating.

Bounds on a client's access and refresh token lifetimes, now that they can be set.

## 0143 webauthn_refuse_cloned

Not compatible with the release before: stop it before migrating.

Whether a passkey whose signature counter did not advance is refused, per organisation, on by default.

## 0142 outpost_search_group

Not compatible with the release before: stop it before migrating.

The core, not the outpost, decides who behind an LDAP outpost may read the directory.

## 0141 webauthn_spent_challenges

Not compatible with the release before: stop it before migrating.

A WebAuthn challenge is spent by the first attempt to finish its ceremony.

## 0140 cli_writes_are_audited

Not compatible with the release before: stop it before migrating.

Every operator CLI command that changes something leaves an audit record, without each of its hundred-odd commands having to remember to write one.

## 0139 cli_writes_bump_version

Not compatible with the release before: stop it before migrating.

A write the operator CLI makes moves core.config_version in the same transaction, as an Admin API write does (ADR-008).

## 0138 ssf_source_audience_global

Not compatible with the release before: stop it before migrating.

A Shared Signals source is chosen by its issuer and its audience together, and that pair belongs to one organisation in the whole deployment.

## 0137 public_client_pkce

Not compatible with the release before: stop it before migrating.

A public client requires PKCE, in the schema as well as in the writers.

## 0136 code_factor_failures

Not compatible with the release before: stop it before migrating.

Email and SMS codes stop after a run of wrong guesses, as TOTP and recovery codes do.

## 0135 sms_pending_number

Not compatible with the release before: stop it before migrating.

A new SMS number is held apart from the one that works, as 0126 did for email.

## 0134 proxy_host_global

Not compatible with the release before: stop it before migrating.

A forward-auth protected host belongs to one organisation in the whole deployment.

## 0133 preauth_access_token

Not compatible with the release before: stop it before migrating.

A redeemed credential offer records the access token it minted, so the credential endpoint can tell an issuance token from any other.

## 0132 drop_ciba_notification_token

Not compatible with the release before: stop it before migrating.

The CIBA client notification token no longer sits in a request row.

## 0131 scim_group_ownership

Not compatible with the release before: stop it before migrating.

A SCIM source owns the groups it creates and no others. A group it owns can never let its members impersonate.

## 0130 saml_entity_id_global

Not compatible with the release before: stop it before migrating.

A SAML service provider's entity ID is unique across the deployment, until there are per-organisation SAML endpoints for two tenants to share one.

## 0129 identity_provider_slug_global

Not compatible with the release before: stop it before migrating.

An identity provider's slug is unique across the deployment, not per organisation.

## 0128 password_only_binds

Not compatible with the release before: stop it before migrating.

Whether a protocol that can carry only a password may sign in somebody the sign-in flow would ask for a second factor.

## 0127 factor_failure_ceiling

Not compatible with the release before: stop it before migrating.

A second factor that keeps being guessed at is switched off, not just paused.

## 0126 email_otp_verified

Not compatible with the release before: stop it before migrating.

An email second factor counts only once its address has been proved, and a new address never displaces a proved one until it is proved too.

## 0125 totp_enrolment

Not compatible with the release before: stop it before migrating.

A TOTP enrolment in progress lives apart from the credential it may replace.

## 0124 logout_delivery_tenant

Not compatible with the release before: stop it before migrating.

Stops core_v1.logout_deliveries showing every tenant's sign-outs to any console session.

## 0123 provider_token_hook

Not compatible with the release before: stop it before migrating.

Let the token hook actually be registered.

## 0122 scim_group_links

Not compatible with the release before: stop it before migrating.

Which of our groups is which group at a provisioning target.

## 0121 scim_target_scope

Not compatible with the release before: stop it before migrating.

Which people a provisioning target receives.

## 0120 admin_token_objects

Not compatible with the release before: stop it before migrating.

Narrowing an admin token to named objects.

## 0119 radius_group_vlan

Not compatible with the release before: stop it before migrating.

Network authorisation a RADIUS Access-Accept may carry.

## 0118 directory_group_map

Not compatible with the release before: stop it before migrating.

Mapping a directory's groups onto this deployment's groups.

## 0117 token_hook

Not compatible with the release before: stop it before migrating.

A provider consulted while a token is being minted.

## 0116 webauthn_policy

Not compatible with the release before: stop it before migrating.

Which authenticators an organisation will accept.

## 0115 scopes

Not compatible with the release before: stop it before migrating.

Scopes an organisation defines, as objects rather than strings.

## 0114 idp_attribute_map

Not compatible with the release before: stop it before migrating.

Mapping an upstream provider's claims onto this deployment's attributes.

## 0113 claim_mappers

Not compatible with the release before: stop it before migrating.

Claim mappers: which attribute becomes which claim, for which client.

## 0112 user_profile_schema

Not compatible with the release before: stop it before migrating.

Operator-defined user attributes, and the schema that governs them.

## 0111 user_locale

Not compatible with the release before: stop it before migrating.

A per-user language, for messages the account holder reads.

## 0110 organizations_rls

Not compatible with the release before: stop it before migrating.

Stop the console enumerating every organisation on the instance.

## 0109 providers

Not compatible with the release before: stop it before migrating.

Extension providers: a service the operator runs, which this engine calls to extend a decision it makes (ADR-011).

## 0108 ssf_poll

Not compatible with the release before: stop it before migrating.

Poll-based delivery of Security Event Tokens (RFC 8936).

## 0107 audit_stream_cursor

Not compatible with the release before: stop it before migrating.

A cursor for streaming the audit trail off the box.

## 0106 user_session_revoke

Not compatible with the release before: stop it before migrating.

A revocation reason for a session the user ended themselves, from the self-service account console.

## 0105 ldap_write

Not compatible with the release before: stop it before migrating.

## 0104 uma_claims_gathering

Not compatible with the release before: stop it before migrating.

## 0103 trust_marks

Not compatible with the release before: stop it before migrating.

## 0102 ciba_push

Not compatible with the release before: stop it before migrating.

## 0101 jwt_bearer_client_providers

Not compatible with the release before: stop it before migrating.

## 0100 mtls_san_ip_email

Not compatible with the release before: stop it before migrating.

## 0099 assertion_issuers

Not compatible with the release before: stop it before migrating.

## 0098 jwt_bearer_grant

Not compatible with the release before: stop it before migrating.

## 0097 key_retirement

Not compatible with the release before: stop it before migrating.

Retirement, the last step of the rotation machine that was documented and never built.

## 0096 session_limits

Not compatible with the release before: stop it before migrating.

## 0095 ciba_ping_mode

Not compatible with the release before: stop it before migrating.

## 0094 exchange_audience_match

Not compatible with the release before: stop it before migrating.

## 0093 dpop_bound_access_tokens

Not compatible with the release before: stop it before migrating.

RFC 9449 §5.2 client registration metadata.

## 0092 rls_completeness

Not compatible with the release before: stop it before migrating.

Close the tenant boundary on every table that carries org_id.

## 0091 reauthenticated_reason

Not compatible with the release before: stop it before migrating.

A termination reason for the session replaced by a re-authentication.

## 0090 webauthn_backup_flags

Not compatible with the release before: stop it before migrating.

Carry WebAuthn backup eligibility and backup state on each credential.

## 0089 uma_permission_tickets

Not compatible with the release before: stop it before migrating.

## 0088 backchannel_authentication

Not compatible with the release before: stop it before migrating.

## 0087 sign_in_flows

Not compatible with the release before: stop it before migrating.

The sign-in flow in force, as the file an operator wrote.

## 0086 ssf_critical_subject_members

Not compatible with the release before: stop it before migrating.

Shared Signals Framework 1.0 §3.6 and §7.1: critical subject members.

## 0085 client_attestation

Not compatible with the release before: stop it before migrating.

OAuth 2.0 Attestation-Based Client Authentication, draft-ietf-oauth-attestation-based-client-auth-10 (6 July 2026).

## 0084 refresh_cert_binding

Not compatible with the release before: stop it before migrating.

RFC 8705 §4: bind a public client's refresh token to its certificate.

## 0083 refresh_dpop_binding

Not compatible with the release before: stop it before migrating.

RFC 9449 §5: bind a public client's refresh token to its DPoP key.

## 0082 credential_nonce_scope

Not compatible with the release before: stop it before migrating.

A c_nonce is not organisation data.

## 0081 credential_issuance

Not compatible with the release before: stop it before migrating.

OID4VCI Credential Issuer: the half we did not implement.

## 0080 authorization_details

Not compatible with the release before: stop it before migrating.

RFC 9396 Rich Authorization Requests.

## 0079 scim_source_groups

Not compatible with the release before: stop it before migrating.

## 0078 oid4vci_client

Not compatible with the release before: stop it before migrating.

Bind a pre-authorized code to the client it was issued for.

## 0077 oid4vci

Not compatible with the release before: stop it before migrating.

OpenID for Verifiable Credential Issuance 1.0 (Final, 16 September 2025): the Pre-Authorized Code grant.

## 0076 dpop_jkt

Not compatible with the release before: stop it before migrating.

RFC 9449 §10: Authorization Code Binding to a DPoP Key.

## 0075 federation_key_index

Not compatible with the release before: stop it before migrating.

The one-active-key constraint has to know about purpose.

## 0074 federation

Not compatible with the release before: stop it before migrating.

OpenID Federation 1.0 (Final, 17 February 2026): Entity Configuration.

## 0073 ssf_receiver

Not compatible with the release before: stop it before migrating.

## 0072 authorization

Not compatible with the release before: stop it before migrating.

The authorization layer: answering "may Alice edit document 42?"

## 0071 webhooks

Not compatible with the release before: stop it before migrating.

Event subscriptions: telling other systems what happened here.

## 0070 impersonation

Not compatible with the release before: stop it before migrating.

Support access: an administrator acting as a user, visibly.

## 0069 password_must_change

Not compatible with the release before: stop it before migrating.

## 0068 password_history

Not compatible with the release before: stop it before migrating.

Previous passwords, so one cannot be reused.

## 0067 more_social_providers

Not compatible with the release before: stop it before migrating.

Slack and Atlassian as federated sign-in providers.

## 0066 desktop_outposts

Not compatible with the release before: stop it before migrating.

Outposts that authenticate a desktop or a workstation login.

## 0065 prompts

Not compatible with the release before: stop it before migrating.

Questions asked during sign-in: terms acceptance, a missing field, a notice.

## 0064 native_target_urls

Not compatible with the release before: stop it before migrating.

A native provisioning target has no base URL to be https.

## 0063 native_provisioning_targets

Not compatible with the release before: stop it before migrating.

Provisioning targets that are not SCIM servers.

## 0062 more_social_providers

Not compatible with the release before: stop it before migrating.

Apple, GitLab, Discord, Twitch and LinkedIn as federated sign-in providers.

## 0061 hybrid_and_form_post

Not compatible with the release before: stop it before migrating.

## 0060 outposts

Not compatible with the release before: stop it before migrating.

Protocol servers running somewhere the database must not be reachable from.

## 0059 invitation_claim_fix

Not compatible with the release before: stop it before migrating.

Let an invitation be claimed before the account it creates exists.

## 0058 invitation_rls_fix

Not compatible with the release before: stop it before migrating.

Let the engine read the tables it has to read before anyone has signed in.

## 0057 invitations_and_signup

Not compatible with the release before: stop it before migrating.

Getting a new person an account.

## 0056 brands

Not compatible with the release before: stop it before migrating.

An organisation's appearance on the pages a user sees.

## 0055 app_portal

Not compatible with the release before: stop it before migrating.

What a user sees when they ask "what can I get into?"

## 0054 saml_key_transport

Not compatible with the release before: stop it before migrating.

Which RSA key transport algorithm to use when encrypting assertions.

## 0053 rac_connections

Not compatible with the release before: stop it before migrating.

Remote access: which hosts a person may reach through the browser.

## 0052 rate_limits

Not compatible with the release before: stop it before migrating.

Rate limits that survive more than one instance.

## 0051 duo

Not compatible with the release before: stop it before migrating.

Duo Universal Prompt as a second factor.

## 0050 sms_otp

Not compatible with the release before: stop it before migrating.

SMS as a second factor.

## 0049 scim_sources

Not compatible with the release before: stop it before migrating.

## 0048 saml_sources

Not compatible with the release before: stop it before migrating.

## 0047 ldap_ca

Not compatible with the release before: stop it before migrating.

An LDAP source's CA bundle.

## 0046 ldap_source

Not compatible with the release before: stop it before migrating.

LDAP as a directory SOURCE.

## 0045 directory_sources

Not compatible with the release before: stop it before migrating.

## 0044 mtls_client_auth

Not compatible with the release before: stop it before migrating.

## 0043 audit_is_immutable

Not compatible with the release before: stop it before migrating.

An audit row must never be mutated. Not even by a foreign key.

## 0042 drop_redundant_enrolled_at

Not compatible with the release before: stop it before migrating.

Drop email_otp_credentials.enrolled_at.

## 0041 dynamic_registration

Not compatible with the release before: stop it before migrating.

Dynamic client registration, RFC 7591 and RFC 7592.

## 0040 email_otp

Not compatible with the release before: stop it before migrating.

Email as a second factor.

## 0039 device_authorization

Not compatible with the release before: stop it before migrating.

The device authorization grant, RFC 8628.

## 0038 policy_view

Not compatible with the release before: stop it before migrating.

## 0037 radius_clients

Not compatible with the release before: stop it before migrating.

RADIUS clients: the network devices permitted to ask.

## 0036 console_read_models

Not compatible with the release before: stop it before migrating.

Console visibility for everything built after the first week.

## 0035 admin_tokens

Not compatible with the release before: stop it before migrating.

Admin API tokens with scopes and an organisation boundary.

## 0034 saml_encryption

Not compatible with the release before: stop it before migrating.

SAML assertion encryption.

## 0033 auth_locations

Not compatible with the release before: stop it before migrating.

Where authentications came from, for impossible-travel detection.

## 0032 ssf

Not compatible with the release before: stop it before migrating.

Shared Signals Framework streams, and CAEP events.

## 0031 frontchannel_logout

Not compatible with the release before: stop it before migrating.

OpenID Connect Front-Channel Logout 1.0.

## 0030 access_policies

Not compatible with the release before: stop it before migrating.

The access policy in force, as the file an operator wrote.

## 0029 par

Not compatible with the release before: stop it before migrating.

Pushed Authorization Requests (RFC 9126).

## 0028 confidential_client_credential

Not compatible with the release before: stop it before migrating.

A confidential client must hold SOME credential. Until now that meant a secret, because a secret was the only kind there was.

## 0027 private_key_jwt

Not compatible with the release before: stop it before migrating.

Client authentication with a signed assertion instead of a shared secret (OIDC Core §9, RFC 7523).

## 0026 dpop

Not compatible with the release before: stop it before migrating.

Replay detection for DPoP proofs (RFC 9449 §11.1).

## 0025 groups

Not compatible with the release before: stop it before migrating.

Groups, and the release of group membership as a claim.

## 0024 scim

Not compatible with the release before: stop it before migrating.

Outbound SCIM 2.0 provisioning: pushing users to downstream applications so they exist there before first sign-in, and -- far more importantly -- stop existing there when they leave.

## 0023 trust_email_verification

Not compatible with the release before: stop it before migrating.

## 0022 identity_providers

Not compatible with the release before: stop it before migrating.

## 0021 saml_logout_progress

Not compatible with the release before: stop it before migrating.

Front-channel single logout is a redirect CHAIN, and a chain needs state.

## 0020 saml_certificates

Not compatible with the release before: stop it before migrating.

SAML needs an X.509 certificate where OIDC needs only a public key.

## 0019 saml

Not compatible with the release before: stop it before migrating.

## 0018 engine_rls_access

Not compatible with the release before: stop it before migrating.

THE ENGINE COULD NOT READ ITS OWN TABLES.

## 0017 proxy_hosts

Not compatible with the release before: stop it before migrating.

The hosts forward authentication will protect, and redirect back to.

## 0016 token_exchange

Not compatible with the release before: stop it before migrating.

RFC 8693 token exchange, off by default per client.

## 0015 per_client_issuer

Not compatible with the release before: stop it before migrating.

Per-client issuer override, so an OAuth migration becomes a DNS change.

## 0014 migration_sources

Not compatible with the release before: stop it before migrating.

## 0013 logout_delivery_view

Not compatible with the release before: stop it before migrating.

Makes back-channel logout DELIVERY visible to an operator.

## 0012 account_recovery

Not compatible with the release before: stop it before migrating.

Account recovery, built as delay-and-notify.

## 0011 login_throttle

Not compatible with the release before: stop it before migrating.

Per-account login throttling, replacing a single global bucket.

## 0010 first_party_clients

Not compatible with the release before: stop it before migrating.

Marks the clients that may skip the consent screen.

## 0009 rp_id_per_instance

Not compatible with the release before: stop it before migrating.

The WebAuthn RP ID, as configuration rather than a constant, with its irreversibility ENFORCED instead of documented.

## 0008 mfa_replay_and_recovery

Not compatible with the release before: stop it before migrating.

Two things TOTP needs that the original schema did not model.

## 0007 revoked_jtis

Not compatible with the release before: stop it before migrating.

Makes RFC 7009 revocation of an ACCESS token mean something.

## 0006 view_arrays_as_json

Not compatible with the release before: stop it before migrating.

Emits array-valued columns in core_v1 as JSON rather than PostgreSQL arrays.

## 0005 optional_pkce

Not compatible with the release before: stop it before migrating.

Models an authorization code that carries no PKCE challenge.

## 0004 session_cookie_split

Not compatible with the release before: stop it before migrating.

Separates the session's PUBLIC identifier from its SECRET bearer token.

## 0003 rls_and_views

Not compatible with the release before: stop it before migrating.

Row-level security as a backstop, and the versioned read-only view contract.

## 0002 core

Not compatible with the release before: stop it before migrating.

## 0001 bootstrap

The bootstrap: roles, schemas and grants, run once with a superuser.

Roles, schemas, and the privilege boundary between the Go engine and the Laravel admin.
