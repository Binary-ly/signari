# Admin API reference

Generated from [admin-openapi.json](admin-openapi.json), which the router draws, by
`engine/internal/sdkgen`; do not edit it by hand. What each operation is for, and the
rules around it, are in [admin-api.md](admin-api.md). Every write takes `If-Match` and is
refused with `412` when the configuration moved since the version it names.

| Section | Operations |
|---|---|
| [access-policy](#access-policy) | 2 |
| [attesters](#attesters) | 3 |
| [attributes](#attributes) | 2 |
| [audit-events](#audit-events) | 1 |
| [authorization-detail-types](#authorization-detail-types) | 3 |
| [authorization-model](#authorization-model) | 2 |
| [batch](#batch) | 1 |
| [budgets](#budgets) | 2 |
| [claim-mappers](#claim-mappers) | 3 |
| [clients](#clients) | 5 |
| [clients / group-release](#clients--group-release) | 3 |
| [clients / rotate-secret](#clients--rotate-secret) | 1 |
| [clients / ssf-stream](#clients--ssf-stream) | 1 |
| [config](#config) | 1 |
| [config-version](#config-version) | 1 |
| [credential-configurations](#credential-configurations) | 2 |
| [credential-proof-roots](#credential-proof-roots) | 3 |
| [directories](#directories) | 6 |
| [duo](#duo) | 2 |
| [event-subscriptions](#event-subscriptions) | 6 |
| [groups](#groups) | 5 |
| [groups / members](#groups--members) | 3 |
| [groups / radius](#groups--radius) | 2 |
| [identity-providers](#identity-providers) | 5 |
| [instances](#instances) | 1 |
| [instances / brand](#instances--brand) | 3 |
| [instances / federation](#instances--federation) | 2 |
| [instances / held-trust-marks](#instances--held-trust-marks) | 2 |
| [instances / issuer-aliases](#instances--issuer-aliases) | 3 |
| [instances / keys](#instances--keys) | 3 |
| [instances / trust-mark-delegations](#instances--trust-mark-delegations) | 1 |
| [instances / trust-marks](#instances--trust-marks) | 3 |
| [instances / webauthn](#instances--webauthn) | 2 |
| [invitations](#invitations) | 3 |
| [me](#me) | 1 |
| [migration-source](#migration-source) | 3 |
| [organizations](#organizations) | 4 |
| [outposts](#outposts) | 3 |
| [prompts](#prompts) | 3 |
| [providers](#providers) | 5 |
| [proxy-hosts](#proxy-hosts) | 3 |
| [rac-connections](#rac-connections) | 3 |
| [radius-authorizations](#radius-authorizations) | 1 |
| [radius-clients](#radius-clients) | 3 |
| [registration](#registration) | 3 |
| [registration-tokens](#registration-tokens) | 3 |
| [relations](#relations) | 2 |
| [resource-servers](#resource-servers) | 3 |
| [role-bindings](#role-bindings) | 3 |
| [saml-providers](#saml-providers) | 7 |
| [scim-sources](#scim-sources) | 3 |
| [scim-targets](#scim-targets) | 6 |
| [scopes](#scopes) | 3 |
| [sessions](#sessions) | 1 |
| [settings](#settings) | 2 |
| [sign-in-flow](#sign-in-flow) | 2 |
| [signup](#signup) | 3 |
| [ssf-sources](#ssf-sources) | 2 |
| [ssf-streams](#ssf-streams) | 2 |
| [subjects](#subjects) | 2 |
| [system](#system) | 1 |
| [tokens](#tokens) | 4 |
| [uma](#uma) | 5 |
| [users](#users) | 5 |
| [users / attributes](#users--attributes) | 3 |
| [users / consents](#users--consents) | 2 |
| [users / credential-offers](#users--credential-offers) | 1 |
| [users / duo](#users--duo) | 1 |
| [users / factors](#users--factors) | 3 |
| [users / identity-links](#users--identity-links) | 3 |
| [users / passkey-link](#users--passkey-link) | 1 |
| [users / sessions](#users--sessions) | 2 |
| [users / throttle](#users--throttle) | 1 |
| [webauthn-policy](#webauthn-policy) | 2 |

## access-policy

### `GET /admin/organizations/{orgID}/access-policy`

The access policy in force, as applied; none allows everything. Needs config:read.

Go `GetOrganizationsOrgIDAccessPolicy`, TypeScript `getOrganizationsOrgIDAccessPolicy`.

Answers:

| Field | Type | |
|---|---|---|
| `applied_at` | string or null | always |
| `document` | string | always |
| `org_id` | string | always |

### `PUT /admin/organizations/{orgID}/access-policy`

Put a policy document in force once it loads and its tests pass. Needs organizations:write.

Go `PutOrganizationsOrgIDAccessPolicy`, TypeScript `putOrganizationsOrgIDAccessPolicy`.

Takes:

| Field | Type | |
|---|---|---|
| `document` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `org_id` | string | always |
| `summary` | string | always |

## attesters

### `GET /admin/organizations/{orgID}/attesters`

The attesters whose client attestations the organisation accepts. Needs config:read.

Go `GetOrganizationsOrgIDAttesters`, TypeScript `getOrganizationsOrgIDAttesters`.

Answers:

| Field | Type | |
|---|---|---|
| `attesters` | list of object | always |
| `org_id` | string | always |

### `DELETE /admin/organizations/{orgID}/attesters/{name}`

Stop trusting an attester. Needs organizations:write.

Go `DeleteOrganizationsOrgIDAttestersName`, TypeScript `deleteOrganizationsOrgIDAttestersName`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `PUT /admin/organizations/{orgID}/attesters/{name}`

Trust an attester's public keys, or replace them. Needs organizations:write.

Go `PutOrganizationsOrgIDAttestersName`, TypeScript `putOrganizationsOrgIDAttestersName`.

Takes:

| Field | Type | |
|---|---|---|
| `description` | string |  |
| `jwks` | any |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `keys` | integer | always |
| `name` | string | always |

## attributes

### `GET /admin/organizations/{orgID}/attributes`

The organisation's user attribute declarations. Needs config:read.

Go `GetOrganizationsOrgIDAttributes`, TypeScript `getOrganizationsOrgIDAttributes`.

Answers:

| Field | Type | |
|---|---|---|
| `attributes` | list of object | always |

### `PUT /admin/organizations/{orgID}/attributes`

Declare or update a user attribute. Needs organizations:write.

Go `PutOrganizationsOrgIDAttributes`, TypeScript `putOrganizationsOrgIDAttributes`.

Takes:

| Field | Type | |
|---|---|---|
| `display_name` | string |  |
| `name` | string |  |
| `personal` | boolean |  |
| `required` | boolean |  |
| `user_readable` | boolean |  |
| `user_writable` | boolean |  |
| `value_type` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `name` | string | always |
| `personal` | boolean |  |

## audit-events

### `GET /admin/audit-events`

Read the audit trail. Does not verify the hash chain. Needs audit:read.

Go `GetAuditEvents`, TypeScript `getAuditEvents`.

Answers:

| Field | Type | |
|---|---|---|
| `chain_note` | string |  |
| `chain_verified` | boolean | always |
| `events` | list of object | always |
| `next_cursor` | string |  |

## authorization-detail-types

### `DELETE /admin/organizations/{orgID}/authorization-detail-types`

Forget a type, named by ?type=, and every client's leave to ask for it. Needs organizations:write.

Go `DeleteOrganizationsOrgIDAuthorizationDetailTypes`, TypeScript `deleteOrganizationsOrgIDAuthorizationDetailTypes`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `GET /admin/organizations/{orgID}/authorization-detail-types`

The authorization details types the organisation accepts, and which clients may ask for each. Needs config:read.

Go `GetOrganizationsOrgIDAuthorizationDetailTypes`, TypeScript `getOrganizationsOrgIDAuthorizationDetailTypes`.

Answers:

| Field | Type | |
|---|---|---|
| `authorization_detail_types` | list of object | always |
| `org_id` | string | always |

### `PUT /admin/organizations/{orgID}/authorization-detail-types`

Register a type, or replace its fields. Needs organizations:write.

Go `PutOrganizationsOrgIDAuthorizationDetailTypes`, TypeScript `putOrganizationsOrgIDAuthorizationDetailTypes`.

Takes:

| Field | Type | |
|---|---|---|
| `description` | string |  |
| `fields` | list of string |  |
| `required` | list of string |  |
| `type` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `type` | string | always |

## authorization-model

### `GET /admin/organizations/{orgID}/authorization-model`

The organisation's authorization model as written; none permits nothing. Needs config:read.

Go `GetOrganizationsOrgIDAuthorizationModel`, TypeScript `getOrganizationsOrgIDAuthorizationModel`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `source` | string | always |

### `PUT /admin/organizations/{orgID}/authorization-model`

Store a model once its own tests pass. Needs organizations:write.

Go `PutOrganizationsOrgIDAuthorizationModel`, TypeScript `putOrganizationsOrgIDAuthorizationModel`.

Takes:

| Field | Type | |
|---|---|---|
| `source` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `actions` | integer | always |
| `config_version` | integer | always |
| `org_id` | string | always |
| `tests_passed` | integer | always |
| `types` | integer | always |

## batch

### `POST /admin/batch`

Up to 100 writes in one transaction, all or none, one version bump. Any token; each operation in it is held to its own scope.

Go `PostBatch`, TypeScript `postBatch`.

Takes:

| Field | Type | |
|---|---|---|
| `operations` | list of object |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `results` | list of object | always |

## budgets

### `GET /admin/organizations/{orgID}/budgets`

The tokens and sign-ins the organisation may take a minute. Needs config:read.

Go `GetOrganizationsOrgIDBudgets`, TypeScript `getOrganizationsOrgIDBudgets`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `sign_ins_default` | boolean | always |
| `sign_ins_per_minute` | integer | always |
| `tokens_default` | boolean | always |
| `tokens_per_minute` | integer | always |

### `PUT /admin/organizations/{orgID}/budgets`

Set the organisation's budgets; deployment-wide tokens only. Needs organizations:write.

Go `PutOrganizationsOrgIDBudgets`, TypeScript `putOrganizationsOrgIDBudgets`.

Takes:

| Field | Type | |
|---|---|---|
| `sign_ins_per_minute` | integer |  |
| `tokens_per_minute` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `org_id` | string | always |
| `sign_ins_default` | boolean | always |
| `sign_ins_per_minute` | integer | always |
| `tokens_default` | boolean | always |
| `tokens_per_minute` | integer | always |

## claim-mappers

### `GET /admin/organizations/{orgID}/claim-mappers`

Every attribute this organisation releases as a claim. Needs config:read.

Go `GetOrganizationsOrgIDClaimMappers`, TypeScript `getOrganizationsOrgIDClaimMappers`.

Answers:

| Field | Type | |
|---|---|---|
| `mappers` | list of object | always |

### `POST /admin/organizations/{orgID}/claim-mappers`

Release an attribute as a claim. Needs organizations:write.

Go `PostOrganizationsOrgIDClaimMappers`, TypeScript `postOrganizationsOrgIDClaimMappers`.

Takes:

| Field | Type | |
|---|---|---|
| `all_clients` | boolean |  |
| `attribute` | string |  |
| `claim_name` | string |  |
| `client_id` | string |  |
| `destination` | string |  |
| `required_scope` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `claim_name` | string | always |
| `config_version` | integer | always |
| `destination` | string |  |
| `id` | string | always |

### `DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}`

Stop releasing an attribute as a claim. Needs organizations:write.

Go `DeleteOrganizationsOrgIDClaimMappersMapperID`, TypeScript `deleteOrganizationsOrgIDClaimMappersMapperID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |

## clients

### `GET /admin/clients`

List clients. Needs clients:read.

Go `GetClients`, TypeScript `getClients`.

Answers:

| Field | Type | |
|---|---|---|
| `clients` | list of object | always |
| `next_cursor` | string | always |

### `POST /admin/clients`

Register a client. Needs clients:write.

Go `PostClients`, TypeScript `postClients`.

Takes:

| Field | Type | |
|---|---|---|
| `client_id` | string |  |
| `display_name` | string |  |
| `org_id` | string |  |
| `public` | boolean |  |
| `redirect_uris` | list of string |  |
| `require_pkce` | boolean |  |
| `secret` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `client_secret` | string |  |
| `config_version` | integer | always |
| `notice` | string |  |
| `require_pkce` | boolean |  |
| `type` | string | always |

### `DELETE /admin/clients/{clientID}`

Remove a client and everything issued under it. Needs clients:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteClientsClientID`, TypeScript `deleteClientsClientID`.

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `config_version` | integer | always |
| `refresh_families_revoked` | integer |  |

### `GET /admin/clients/{clientID}`

One client. Needs clients:read.

Go `GetClientsClientID`, TypeScript `getClientsClientID`.

Answers:

| Field | Type | |
|---|---|---|
| `access_token_ttl_s` | integer |  |
| `admin_api` | boolean |  |
| `allow_hybrid` | boolean |  |
| `authorization_detail_types` | list of string |  |
| `backchannel_client_notification_endpoint` | string or null |  |
| `backchannel_logout_session_required` | boolean |  |
| `backchannel_logout_uri` | string or null |  |
| `backchannel_token_delivery_mode` | string |  |
| `claims_redirect_uris` | list of string or null |  |
| `client_id` | string | always |
| `client_type` | string | always |
| `consent_lifetime_s` | integer or null |  |
| `created_at` | string | always |
| `display_name` | string | always |
| `dpop_bound_access_tokens` | boolean |  |
| `dynamically_registered` | boolean |  |
| `enabled` | boolean | always |
| `exchange_audiences` | list of string |  |
| `exchange_requires_audience_match` | boolean |  |
| `first_party` | boolean |  |
| `frontchannel_logout_session_required` | boolean |  |
| `frontchannel_logout_uri` | string or null |  |
| `grant_types` | list of string | always |
| `hybrid_review_by` | string or null |  |
| `id_token_signed_alg` | string |  |
| `initiate_login_uri` | string or null |  |
| `issuer_alias` | string or null |  |
| `jwks` | object or null |  |
| `jwt_bearer_providers` | list of string |  |
| `logo_uri` | string or null |  |
| `may_exchange` | boolean |  |
| `minimum_acr` | string |  |
| `org_id` | string | always |
| `portal_hidden` | boolean |  |
| `redirect_uris` | list of string | always |
| `refresh_token_ttl_s` | integer |  |
| `registered_at` | string or null |  |
| `require_pkce` | boolean |  |
| `require_pushed_authorization` | boolean |  |
| `response_types` | list of string |  |
| `scopes` | list of string | always |
| `tls_bound_tokens` | boolean |  |
| `tls_san_dns` | string or null |  |
| `tls_san_email` | string or null |  |
| `tls_san_ip` | string or null |  |
| `tls_san_uri` | string or null |  |
| `tls_subject_dn` | string or null |  |
| `tls_thumbprint` | string or null |  |
| `token_endpoint_auth_method` | string |  |

### `PATCH /admin/clients/{clientID}`

Enable or disable a client, or opt it out of PKCE. Needs clients:write. A target that may impersonate others also needs privileged-users:write.

Go `PatchClientsClientID`, TypeScript `patchClientsClientID`.

Takes:

| Field | Type | |
|---|---|---|
| `access_token_ttl_s` | integer |  |
| `admin_api` | boolean |  |
| `allow_hybrid` | boolean |  |
| `authorization_detail_types` | list of string |  |
| `backchannel_client_notification_endpoint` | string |  |
| `backchannel_logout_session_required` | boolean |  |
| `backchannel_logout_uri` | string |  |
| `backchannel_token_delivery_mode` | string |  |
| `claims_redirect_uris` | list of string |  |
| `consent_lifetime_s` | integer |  |
| `display_name` | string |  |
| `dpop_bound_access_tokens` | boolean |  |
| `enabled` | boolean |  |
| `exchange_audiences` | list of string |  |
| `exchange_requires_audience_match` | boolean |  |
| `first_party` | boolean |  |
| `frontchannel_logout_session_required` | boolean |  |
| `frontchannel_logout_uri` | string |  |
| `grant_types` | list of string |  |
| `hybrid_review_by` | string |  |
| `id_token_signed_response_alg` | string |  |
| `initiate_login_uri` | string |  |
| `issuer_alias` | string |  |
| `jwks` | any |  |
| `jwt_bearer_providers` | list of string |  |
| `logo_uri` | string |  |
| `may_exchange` | boolean |  |
| `minimum_acr` | string |  |
| `portal_hidden` | boolean |  |
| `post_logout_redirect_uris` | list of string |  |
| `redirect_uris` | list of string |  |
| `refresh_token_ttl_s` | integer |  |
| `require_pkce` | boolean |  |
| `require_pushed_authorization_requests` | boolean |  |
| `scopes` | list of string |  |
| `tls_bound_tokens` | boolean |  |
| `tls_certificate` | string |  |
| `tls_san_dns` | string |  |
| `tls_san_email` | string |  |
| `tls_san_ip` | string |  |
| `tls_san_uri` | string |  |
| `tls_subject_dn` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `access_token_ttl_s` | integer |  |
| `client_id` | string | always |
| `config_version` | integer | always |
| `consent_lifetime_s` | integer |  |
| `enabled` | boolean | always |
| `exchange_audiences` | list of string |  |
| `first_party` | boolean |  |
| `frontchannel_logout_session_required` | boolean |  |
| `frontchannel_logout_uri` | string |  |
| `id_token_signed_response_alg` | string |  |
| `issuer_alias` | string |  |
| `may_exchange` | boolean |  |
| `minimum_acr` | string |  |
| `post_logout_redirect_uris` | list of string |  |
| `refresh_token_ttl_s` | integer |  |
| `require_pkce` | boolean | always |
| `require_pushed_authorization_requests` | boolean |  |

## clients / group-release

### `DELETE /admin/clients/{clientID}/group-release`

Tell the application of no group. Needs clients:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteClientsClientIDGroupRelease`, TypeScript `deleteClientsClientIDGroupRelease`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `GET /admin/clients/{clientID}/group-release`

Which groups the application is told of in the groups claim. Needs clients:read.

Go `GetClientsClientIDGroupRelease`, TypeScript `getClientsClientIDGroupRelease`.

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `only_groups` | list of string | always |
| `released` | boolean | always |

### `PUT /admin/clients/{clientID}/group-release`

Tell the application of these groups, or every group when none is named. Needs clients:write. A target that may impersonate others also needs privileged-users:write.

Go `PutClientsClientIDGroupRelease`, TypeScript `putClientsClientIDGroupRelease`.

Takes:

| Field | Type | |
|---|---|---|
| `only_groups` | list of string |  |

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `config_version` | integer | always |
| `only_groups` | list of string | always |
| `released` | boolean | always |

## clients / rotate-secret

### `POST /admin/clients/{clientID}/rotate-secret`

Issue a new client secret, shown once. Needs clients:write. A target that may impersonate others also needs privileged-users:write.

Go `PostClientsClientIDRotateSecret`, TypeScript `postClientsClientIDRotateSecret`.

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `client_secret` | string | always |
| `config_version` | integer | always |
| `notice` | string |  |

## clients / ssf-stream

### `PATCH /admin/clients/{clientID}/ssf-stream`

Pause, disable or re-enable a client's stream, telling its receiver. Needs clients:write. A target that may impersonate others also needs privileged-users:write.

Go `PatchClientsClientIDSSFStream`, TypeScript `patchClientsClientIDSSFStream`.

Takes:

| Field | Type | |
|---|---|---|
| `reason` | string |  |
| `status` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `config_version` | integer | always |
| `status` | string | always |
| `was` | string | always |

## config

### `POST /admin/organizations/{orgID}/config`

Plan a configuration file, or apply it in one transaction. Needs organizations:write.

Go `PostOrganizationsOrgIDConfig`, TypeScript `postOrganizationsOrgIDConfig`.

Takes:

| Field | Type | |
|---|---|---|
| `document` | string |  |
| `dry_run` | boolean |  |
| `prune` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `changes` | list of object | always |
| `config_version` | integer | always |
| `create` | integer | always |
| `delete` | integer | always |
| `dry_run` | boolean | always |
| `minted` | list of object |  |
| `update` | integer | always |

## config-version

### `GET /admin/config-version`

The current configuration version, for conditional writes. Needs config:read.

Go `GetConfigVersion`, TypeScript `getConfigVersion`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |

## credential-configurations

### `GET /admin/organizations/{orgID}/credential-configurations`

The credentials the organisation issues. Needs config:read.

Go `GetOrganizationsOrgIDCredentialConfigurations`, TypeScript `getOrganizationsOrgIDCredentialConfigurations`.

Answers:

| Field | Type | |
|---|---|---|
| `configurations` | list of object | always |
| `org_id` | string | always |

### `PUT /admin/organizations/{orgID}/credential-configurations/{configID}`

Define a credential, or redefine it. Needs organizations:write.

Go `PutOrganizationsOrgIDCredentialConfigurationsConfigID`, TypeScript `putOrganizationsOrgIDCredentialConfigurationsConfigID`.

Takes:

| Field | Type | |
|---|---|---|
| `always` | list of string |  |
| `display_name` | string |  |
| `lifetime_s` | integer |  |
| `require_key_attestation` | boolean |  |
| `selective` | list of string |  |
| `vct` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `require_key_attestation` | boolean | always |

## credential-proof-roots

### `GET /admin/organizations/{orgID}/credential-proof-roots`

The roots an x5c key proof may verify to. Needs config:read.

Go `GetOrganizationsOrgIDCredentialProofRoots`, TypeScript `getOrganizationsOrgIDCredentialProofRoots`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `roots` | list of object | always |

### `DELETE /admin/organizations/{orgID}/credential-proof-roots/{name}`

Stop trusting a CA for x5c key proofs. Needs organizations:write.

Go `DeleteOrganizationsOrgIDCredentialProofRootsName`, TypeScript `deleteOrganizationsOrgIDCredentialProofRootsName`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `name` | string | always |
| `removed` | boolean | always |

### `PUT /admin/organizations/{orgID}/credential-proof-roots/{name}`

Trust a CA for x5c key proofs. Needs organizations:write.

Go `PutOrganizationsOrgIDCredentialProofRootsName`, TypeScript `putOrganizationsOrgIDCredentialProofRootsName`.

Takes:

| Field | Type | |
|---|---|---|
| `certificate` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `name` | string | always |
| `not_after` | string | always |
| `subject` | string | always |

## directories

### `GET /admin/organizations/{orgID}/directories`

The directories the organisation's accounts follow, and what each last sync did. Needs config:read.

Go `GetOrganizationsOrgIDDirectories`, TypeScript `getOrganizationsOrgIDDirectories`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `sources` | list of object | always |

### `POST /admin/organizations/{orgID}/directories`

Register a Google, Entra or LDAP source; it starts in dry run. Needs organizations:write.

Go `PostOrganizationsOrgIDDirectories`, TypeScript `postOrganizationsOrgIDDirectories`.

Takes:

| Field | Type | |
|---|---|---|
| `credentials` | any |  |
| `domain` | string |  |
| `fetch_groups` | boolean |  |
| `filter` | string |  |
| `group_attribute` | string |  |
| `impersonate` | string |  |
| `kind` | string |  |
| `ldap_base_dn` | string |  |
| `ldap_bind_dn` | string |  |
| `ldap_ca_pem` | string |  |
| `ldap_flavour` | string |  |
| `ldap_password` | string |  |
| `ldap_start_tls` | boolean |  |
| `ldap_url` | string |  |
| `name` | string |  |
| `slug` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `dry_run` | boolean | always |
| `id` | string | always |
| `kind` | string | always |
| `slug` | string | always |

### `PATCH /admin/organizations/{orgID}/directories/{slug}`

Change how a source syncs; what is not given is kept. Needs organizations:write.

Go `PatchOrganizationsOrgIDDirectoriesSlug`, TypeScript `patchOrganizationsOrgIDDirectoriesSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `dry_run` | boolean |  |
| `enabled` | boolean |  |
| `fetch_groups` | boolean |  |
| `group_attribute` | string |  |
| `max_deactivate_percent` | integer |  |
| `on_missing` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `slug` | string | always |

### `DELETE /admin/organizations/{orgID}/directories/{slug}/group-map`

Stop a directory group granting a local group. Needs organizations:write.

Go `DeleteOrganizationsOrgIDDirectoriesSlugGroupMap`, TypeScript `deleteOrganizationsOrgIDDirectoriesSlugGroupMap`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `group` | string | always |
| `mapped` | boolean | always |
| `remote_group` | string | always |
| `slug` | string | always |

### `PUT /admin/organizations/{orgID}/directories/{slug}/group-map`

Say which local group a directory group grants. Needs organizations:write.

Go `PutOrganizationsOrgIDDirectoriesSlugGroupMap`, TypeScript `putOrganizationsOrgIDDirectoriesSlugGroupMap`.

Takes:

| Field | Type | |
|---|---|---|
| `group` | string |  |
| `remote_group` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `group` | string | always |
| `mapped` | boolean | always |
| `remote_group` | string | always |
| `slug` | string | always |

### `POST /admin/organizations/{orgID}/directories/{slug}/sync`

Reconcile the organisation with a directory, or preview it. Needs organizations:write.

Go `PostOrganizationsOrgIDDirectoriesSlugSync`, TypeScript `postOrganizationsOrgIDDirectoriesSlugSync`.

Takes:

| Field | Type | |
|---|---|---|
| `apply` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `active_before` | integer | always |
| `applied` | boolean | always |
| `config_version` | integer | always |
| `dry_run_configured` | boolean | always |
| `error` | string |  |
| `error_detail` | string |  |
| `groups` | string | always |
| `groups_skipped` | boolean | always |
| `plan` | string | always |
| `slug` | string | always |
| `upstream` | integer | always |

## duo

### `GET /admin/organizations/{orgID}/duo`

The organisation's Duo application, without its secret, and how many people are enrolled. Needs config:read.

Go `GetOrganizationsOrgIDDuo`, TypeScript `getOrganizationsOrgIDDuo`.

Answers:

| Field | Type | |
|---|---|---|
| `api_host` | string | always |
| `client_id` | string | always |
| `configured` | boolean | always |
| `enabled` | boolean | always |
| `enrolled` | integer | always |
| `fail_open` | boolean | always |
| `org_id` | string | always |

### `PUT /admin/organizations/{orgID}/duo`

Configure Duo, checked against Duo before anything is stored. Needs organizations:write.

Go `PutOrganizationsOrgIDDuo`, TypeScript `putOrganizationsOrgIDDuo`.

Takes:

| Field | Type | |
|---|---|---|
| `api_host` | string |  |
| `client_id` | string |  |
| `fail_open` | boolean |  |
| `secret` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `api_host` | string | always |
| `client_id` | string | always |
| `config_version` | integer | always |
| `fail_open` | boolean | always |
| `org_id` | string | always |

## event-subscriptions

### `GET /admin/organizations/{orgID}/event-subscriptions`

Where the organisation's events are delivered, and how the deliveries are going. Needs config:read.

Go `GetOrganizationsOrgIDEventSubscriptions`, TypeScript `getOrganizationsOrgIDEventSubscriptions`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `subscriptions` | list of object | always |

### `POST /admin/organizations/{orgID}/event-subscriptions`

Subscribe a URL to events; its signing secret is shown once. Needs organizations:write.

Go `PostOrganizationsOrgIDEventSubscriptions`, TypeScript `postOrganizationsOrgIDEventSubscriptions`.

Takes:

| Field | Type | |
|---|---|---|
| `event_types` | list of string |  |
| `name` | string |  |
| `url` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `name` | string | always |
| `secret` | string | always |

### `DELETE /admin/organizations/{orgID}/event-subscriptions/{name}`

Remove a subscription; nothing more is delivered to it. Needs organizations:write.

Go `DeleteOrganizationsOrgIDEventSubscriptionsName`, TypeScript `deleteOrganizationsOrgIDEventSubscriptionsName`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `name` | string | always |
| `removed` | boolean | always |

### `POST /admin/organizations/{orgID}/event-subscriptions/{name}/enable`

Switch a subscription back on after it was given up on. Needs organizations:write.

Go `PostOrganizationsOrgIDEventSubscriptionsNameEnable`, TypeScript `postOrganizationsOrgIDEventSubscriptionsNameEnable`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean | always |
| `name` | string | always |

### `POST /admin/organizations/{orgID}/event-subscriptions/{name}/rotate-secret`

Replace a subscription's signing secret, shown once. Needs organizations:write.

Go `PostOrganizationsOrgIDEventSubscriptionsNameRotateSecret`, TypeScript `postOrganizationsOrgIDEventSubscriptionsNameRotateSecret`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `name` | string | always |
| `secret` | string | always |

### `POST /admin/organizations/{orgID}/event-subscriptions/{name}/test`

Queue one signed test delivery to a subscription. Needs organizations:write.

Go `PostOrganizationsOrgIDEventSubscriptionsNameTest`, TypeScript `postOrganizationsOrgIDEventSubscriptionsNameTest`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `event_id` | string | always |
| `name` | string | always |

## groups

### `GET /admin/groups`

List groups. Needs groups:read.

Go `GetGroups`, TypeScript `getGroups`.

Answers:

| Field | Type | |
|---|---|---|
| `groups` | list of object | always |
| `next_cursor` | string |  |

### `POST /admin/groups`

Create a group. Needs groups:write.

Go `PostGroups`, TypeScript `postGroups`.

Takes:

| Field | Type | |
|---|---|---|
| `description` | string |  |
| `display_name` | string |  |
| `name` | string |  |
| `org_id` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |

### `DELETE /admin/groups/{groupID}`

Delete a group and its memberships. Needs groups:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteGroupsGroupID`, TypeScript `deleteGroupsGroupID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `members_removed` | integer |  |

### `GET /admin/groups/{groupID}`

One group. Needs groups:read.

Go `GetGroupsGroupID`, TypeScript `getGroupsGroupID`.

Answers:

| Field | Type | |
|---|---|---|
| `created_at` | string | always |
| `description` | string | always |
| `display_name` | string | always |
| `id` | string | always |
| `may_impersonate` | boolean | always |
| `name` | string | always |
| `org_id` | string | always |

### `PATCH /admin/groups/{groupID}`

Rename a group or change its description. Needs groups:write. A target that may impersonate others also needs privileged-users:write.

Go `PatchGroupsGroupID`, TypeScript `patchGroupsGroupID`.

Takes:

| Field | Type | |
|---|---|---|
| `description` | string |  |
| `display_name` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |

## groups / members

### `GET /admin/groups/{groupID}/members`

List a group's members. Needs groups:read.

Go `GetGroupsGroupIDMembers`, TypeScript `getGroupsGroupIDMembers`.

Answers:

| Field | Type | |
|---|---|---|
| `members` | list of object | always |
| `next_cursor` | string |  |

### `DELETE /admin/groups/{groupID}/members/{userID}`

Remove a member. Needs groups:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteGroupsGroupIDMembersUserID`, TypeScript `deleteGroupsGroupIDMembersUserID`.

Answers:

| Field | Type | |
|---|---|---|
| `changed` | boolean | always |
| `config_version` | integer | always |
| `group_id` | string | always |
| `member` | boolean | always |
| `user_id` | string | always |

### `PUT /admin/groups/{groupID}/members/{userID}`

Add a member. Needs groups:write. A target that may impersonate others also needs privileged-users:write.

Go `PutGroupsGroupIDMembersUserID`, TypeScript `putGroupsGroupIDMembersUserID`.

Answers:

| Field | Type | |
|---|---|---|
| `changed` | boolean | always |
| `config_version` | integer | always |
| `group_id` | string | always |
| `member` | boolean | always |
| `user_id` | string | always |

## groups / radius

### `DELETE /admin/groups/{groupID}/radius`

Take a group's VLAN and Filter-Id away. Needs groups:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteGroupsGroupIDRADIUS`, TypeScript `deleteGroupsGroupIDRADIUS`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `group_id` | string | always |
| `removed` | boolean | always |

### `PUT /admin/groups/{groupID}/radius`

Place a group's members on a VLAN, a Filter-Id or both. Needs groups:write. A target that may impersonate others also needs privileged-users:write.

Go `PutGroupsGroupIDRADIUS`, TypeScript `putGroupsGroupIDRADIUS`.

Takes:

| Field | Type | |
|---|---|---|
| `filter_id` | string |  |
| `priority` | integer |  |
| `vlan_id` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `group_id` | string | always |

## identity-providers

### `GET /admin/organizations/{orgID}/identity-providers`

The providers people sign in through and the issuers assertions come from. Needs config:read.

Go `GetOrganizationsOrgIDIdentityProviders`, TypeScript `getOrganizationsOrgIDIdentityProviders`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `providers` | list of object | always |

### `POST /admin/organizations/{orgID}/identity-providers`

Register a provider to sign in through, or an issuer whose assertions may be accepted. Needs organizations:write.

Go `PostOrganizationsOrgIDIdentityProviders`, TypeScript `postOrganizationsOrgIDIdentityProviders`.

Takes:

| Field | Type | |
|---|---|---|
| `allow_linking` | boolean |  |
| `allow_signup` | boolean |  |
| `allow_unsolicited` | boolean |  |
| `certificate` | string |  |
| `client_id` | string |  |
| `client_secret` | string |  |
| `entity_id` | string |  |
| `force_authn` | boolean |  |
| `issuer` | string |  |
| `jwks_url` | string |  |
| `kind` | string |  |
| `name` | string |  |
| `name_id_format` | string |  |
| `skew_seconds` | integer |  |
| `slug` | string |  |
| `sso_url` | string |  |
| `trust_email_verification` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `acs_path` | string |  |
| `allow_assertions` | boolean | always |
| `callback_path` | string |  |
| `config_version` | integer | always |
| `id` | string | always |
| `keys` | integer |  |
| `kind` | string | always |
| `metadata_path` | string |  |
| `sign_in_path` | string |  |
| `slug` | string | always |

### `PATCH /admin/organizations/{orgID}/identity-providers/{slug}`

Take a provider out of service, allow its assertions, or say what of it is trusted. Needs organizations:write.

Go `PatchOrganizationsOrgIDIdentityProvidersSlug`, TypeScript `patchOrganizationsOrgIDIdentityProvidersSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `allow_assertions` | boolean |  |
| `enabled` | boolean |  |
| `mfa_acr` | list of string |  |
| `mfa_amr` | list of string |  |
| `require_verified_email` | boolean |  |
| `trust_email_verification` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `slug` | string | always |

### `DELETE /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map`

Stop a provider's claim reaching an attribute. Needs organizations:write.

Go `DeleteOrganizationsOrgIDIdentityProvidersSlugAttributeMap`, TypeScript `deleteOrganizationsOrgIDIdentityProvidersSlugAttributeMap`.

Answers:

| Field | Type | |
|---|---|---|
| `attribute` | string | always |
| `claim` | string | always |
| `config_version` | integer | always |
| `mapped` | boolean | always |
| `slug` | string | always |

### `PUT /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map`

Route a provider's claim into a declared attribute. Needs organizations:write.

Go `PutOrganizationsOrgIDIdentityProvidersSlugAttributeMap`, TypeScript `putOrganizationsOrgIDIdentityProvidersSlugAttributeMap`.

Takes:

| Field | Type | |
|---|---|---|
| `attribute` | string |  |
| `claim` | string |  |
| `max_length` | integer |  |
| `overwrite` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `attribute` | string | always |
| `claim` | string | always |
| `config_version` | integer | always |
| `mapped` | boolean | always |
| `slug` | string | always |

## instances

### `GET /admin/instances`

The issuers this deployment has; deployment-wide tokens only. Needs config:read.

Go `GetInstances`, TypeScript `getInstances`.

Answers:

| Field | Type | |
|---|---|---|
| `instances` | list of object | always |

## instances / brand

### `DELETE /admin/instances/{instanceID}/brand`

Return the instance's pages to the built-in appearance. Needs organizations:write.

Go `DeleteInstancesInstanceIDBrand`, TypeScript `deleteInstancesInstanceIDBrand`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `GET /admin/instances/{instanceID}/brand`

The instance's name, logo, support link and colours. Needs config:read.

Go `GetInstancesInstanceIDBrand`, TypeScript `getInstancesInstanceIDBrand`.

Answers:

| Field | Type | |
|---|---|---|
| `branded` | boolean | always |
| `colour_background` | string | always |
| `colour_on_primary` | string | always |
| `colour_primary` | string | always |
| `colour_text` | string | always |
| `instance_id` | string | always |
| `logo_url` | string | always |
| `product_name` | string | always |
| `support_url` | string | always |

### `PUT /admin/instances/{instanceID}/brand`

Brand the instance's pages, checked for contrast. Needs organizations:write.

Go `PutInstancesInstanceIDBrand`, TypeScript `putInstancesInstanceIDBrand`.

Takes:

| Field | Type | |
|---|---|---|
| `colour_background` | string |  |
| `colour_on_primary` | string |  |
| `colour_primary` | string |  |
| `colour_text` | string |  |
| `logo_url` | string |  |
| `product_name` | string |  |
| `support_url` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `branded` | boolean | always |
| `colour_background` | string | always |
| `colour_on_primary` | string | always |
| `colour_primary` | string | always |
| `colour_text` | string | always |
| `config_version` | integer | always |
| `instance_id` | string | always |
| `logo_url` | string | always |
| `product_name` | string | always |
| `support_url` | string | always |

## instances / federation

### `GET /admin/instances/{instanceID}/federation`

Whether the instance is a federation entity, and what it publishes. Needs config:read.

Go `GetInstancesInstanceIDFederation`, TypeScript `getInstancesInstanceIDFederation`.

Answers:

| Field | Type | |
|---|---|---|
| `authority_hints` | list of string | always |
| `contacts` | list of string | always |
| `enabled` | boolean | always |
| `entity_id` | string | always |
| `homepage_uri` | string | always |
| `instance_id` | string | always |
| `lifetime_s` | integer | always |
| `organization_name` | string | always |
| `trust_anchor_hints` | list of string | always |

### `PUT /admin/instances/{instanceID}/federation`

Make the instance a federation entity, or change what it publishes. Needs organizations:write.

Go `PutInstancesInstanceIDFederation`, TypeScript `putInstancesInstanceIDFederation`.

Takes:

| Field | Type | |
|---|---|---|
| `authority_hints` | list of string |  |
| `contacts` | list of string |  |
| `homepage_uri` | string |  |
| `lifetime_s` | integer |  |
| `organization_name` | string |  |
| `trust_anchor_hints` | list of string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `entity_id` | string | always |
| `generated_key` | string | always |
| `instance_id` | string | always |
| `restart_required` | boolean | always |

## instances / held-trust-marks

### `DELETE /admin/instances/{instanceID}/held-trust-marks`

Stop publishing a Trust Mark the instance holds. Needs organizations:write.

Go `DeleteInstancesInstanceIDHeldTrustMarks`, TypeScript `deleteInstancesInstanceIDHeldTrustMarks`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `issuer` | string | always |
| `removed` | boolean | always |
| `type` | string | always |

### `PUT /admin/instances/{instanceID}/held-trust-marks`

Publish a Trust Mark another issuer granted the instance. Needs organizations:write.

Go `PutInstancesInstanceIDHeldTrustMarks`, TypeScript `putInstancesInstanceIDHeldTrustMarks`.

Takes:

| Field | Type | |
|---|---|---|
| `trust_mark` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `issuer` | string | always |
| `published` | boolean | always |
| `type` | string | always |

## instances / issuer-aliases

### `GET /admin/instances/{instanceID}/issuer-aliases`

Legacy issuers the instance also claims, and who is pinned to each. Needs config:read.

Go `GetInstancesInstanceIDIssuerAliases`, TypeScript `getInstancesInstanceIDIssuerAliases`.

Answers:

| Field | Type | |
|---|---|---|
| `instance_id` | string | always |
| `issuer_aliases` | list of object | always |

### `PATCH /admin/instances/{instanceID}/issuer-aliases`

Retire an alias, now unless told when. Needs organizations:write.

Go `PatchInstancesInstanceIDIssuerAliases`, TypeScript `patchInstancesInstanceIDIssuerAliases`.

Takes:

| Field | Type | |
|---|---|---|
| `alias` | string |  |
| `retire_after` | object |  |

Answers:

| Field | Type | |
|---|---|---|
| `alias` | string | always |
| `config_version` | integer | always |

### `POST /admin/instances/{instanceID}/issuer-aliases`

Claim a legacy issuer while relying parties move across. Needs organizations:write.

Go `PostInstancesInstanceIDIssuerAliases`, TypeScript `postInstancesInstanceIDIssuerAliases`.

Takes:

| Field | Type | |
|---|---|---|
| `alias` | string |  |
| `retire_after` | object |  |

Answers:

| Field | Type | |
|---|---|---|
| `alias` | string | always |
| `config_version` | integer | always |

## instances / keys

### `GET /admin/instances/{instanceID}/keys`

The instance's signing keys by id, algorithm and state; never a private half. Needs config:read.

Go `GetInstancesInstanceIDKeys`, TypeScript `getInstancesInstanceIDKeys`.

Answers:

| Field | Type | |
|---|---|---|
| `instance_id` | string | always |
| `keys` | list of object | always |

### `POST /admin/instances/{instanceID}/keys/retire`

Retire the passive keys whose dwell is over. Needs organizations:write.

Go `PostInstancesInstanceIDKeysRetire`, TypeScript `postInstancesInstanceIDKeysRetire`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `instance_id` | string | always |
| `retired` | list of string | always |

### `POST /admin/instances/{instanceID}/keys/rotate`

Take the next safe step of rotation for each algorithm in use. Needs organizations:write.

Go `PostInstancesInstanceIDKeysRotate`, TypeScript `postInstancesInstanceIDKeysRotate`.

Takes:

| Field | Type | |
|---|---|---|
| `algorithm` | string |  |
| `promote_now` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `instance_id` | string | always |
| `steps` | list of object | always |

## instances / trust-mark-delegations

### `POST /admin/instances/{instanceID}/trust-mark-delegations`

Authorise another entity to issue a type of Trust Mark the instance owns. Needs organizations:write.

Go `PostInstancesInstanceIDTrustMarkDelegations`, TypeScript `postInstancesInstanceIDTrustMarkDelegations`.

Takes:

| Field | Type | |
|---|---|---|
| `delegate` | string |  |
| `lifetime_s` | integer |  |
| `ref` | string |  |
| `type` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `delegate` | string | always |
| `delegation` | string | always |
| `type` | string | always |

## instances / trust-marks

### `GET /admin/instances/{instanceID}/trust-marks`

The Trust Marks the instance issued and the ones it holds. Needs config:read.

Go `GetInstancesInstanceIDTrustMarks`, TypeScript `getInstancesInstanceIDTrustMarks`.

Answers:

| Field | Type | |
|---|---|---|
| `entity_id` | string | always |
| `held` | list of object | always |
| `instance_id` | string | always |
| `issued` | list of object | always |

### `POST /admin/instances/{instanceID}/trust-marks`

Issue a Trust Mark, signed with the federation key. Needs organizations:write.

Go `PostInstancesInstanceIDTrustMarks`, TypeScript `postInstancesInstanceIDTrustMarks`.

Takes:

| Field | Type | |
|---|---|---|
| `delegation` | string |  |
| `lifetime_s` | integer |  |
| `logo_uri` | string |  |
| `ref` | string |  |
| `subject` | string |  |
| `type` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `expires_at` | string or null | always |
| `subject` | string | always |
| `trust_mark` | string | always |
| `type` | string | always |

### `POST /admin/instances/{instanceID}/trust-marks/revoke`

Revoke a Trust Mark the instance issued. Needs organizations:write.

Go `PostInstancesInstanceIDTrustMarksRevoke`, TypeScript `postInstancesInstanceIDTrustMarksRevoke`.

Takes:

| Field | Type | |
|---|---|---|
| `reason` | string |  |
| `subject` | string |  |
| `type` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `revoked` | boolean | always |
| `subject` | string | always |
| `type` | string | always |

## instances / webauthn

### `GET /admin/instances/{instanceID}/webauthn`

The Relying Party ID the instance's passkeys are bound to, and its related origins. Needs config:read.

Go `GetInstancesInstanceIDWebauthn`, TypeScript `getInstancesInstanceIDWebauthn`.

Answers:

| Field | Type | |
|---|---|---|
| `instance_id` | string | always |
| `related_origins` | list of string | always |
| `rp_display_name` | string | always |
| `rp_id` | string | always |

### `PUT /admin/instances/{instanceID}/webauthn`

Set the RP ID, its name and related origins; changing a set RP ID must be confirmed. Needs organizations:write.

Go `PutInstancesInstanceIDWebauthn`, TypeScript `putInstancesInstanceIDWebauthn`.

Takes:

| Field | Type | |
|---|---|---|
| `related_origins` | list of string |  |
| `replace_rp_id` | boolean |  |
| `rp_display_name` | string |  |
| `rp_id` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `instance_id` | string | always |
| `related_origins` | list of string | always |
| `replaced_rp_id` | string | always |
| `rp_display_name` | string | always |
| `rp_id` | string | always |

## invitations

### `GET /admin/invitations`

Invitations, with whether each is open, used, revoked or expired. Needs users:read.

Go `GetInvitations`, TypeScript `getInvitations`.

Answers:

| Field | Type | |
|---|---|---|
| `invitations` | list of object | always |
| `next_cursor` | string |  |

### `POST /admin/invitations`

Invite somebody to create an account: the link once, or mailed to the bound address with send. Needs users:write.

Go `PostInvitations`, TypeScript `postInvitations`.

Takes:

| Field | Type | |
|---|---|---|
| `email` | string |  |
| `expires_in_seconds` | integer |  |
| `groups` | list of string |  |
| `org_id` | string |  |
| `send` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `expires_at` | string | always |
| `id` | string | always |
| `link` | string |  |
| `org_id` | string | always |
| `sent` | boolean | always |

### `DELETE /admin/invitations/{invitationID}`

Revoke an open invitation. Needs users:write.

Go `DeleteInvitationsInvitationID`, TypeScript `deleteInvitationsInvitationID`.

## me

### `GET /admin/me`

Who the caller is, as this request was authenticated: kind, organisation, scopes and any delegation. Any token; each operation in it is held to its own scope.

Go `GetMe`, TypeScript `getMe`.

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string |  |
| `delegated` | object |  |
| `expires_at` | string or null | always |
| `kind` | string | always |
| `name` | string | always |
| `org_id` | string or null | always |
| `scopes` | list of string | always |
| `user` | object |  |

## migration-source

### `DELETE /admin/organizations/{orgID}/migration-source`

Remove the migration source. Needs organizations:write.

Go `DeleteOrganizationsOrgIDMigrationSource`, TypeScript `deleteOrganizationsOrgIDMigrationSource`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `GET /admin/organizations/{orgID}/migration-source`

The provider this organisation is migrating off, and how the cutover is going. Needs config:read.

Go `GetOrganizationsOrgIDMigrationSource`, TypeScript `getOrganizationsOrgIDMigrationSource`.

Answers:

| Field | Type | |
|---|---|---|
| `bind_dn_template` | string |  |
| `client_id` | string |  |
| `delegated_failures` | integer | always |
| `delegated_successes` | integer | always |
| `display_name` | string | always |
| `enabled` | boolean | always |
| `has_ca` | boolean | always |
| `has_client_secret` | boolean | always |
| `kind` | string | always |
| `last_error` | string |  |
| `scope` | string |  |
| `start_tls` | boolean | always |
| `url` | string | always |
| `users_migrated` | integer | always |
| `users_pending` | integer | always |

### `PUT /admin/organizations/{orgID}/migration-source`

Configure the old directory or provider that verifies a migrating person's password. Needs organizations:write.

Go `PutOrganizationsOrgIDMigrationSource`, TypeScript `putOrganizationsOrgIDMigrationSource`.

Takes:

| Field | Type | |
|---|---|---|
| `bind_dn_template` | string |  |
| `ca_pem` | string |  |
| `client_id` | string |  |
| `client_secret` | string |  |
| `display_name` | string |  |
| `enabled` | boolean |  |
| `kind` | string |  |
| `scope` | string |  |
| `start_tls` | boolean |  |
| `url` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `bind_dn_template` | string |  |
| `client_id` | string |  |
| `delegated_failures` | integer | always |
| `delegated_successes` | integer | always |
| `display_name` | string | always |
| `enabled` | boolean | always |
| `has_ca` | boolean | always |
| `has_client_secret` | boolean | always |
| `kind` | string | always |
| `last_error` | string |  |
| `scope` | string |  |
| `start_tls` | boolean | always |
| `url` | string | always |
| `users_migrated` | integer | always |
| `users_pending` | integer | always |

## organizations

### `GET /admin/organizations`

The organisations this token may see, with their status. Needs config:read.

Go `GetOrganizations`, TypeScript `getOrganizations`.

Answers:

| Field | Type | |
|---|---|---|
| `organizations` | list of object | always |

### `POST /admin/organizations`

Provision a tenant. Requires an unscoped token. Needs organizations:write.

Go `PostOrganizations`, TypeScript `postOrganizations`.

Takes:

| Field | Type | |
|---|---|---|
| `display_name` | string |  |
| `instance_id` | string |  |
| `slug` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `display_name` | string |  |
| `id` | string | always |
| `instance_id` | string | always |
| `slug` | string | always |

### `GET /admin/organizations/{orgID}`

One organisation and its status. Needs config:read.

Go `GetOrganizationsOrgID`, TypeScript `getOrganizationsOrgID`.

Answers:

| Field | Type | |
|---|---|---|
| `created_at` | string | always |
| `display_name` | string | always |
| `id` | string | always |
| `instance_id` | string | always |
| `slug` | string | always |
| `status` | string | always |

### `PATCH /admin/organizations/{orgID}`

Suspend or reactivate a tenant. Requires an unscoped token. Needs organizations:write.

Go `PatchOrganizationsOrgID`, TypeScript `patchOrganizationsOrgID`.

Takes:

| Field | Type | |
|---|---|---|
| `status` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `status` | string | always |
| `was` | string | always |

## outposts

### `GET /admin/organizations/{orgID}/outposts`

The organisation's outposts, when each was last heard from, never a token. Needs config:read.

Go `GetOrganizationsOrgIDOutposts`, TypeScript `getOrganizationsOrgIDOutposts`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `outposts` | list of object | always |

### `POST /admin/organizations/{orgID}/outposts`

Register an outpost; its token is shown once. Needs organizations:write.

Go `PostOrganizationsOrgIDOutposts`, TypeScript `postOrganizationsOrgIDOutposts`.

Takes:

| Field | Type | |
|---|---|---|
| `kind` | string |  |
| `name` | string |  |
| `search_group` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `kind` | string | always |
| `name` | string | always |
| `token` | string | always |

### `PATCH /admin/organizations/{orgID}/outposts/{name}`

Take an outpost out of service or back, or set who may search through it. Needs organizations:write.

Go `PatchOrganizationsOrgIDOutpostsName`, TypeScript `patchOrganizationsOrgIDOutpostsName`.

Takes:

| Field | Type | |
|---|---|---|
| `enabled` | boolean |  |
| `search_group` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean |  |
| `name` | string | always |
| `search_group` | string |  |

## prompts

### `GET /admin/organizations/{orgID}/prompts`

The prompts asked between sign-in and the session, in order. Needs config:read.

Go `GetOrganizationsOrgIDPrompts`, TypeScript `getOrganizationsOrgIDPrompts`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `prompts` | list of object | always |

### `PATCH /admin/organizations/{orgID}/prompts/{slug}`

Enable or disable a prompt, keeping its answers. Needs organizations:write.

Go `PatchOrganizationsOrgIDPromptsSlug`, TypeScript `patchOrganizationsOrgIDPromptsSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `enabled` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean | always |
| `slug` | string | always |

### `PUT /admin/organizations/{orgID}/prompts/{slug}`

Define or replace a prompt; a change to its wording asks everyone again. Needs organizations:write.

Go `PutOrganizationsOrgIDPromptsSlug`, TypeScript `putOrganizationsOrgIDPromptsSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `body` | string |  |
| `fields` | list of object |  |
| `once` | boolean |  |
| `order` | integer |  |
| `title` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `asked_again` | integer | always |
| `config_version` | integer | always |
| `slug` | string | always |
| `version` | integer | always |

## providers

### `GET /admin/organizations/{orgID}/providers`

The services the organisation's hooks call, and whether anything consults them. Needs config:read.

Go `GetOrganizationsOrgIDProviders`, TypeScript `getOrganizationsOrgIDProviders`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `providers` | list of object | always |

### `DELETE /admin/organizations/{orgID}/providers/{hook}`

Remove a hook's provider; the decision is made locally only. Needs organizations:write.

Go `DeleteOrganizationsOrgIDProvidersHook`, TypeScript `deleteOrganizationsOrgIDProvidersHook`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `hook` | string | always |
| `removed` | boolean | always |

### `PUT /admin/organizations/{orgID}/providers/{hook}`

Register or replace a hook's provider; a first registration's secret is shown once. Needs organizations:write.

Go `PutOrganizationsOrgIDProvidersHook`, TypeScript `putOrganizationsOrgIDProvidersHook`.

Takes:

| Field | Type | |
|---|---|---|
| `mode` | string |  |
| `timeout_ms` | integer |  |
| `url` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `called` | boolean | always |
| `config_version` | integer | always |
| `hook` | string | always |
| `id` | string | always |
| `secret` | string | always |

### `PUT /admin/organizations/{orgID}/providers/{hook}/claims`

The claims a token hook may add; empty lets it add none. Needs organizations:write.

Go `PutOrganizationsOrgIDProvidersHookClaims`, TypeScript `putOrganizationsOrgIDProvidersHookClaims`.

Takes:

| Field | Type | |
|---|---|---|
| `claims` | list of string |  |

Answers:

| Field | Type | |
|---|---|---|
| `allowed_claims` | list of string | always |
| `config_version` | integer | always |
| `hook` | string | always |

### `POST /admin/organizations/{orgID}/providers/{hook}/rotate-secret`

Replace a provider's signing secret, shown once. Needs organizations:write.

Go `PostOrganizationsOrgIDProvidersHookRotateSecret`, TypeScript `postOrganizationsOrgIDProvidersHookRotateSecret`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `hook` | string | always |
| `secret` | string | always |

## proxy-hosts

### `GET /admin/organizations/{orgID}/proxy-hosts`

The applications forward auth protects. Needs config:read.

Go `GetOrganizationsOrgIDProxyHosts`, TypeScript `getOrganizationsOrgIDProxyHosts`.

Answers:

| Field | Type | |
|---|---|---|
| `proxy_hosts` | list of object | always |

### `PUT /admin/organizations/{orgID}/proxy-hosts`

Register a protected host, or enable or disable one. Needs organizations:write.

Go `PutOrganizationsOrgIDProxyHosts`, TypeScript `putOrganizationsOrgIDProxyHosts`.

Takes:

| Field | Type | |
|---|---|---|
| `enabled` | boolean |  |
| `host` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean |  |
| `host` | string | always |

### `DELETE /admin/organizations/{orgID}/proxy-hosts/{host}`

Remove a protected host. Needs organizations:write.

Go `DeleteOrganizationsOrgIDProxyHostsHost`, TypeScript `deleteOrganizationsOrgIDProxyHostsHost`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `host` | string | always |

## rac-connections

### `GET /admin/organizations/{orgID}/rac-connections`

The machines people reach through the browser; never a credential. Needs config:read.

Go `GetOrganizationsOrgIDRACConnections`, TypeScript `getOrganizationsOrgIDRACConnections`.

Answers:

| Field | Type | |
|---|---|---|
| `connections` | list of object | always |
| `org_id` | string | always |

### `POST /admin/organizations/{orgID}/rac-connections`

Register a machine, sealing its credentials. Needs organizations:write.

Go `PostOrganizationsOrgIDRACConnections`, TypeScript `postOrganizationsOrgIDRACConnections`.

Takes:

| Field | Type | |
|---|---|---|
| `host` | string |  |
| `login` | string |  |
| `name` | string |  |
| `password` | string |  |
| `port` | integer |  |
| `protocol` | string |  |
| `require_group` | string |  |
| `slug` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `slug` | string | always |

### `PATCH /admin/organizations/{orgID}/rac-connections/{slug}`

Take a connection out of service or back, or replace its guacd parameters. Needs organizations:write.

Go `PatchOrganizationsOrgIDRACConnectionsSlug`, TypeScript `patchOrganizationsOrgIDRACConnectionsSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `enabled` | boolean |  |
| `parameters` | object |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean |  |
| `parameters` | object |  |
| `slug` | string | always |

## radius-authorizations

### `GET /admin/organizations/{orgID}/radius-authorizations`

The VLAN and Filter-Id each authorised group's members are given. Needs config:read.

Go `GetOrganizationsOrgIDRADIUSAuthorizations`, TypeScript `getOrganizationsOrgIDRADIUSAuthorizations`.

Answers:

| Field | Type | |
|---|---|---|
| `authorizations` | list of object | always |
| `org_id` | string | always |

## radius-clients

### `GET /admin/organizations/{orgID}/radius-clients`

The network devices that may send Access-Requests; never a secret. Needs config:read.

Go `GetOrganizationsOrgIDRADIUSClients`, TypeScript `getOrganizationsOrgIDRADIUSClients`.

Answers:

| Field | Type | |
|---|---|---|
| `clients` | list of object | always |
| `org_id` | string | always |

### `POST /admin/organizations/{orgID}/radius-clients`

Register a device by the range it sends from and its shared secret. Needs organizations:write.

Go `PostOrganizationsOrgIDRADIUSClients`, TypeScript `postOrganizationsOrgIDRADIUSClients`.

Takes:

| Field | Type | |
|---|---|---|
| `name` | string |  |
| `network` | string |  |
| `secret` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `name` | string | always |
| `network` | string | always |

### `PATCH /admin/organizations/{orgID}/radius-clients/{deviceID}`

Revoke or restore a device's access. Needs organizations:write.

Go `PatchOrganizationsOrgIDRADIUSClientsDeviceID`, TypeScript `patchOrganizationsOrgIDRADIUSClientsDeviceID`.

Takes:

| Field | Type | |
|---|---|---|
| `enabled` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean | always |
| `id` | string | always |

## registration

### `DELETE /admin/organizations/{orgID}/registration`

Turn dynamic registration off, keeping its policy and tokens. Needs organizations:write.

Go `DeleteOrganizationsOrgIDRegistration`, TypeScript `deleteOrganizationsOrgIDRegistration`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `GET /admin/organizations/{orgID}/registration`

Whether /oauth2/register is on, open, and what it allows. Needs config:read.

Go `GetOrganizationsOrgIDRegistration`, TypeScript `getOrganizationsOrgIDRegistration`.

Answers:

| Field | Type | |
|---|---|---|
| `allow_confidential` | boolean | always |
| `allowed_scopes` | list of string | always |
| `enabled` | boolean | always |
| `max_clients` | integer | always |
| `open` | boolean | always |
| `org_id` | string | always |

### `PUT /admin/organizations/{orgID}/registration`

Turn dynamic registration on with this policy. Needs organizations:write.

Go `PutOrganizationsOrgIDRegistration`, TypeScript `putOrganizationsOrgIDRegistration`.

Takes:

| Field | Type | |
|---|---|---|
| `allow_confidential` | boolean |  |
| `allowed_scopes` | list of string |  |
| `max_clients` | integer |  |
| `open` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `allow_confidential` | boolean | always |
| `allowed_scopes` | list of string | always |
| `config_version` | integer | always |
| `enabled` | boolean | always |
| `max_clients` | integer | always |
| `open` | boolean | always |
| `org_id` | string | always |

## registration-tokens

### `GET /admin/organizations/{orgID}/registration-tokens`

The organisation's initial access tokens, never their secrets. Needs config:read.

Go `GetOrganizationsOrgIDRegistrationTokens`, TypeScript `getOrganizationsOrgIDRegistrationTokens`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `registration_tokens` | list of object | always |

### `POST /admin/organizations/{orgID}/registration-tokens`

Mint an initial access token, shown once. Needs organizations:write.

Go `PostOrganizationsOrgIDRegistrationTokens`, TypeScript `postOrganizationsOrgIDRegistrationTokens`.

Takes:

| Field | Type | |
|---|---|---|
| `expires_in_s` | integer |  |
| `name` | string |  |
| `uses` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `token` | string | always |

### `DELETE /admin/organizations/{orgID}/registration-tokens/{tokenID}`

Revoke an initial access token. Needs organizations:write.

Go `DeleteOrganizationsOrgIDRegistrationTokensTokenID`, TypeScript `deleteOrganizationsOrgIDRegistrationTokensTokenID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

## relations

### `DELETE /admin/organizations/{orgID}/relations`

Revoke a relation named by subject, relation and object. Needs organizations:write.

Go `DeleteOrganizationsOrgIDRelations`, TypeScript `deleteOrganizationsOrgIDRelations`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `granted` | boolean | always |
| `object` | string | always |
| `relation` | string | always |
| `subject` | string | always |

### `PUT /admin/organizations/{orgID}/relations`

Grant a subject a relation on an object. Needs organizations:write.

Go `PutOrganizationsOrgIDRelations`, TypeScript `putOrganizationsOrgIDRelations`.

Takes:

| Field | Type | |
|---|---|---|
| `object` | string |  |
| `relation` | string |  |
| `subject` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `granted` | boolean | always |
| `object` | string | always |
| `relation` | string | always |
| `subject` | string | always |

## resource-servers

### `DELETE /admin/organizations/{orgID}/resource-servers`

Withdraw a resource server; tokens for it are refused from the next request. Needs organizations:write.

Go `DeleteOrganizationsOrgIDResourceServers`, TypeScript `deleteOrganizationsOrgIDResourceServers`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `GET /admin/organizations/{orgID}/resource-servers`

The RFC 8707 resources this organisation's tokens may be audienced to. Needs config:read.

Go `GetOrganizationsOrgIDResourceServers`, TypeScript `getOrganizationsOrgIDResourceServers`.

Answers a list, each:

| Field | Type | |
|---|---|---|
| `created_at` | string |  |
| `name` | string |  |
| `resource` | string | always |

### `PUT /admin/organizations/{orgID}/resource-servers`

Register a resource server, or rename one. Needs organizations:write.

Go `PutOrganizationsOrgIDResourceServers`, TypeScript `putOrganizationsOrgIDResourceServers`.

Takes:

| Field | Type | |
|---|---|---|
| `name` | string |  |
| `resource` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `name` | string |  |
| `resource` | string | always |

## role-bindings

### `GET /admin/organizations/{orgID}/role-bindings`

Who holds which administrative role in the organisation. Needs config:read.

Go `GetOrganizationsOrgIDRoleBindings`, TypeScript `getOrganizationsOrgIDRoleBindings`.

Answers:

| Field | Type | |
|---|---|---|
| `role_bindings` | list of object | always |

### `POST /admin/organizations/{orgID}/role-bindings`

Give a person or an application a role, a user manager optionally over one group's members. Needs organizations:write.

Go `PostOrganizationsOrgIDRoleBindings`, TypeScript `postOrganizationsOrgIDRoleBindings`.

Takes:

| Field | Type | |
|---|---|---|
| `client_id` | string |  |
| `group_id` | string |  |
| `role` | string |  |
| `user_id` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |

### `DELETE /admin/organizations/{orgID}/role-bindings/{bindingID}`

Take a role away; the holder's next request is refused what it gave. Needs organizations:write.

Go `DeleteOrganizationsOrgIDRoleBindingsBindingID`, TypeScript `deleteOrganizationsOrgIDRoleBindingsBindingID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

## saml-providers

### `GET /admin/organizations/{orgID}/saml-providers`

The organisation's SAML service providers and what each is told. Needs config:read.

Go `GetOrganizationsOrgIDSAMLProviders`, TypeScript `getOrganizationsOrgIDSAMLProviders`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `providers` | list of object | always |

### `POST /admin/organizations/{orgID}/saml-providers`

Register a service provider by entity id and ACS URL. Needs organizations:write.

Go `PostOrganizationsOrgIDSAMLProviders`, TypeScript `postOrganizationsOrgIDSAMLProviders`.

Takes:

| Field | Type | |
|---|---|---|
| `acs_url` | string |  |
| `encryption_cert` | string |  |
| `entity_id` | string |  |
| `key_transport` | string |  |
| `name` | string |  |
| `name_id_format` | string |  |
| `signing_cert` | string |  |
| `slo_binding` | string |  |
| `slo_url` | string |  |
| `want_signed_requests` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `entity_id` | string | always |
| `id` | string | always |
| `name_id_format` | string | always |

### `PATCH /admin/organizations/{orgID}/saml-providers/{providerID}`

Choose what is signed, with which algorithm, and an assertion's lifetime. Needs organizations:write.

Go `PatchOrganizationsOrgIDSAMLProvidersProviderID`, TypeScript `patchOrganizationsOrgIDSAMLProvidersProviderID`.

Takes:

| Field | Type | |
|---|---|---|
| `lifetime_s` | integer |  |
| `sign_assertions` | boolean |  |
| `sign_responses` | boolean |  |
| `signature_alg` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `metadata_changed` | boolean |  |
| `sign_assertions` | boolean | always |
| `sign_responses` | boolean | always |
| `signature_alg` | string | always |

### `DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release`

Stop releasing a SAML attribute. Needs organizations:write.

Go `DeleteOrganizationsOrgIDSAMLProvidersProviderIDAttributeRelease`, TypeScript `deleteOrganizationsOrgIDSAMLProvidersProviderIDAttributeRelease`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `removed` | boolean | always |
| `saml_attribute` | string | always |

### `PUT /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release`

Release a local attribute under a SAML attribute name. Needs organizations:write.

Go `PutOrganizationsOrgIDSAMLProvidersProviderIDAttributeRelease`, TypeScript `putOrganizationsOrgIDSAMLProvidersProviderIDAttributeRelease`.

Takes:

| Field | Type | |
|---|---|---|
| `attribute` | string |  |
| `saml_attribute` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `attribute` | string | always |
| `config_version` | integer | always |
| `id` | string | always |
| `saml_attribute` | string | always |

### `DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/group-release`

Stop telling the provider of group membership. Needs organizations:write.

Go `DeleteOrganizationsOrgIDSAMLProvidersProviderIDGroupRelease`, TypeScript `deleteOrganizationsOrgIDSAMLProvidersProviderIDGroupRelease`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `removed` | boolean | always |

### `PUT /admin/organizations/{orgID}/saml-providers/{providerID}/group-release`

Say which groups the provider is told of. Needs organizations:write.

Go `PutOrganizationsOrgIDSAMLProvidersProviderIDGroupRelease`, TypeScript `putOrganizationsOrgIDSAMLProvidersProviderIDGroupRelease`.

Takes:

| Field | Type | |
|---|---|---|
| `attribute_name` | string |  |
| `only` | list of string |  |

Answers:

| Field | Type | |
|---|---|---|
| `attribute_name` | string | always |
| `config_version` | integer | always |
| `id` | string | always |
| `only` | list of string | always |

## scim-sources

### `GET /admin/organizations/{orgID}/scim-sources`

The upstreams that provision people into the organisation; never a token. Needs config:read.

Go `GetOrganizationsOrgIDSCIMSources`, TypeScript `getOrganizationsOrgIDSCIMSources`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `sources` | list of object | always |

### `POST /admin/organizations/{orgID}/scim-sources`

Register an upstream; its bearer token is shown once. Needs organizations:write.

Go `PostOrganizationsOrgIDSCIMSources`, TypeScript `postOrganizationsOrgIDSCIMSources`.

Takes:

| Field | Type | |
|---|---|---|
| `name` | string |  |
| `on_delete` | string |  |
| `slug` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `slug` | string | always |
| `token` | string | always |

### `PATCH /admin/organizations/{orgID}/scim-sources/{slug}`

Take an upstream out of service or back. Needs organizations:write.

Go `PatchOrganizationsOrgIDSCIMSourcesSlug`, TypeScript `patchOrganizationsOrgIDSCIMSourcesSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `enabled` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean | always |
| `slug` | string | always |

## scim-targets

### `GET /admin/organizations/{orgID}/scim-targets`

The systems the organisation's people are written out to; never a token. Needs config:read.

Go `GetOrganizationsOrgIDSCIMTargets`, TypeScript `getOrganizationsOrgIDSCIMTargets`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `targets` | list of object | always |

### `POST /admin/organizations/{orgID}/scim-targets`

Register a SCIM, Google or Entra target; nothing is sent until it is synced. Needs organizations:write.

Go `PostOrganizationsOrgIDSCIMTargets`, TypeScript `postOrganizationsOrgIDSCIMTargets`.

Takes:

| Field | Type | |
|---|---|---|
| `base_url` | string |  |
| `credentials` | any |  |
| `dry_run` | boolean |  |
| `impersonate` | string |  |
| `kind` | string |  |
| `name` | string |  |
| `on_deactivate` | string |  |
| `slug` | string |  |
| `target_domain` | string |  |
| `token` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `dry_run` | boolean | always |
| `kind` | string | always |
| `slug` | string | always |

### `PATCH /admin/organizations/{orgID}/scim-targets/{slug}`

Take a target out of service or back, or scope it to a group. Needs organizations:write.

Go `PatchOrganizationsOrgIDSCIMTargetsSlug`, TypeScript `patchOrganizationsOrgIDSCIMTargetsSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `enabled` | boolean |  |
| `scope_group` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `enabled` | boolean |  |
| `scope_group` | string |  |
| `slug` | string | always |

### `DELETE /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}`

Delete a group this deployment created at a target. Needs organizations:write.

Go `DeleteOrganizationsOrgIDSCIMTargetsSlugGroupsGroup`, TypeScript `deleteOrganizationsOrgIDSCIMTargetsSlugGroupsGroup`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `group` | string | always |
| `provisioned` | boolean | always |
| `remote_id` | string | always |
| `slug` | string | always |

### `PUT /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}`

Create a group at a SCIM target and own it there. Needs organizations:write.

Go `PutOrganizationsOrgIDSCIMTargetsSlugGroupsGroup`, TypeScript `putOrganizationsOrgIDSCIMTargetsSlugGroupsGroup`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `group` | string | always |
| `provisioned` | boolean | always |
| `remote_id` | string | always |
| `slug` | string | always |

### `POST /admin/organizations/{orgID}/scim-targets/{slug}/sync`

Converge a target on who should have an account there, or preview it. Needs organizations:write.

Go `PostOrganizationsOrgIDSCIMTargetsSlugSync`, TypeScript `postOrganizationsOrgIDSCIMTargetsSlugSync`.

Takes:

| Field | Type | |
|---|---|---|
| `apply` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `applied` | boolean | always |
| `config_version` | integer | always |
| `created` | integer | always |
| `deactivated` | integer | always |
| `deleted` | integer | always |
| `error` | string |  |
| `error_detail` | string |  |
| `failed` | integer | always |
| `failures` | list of string | always |
| `groups` | list of object | always |
| `slug` | string | always |

## scopes

### `GET /admin/organizations/{orgID}/scopes`

The organisation's declared scopes, plus the standard set. Needs config:read.

Go `GetOrganizationsOrgIDScopes`, TypeScript `getOrganizationsOrgIDScopes`.

Answers:

| Field | Type | |
|---|---|---|
| `scopes` | list of object | always |
| `standard` | list of string | always |

### `PUT /admin/organizations/{orgID}/scopes`

Declare or update a scope. Needs organizations:write.

Go `PutOrganizationsOrgIDScopes`, TypeScript `putOrganizationsOrgIDScopes`.

Takes:

| Field | Type | |
|---|---|---|
| `advertise` | boolean |  |
| `description` | string |  |
| `display_name` | string |  |
| `name` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `advertise` | boolean |  |
| `config_version` | integer | always |
| `name` | string | always |

### `DELETE /admin/organizations/{orgID}/scopes/{scope}`

Remove a scope declaration. Needs organizations:write.

Go `DeleteOrganizationsOrgIDScopesScope`, TypeScript `deleteOrganizationsOrgIDScopesScope`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `name` | string | always |

## sessions

### `DELETE /admin/sessions/{sid}`

End one session. Needs users:write.

Go `DeleteSessionsSID`, TypeScript `deleteSessionsSID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `notices_queued` | integer |  |
| `sessions_ended` | integer | always |
| `sid` | string | always |
| `user_id` | string |  |

## settings

### `GET /admin/organizations/{orgID}/settings`

The organisation's sign-in and session policy. Needs config:read.

Go `GetOrganizationsOrgIDSettings`, TypeScript `getOrganizationsOrgIDSettings`.

Answers:

| Field | Type | |
|---|---|---|
| `login_free_attempts` | integer | always |
| `login_max_delay_s` | integer | always |
| `max_concurrent_sessions` | integer | always |
| `new_device_notice` | boolean | always |
| `offline_lifetime_s` | integer | always |
| `org_id` | string | always |
| `password_only_binds` | string | always |
| `persistent_sessions` | boolean | always |
| `reauth_window_s` | integer | always |
| `remember_device_days` | integer | always |
| `session_idle_s` | integer | always |
| `session_lifetime_s` | integer | always |
| `session_limit_behaviour` | string | always |
| `sms_numbers` | string | always |
| `totp_algorithm` | string | always |
| `totp_digits` | integer | always |
| `totp_period_s` | integer | always |

### `PATCH /admin/organizations/{orgID}/settings`

Change the settings named; the rest are left as they are. Needs organizations:write.

Go `PatchOrganizationsOrgIDSettings`, TypeScript `patchOrganizationsOrgIDSettings`.

Takes:

| Field | Type | |
|---|---|---|
| `login_free_attempts` | integer |  |
| `login_max_delay_s` | integer |  |
| `max_concurrent_sessions` | integer |  |
| `new_device_notice` | boolean |  |
| `offline_lifetime_s` | integer |  |
| `password_only_binds` | string |  |
| `persistent_sessions` | boolean |  |
| `reauth_window_s` | integer |  |
| `remember_device_days` | integer |  |
| `session_idle_s` | integer |  |
| `session_lifetime_s` | integer |  |
| `session_limit_behaviour` | string |  |
| `sms_numbers` | string |  |
| `totp_algorithm` | string |  |
| `totp_digits` | integer |  |
| `totp_period_s` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `login_free_attempts` | integer | always |
| `login_max_delay_s` | integer | always |
| `max_concurrent_sessions` | integer | always |
| `new_device_notice` | boolean | always |
| `offline_lifetime_s` | integer | always |
| `org_id` | string | always |
| `password_only_binds` | string | always |
| `persistent_sessions` | boolean | always |
| `reauth_window_s` | integer | always |
| `remember_device_days` | integer | always |
| `session_idle_s` | integer | always |
| `session_lifetime_s` | integer | always |
| `session_limit_behaviour` | string | always |
| `sms_numbers` | string | always |
| `totp_algorithm` | string | always |
| `totp_digits` | integer | always |
| `totp_period_s` | integer | always |

## sign-in-flow

### `GET /admin/organizations/{orgID}/sign-in-flow`

The sign-in flows applied; none runs the built-in flows. Needs config:read.

Go `GetOrganizationsOrgIDSignInFlow`, TypeScript `getOrganizationsOrgIDSignInFlow`.

Answers:

| Field | Type | |
|---|---|---|
| `applied_at` | string or null | always |
| `document` | string | always |
| `org_id` | string | always |

### `PUT /admin/organizations/{orgID}/sign-in-flow`

Apply a flow document once it loads and its tests pass. Needs organizations:write.

Go `PutOrganizationsOrgIDSignInFlow`, TypeScript `putOrganizationsOrgIDSignInFlow`.

Takes:

| Field | Type | |
|---|---|---|
| `document` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `not_executed` | list of string | always |
| `org_id` | string | always |
| `summary` | string | always |

## signup

### `DELETE /admin/organizations/{orgID}/signup`

Close self-sign-up; invitations and administrators still make accounts. Needs organizations:write.

Go `DeleteOrganizationsOrgIDSignup`, TypeScript `deleteOrganizationsOrgIDSignup`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `removed` | boolean | always |

### `GET /admin/organizations/{orgID}/signup`

Whether people may make their own accounts, from which addresses, and into which groups. Needs config:read.

Go `GetOrganizationsOrgIDSignup`, TypeScript `getOrganizationsOrgIDSignup`.

Answers:

| Field | Type | |
|---|---|---|
| `allowed_domains` | list of string | always |
| `any_domain` | boolean | always |
| `default_groups` | list of string | always |
| `enabled` | boolean | always |
| `org_id` | string | always |
| `require_approval` | boolean | always |
| `require_verified_email` | boolean | always |

### `PUT /admin/organizations/{orgID}/signup`

Open self-sign-up or replace its rule. Needs organizations:write.

Go `PutOrganizationsOrgIDSignup`, TypeScript `putOrganizationsOrgIDSignup`.

Takes:

| Field | Type | |
|---|---|---|
| `allowed_domains` | list of string |  |
| `any_domain` | boolean |  |
| `default_groups` | list of string |  |
| `require_approval` | boolean |  |
| `require_verified_email` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `allowed_domains` | list of string | always |
| `any_domain` | boolean | always |
| `config_version` | integer | always |
| `default_groups` | list of string | always |
| `enabled` | boolean | always |
| `org_id` | string | always |
| `require_approval` | boolean | always |
| `require_verified_email` | boolean | always |

## ssf-sources

### `GET /admin/organizations/{orgID}/ssf-sources`

The transmitters whose events the organisation acts on. Needs config:read.

Go `GetOrganizationsOrgIDSSFSources`, TypeScript `getOrganizationsOrgIDSSFSources`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `sources` | list of object | always |

### `PUT /admin/organizations/{orgID}/ssf-sources`

Accept events from a transmitter, or replace what it may send. Needs organizations:write.

Go `PutOrganizationsOrgIDSSFSources`, TypeScript `putOrganizationsOrgIDSSFSources`.

Takes:

| Field | Type | |
|---|---|---|
| `audience` | string |  |
| `critical_members` | list of string |  |
| `events` | list of string |  |
| `issuer` | string |  |
| `jwks_uri` | string |  |
| `name` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `issuer` | string | always |
| `name` | string | always |

## ssf-streams

### `GET /admin/organizations/{orgID}/ssf-streams`

The relying parties' Shared Signals streams; never a receiver token. Needs clients:read.

Go `GetOrganizationsOrgIDSSFStreams`, TypeScript `getOrganizationsOrgIDSSFStreams`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `streams` | list of object | always |

### `POST /admin/organizations/{orgID}/ssf-streams`

Register a client's stream, pushed or polled. Needs clients:write.

Go `PostOrganizationsOrgIDSSFStreams`, TypeScript `postOrganizationsOrgIDSSFStreams`.

Takes:

| Field | Type | |
|---|---|---|
| `client_id` | string |  |
| `endpoint` | string |  |
| `events` | list of string |  |
| `poll` | boolean |  |
| `receiver_token` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `config_version` | integer | always |
| `events` | list of string | always |
| `id` | string | always |

## subjects

### `POST /admin/subjects/{subjectID}/erase`

Crypto-shred a subject. Permanent. Needs subjects:erase. A target that may impersonate others also needs privileged-users:write.

Go `PostSubjectsSubjectIDErase`, TypeScript `postSubjectsSubjectIDErase`.

Takes:

| Field | Type | |
|---|---|---|
| `confirm_subject_id` | string |  |
| `deactivate` | boolean |  |

Answers:

| Field | Type | |
|---|---|---|
| `account_deleted` | boolean |  |
| `config_version` | integer | always |
| `deactivated` | boolean |  |
| `erased` | boolean | always |
| `key_shredded` | boolean |  |
| `notices_queued` | integer |  |
| `sessions_ended` | integer |  |
| `subject_id` | string | always |
| `totp_credentials` | integer |  |

### `GET /admin/subjects/{subjectID}/export`

Everything kept about a person, credentials withheld. Needs subjects:export.

Go `GetSubjectsSubjectIDExport`, TypeScript `getSubjectsSubjectIDExport`.

Answers:

| Field | Type | |
|---|---|---|
| `attributes` | list of object or null |  |
| `exported_at` | string | always |
| `format` | string | always |
| `subject_id` | string | always |
| `tables` | object | always |
| `withheld` | object |  |

## system

### `GET /admin/system`

The release, schema and size of the deployment. Requires an unscoped token. Needs config:read.

Go `GetSystem`, TypeScript `getSystem`.

Answers:

| Field | Type | |
|---|---|---|
| `commit` | string |  |
| `go` | string |  |
| `instances` | integer |  |
| `organizations` | integer | always |
| `rate_limits` | object | always |
| `release` | string | always |
| `schema` | object | always |
| `suspended_organizations` | integer |  |

## tokens

### `GET /admin/tokens`

The admin tokens this token may see; never a secret or hash. Needs tokens:read.

Go `GetTokens`, TypeScript `getTokens`.

Answers:

| Field | Type | |
|---|---|---|
| `tokens` | list of object | always |

### `POST /admin/tokens`

Mint an admin token no wider than the caller. The secret is returned once. Needs tokens:write.

Go `PostTokens`, TypeScript `postTokens`.

Takes:

| Field | Type | |
|---|---|---|
| `client_ids` | list of string |  |
| `expires_in_s` | integer |  |
| `group_ids` | list of string |  |
| `name` | string |  |
| `org_id` | string |  |
| `scopes` | list of string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `expires_at` | string | always |
| `id` | string | always |
| `name` | string | always |
| `org_id` | string |  |
| `scopes` | list of string | always |
| `secret` | string | always |

### `DELETE /admin/tokens/{tokenID}`

Revoke an admin token no wider than the caller. Needs tokens:write.

Go `DeleteTokensTokenID`, TypeScript `deleteTokensTokenID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `revoked` | boolean | always |

### `POST /admin/tokens/{tokenID}/rotate`

Replace a token's secret, the old one working for a grace period. Needs tokens:write.

Go `PostTokensTokenIDRotate`, TypeScript `postTokensTokenIDRotate`.

Takes:

| Field | Type | |
|---|---|---|
| `expires_in_s` | integer |  |
| `grace_s` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `expires_at` | string | always |
| `id` | string | always |
| `replaced_works_until` | string | always |
| `replaces` | string | always |
| `secret` | string | always |

## uma

### `GET /admin/organizations/{orgID}/uma`

Whether refused UMA requests wait for a resource owner, and how often clients poll. Needs config:read.

Go `GetOrganizationsOrgIDUMA`, TypeScript `getOrganizationsOrgIDUMA`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `owner_intervention` | boolean | always |
| `poll_interval_s` | integer | always |

### `PUT /admin/organizations/{orgID}/uma`

Offer or stop offering resource-owner intervention. Needs organizations:write.

Go `PutOrganizationsOrgIDUMA`, TypeScript `putOrganizationsOrgIDUMA`.

Takes:

| Field | Type | |
|---|---|---|
| `owner_intervention` | boolean |  |
| `poll_interval_s` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `org_id` | string | always |
| `owner_intervention` | boolean | always |
| `poll_interval_s` | integer | always |

### `GET /admin/organizations/{orgID}/uma/requests`

The UMA requests waiting for a decision, with the relations that would let each through. Needs config:read.

Go `GetOrganizationsOrgIDUMARequests`, TypeScript `getOrganizationsOrgIDUMARequests`.

Answers:

| Field | Type | |
|---|---|---|
| `org_id` | string | always |
| `requests` | list of object | always |

### `POST /admin/organizations/{orgID}/uma/requests/{requestID}/approve`

Grant a relation that lets the whole request through, and approve it. Needs organizations:write.

Go `PostOrganizationsOrgIDUMARequestsRequestIDApprove`, TypeScript `postOrganizationsOrgIDUMARequestsRequestIDApprove`.

Takes:

| Field | Type | |
|---|---|---|
| `relation` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `state` | string | always |

### `POST /admin/organizations/{orgID}/uma/requests/{requestID}/deny`

Close the request, granting nothing. Needs organizations:write.

Go `PostOrganizationsOrgIDUMARequestsRequestIDDeny`, TypeScript `postOrganizationsOrgIDUMARequestsRequestIDDeny`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `state` | string | always |

## users

### `GET /admin/users`

List users. Needs users:read.

Go `GetUsers`, TypeScript `getUsers`.

Answers:

| Field | Type | |
|---|---|---|
| `next_cursor` | string |  |
| `users` | list of object | always |

### `POST /admin/users`

Create a user. Needs users:write.

Go `PostUsers`, TypeScript `postUsers`.

Takes:

| Field | Type | |
|---|---|---|
| `email` | string |  |
| `org_id` | string |  |
| `password` | string |  |
| `username` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |

### `DELETE /admin/users/{userID}`

Remove a user, ending their sessions first. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteUsersUserID`, TypeScript `deleteUsersUserID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `notices_queued` | integer |  |
| `refresh_families_revoked` | integer |  |
| `sessions_ended` | integer |  |

### `GET /admin/users/{userID}`

One user. Needs users:read.

Go `GetUsersUserID`, TypeScript `getUsersUserID`.

Answers:

| Field | Type | |
|---|---|---|
| `created_at` | string | always |
| `display_name` | string | always |
| `email` | string | always |
| `email_verified` | boolean | always |
| `given_name` | string | always |
| `id` | string | always |
| `locale` | string | always |
| `org_id` | string | always |
| `require_password_change` | boolean | always |
| `status` | string | always |
| `surname` | string | always |
| `updated_at` | string | always |
| `username` | string | always |

### `PATCH /admin/users/{userID}`

Update a user's status, password or identity fields. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `PatchUsersUserID`, TypeScript `patchUsersUserID`.

Takes:

| Field | Type | |
|---|---|---|
| `active` | boolean |  |
| `display_name` | string |  |
| `email` | string |  |
| `given_name` | string |  |
| `locale` | string |  |
| `password` | string |  |
| `require_password_change` | boolean |  |
| `surname` | string |  |
| `username` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `id` | string | always |
| `sessions_ended` | integer |  |

## users / attributes

### `GET /admin/users/{userID}/attributes`

One user's attribute values. Needs users:read.

Go `GetUsersUserIDAttributes`, TypeScript `getUsersUserIDAttributes`.

Answers:

| Field | Type | |
|---|---|---|
| `attributes` | list of object | always |
| `user_id` | string | always |

### `PUT /admin/users/{userID}/attributes`

Set a user's attribute values. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `PutUsersUserIDAttributes`, TypeScript `putUsersUserIDAttributes`.

Takes:

| Field | Type | |
|---|---|---|
| `attributes` | object |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `user_id` | string | always |

### `DELETE /admin/users/{userID}/attributes/{name}`

Clear one of a user's attribute values. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteUsersUserIDAttributesName`, TypeScript `deleteUsersUserIDAttributesName`.

Answers:

| Field | Type | |
|---|---|---|
| `attribute` | string | always |
| `cleared` | boolean | always |
| `config_version` | integer | always |
| `user_id` | string | always |

## users / consents

### `GET /admin/users/{userID}/consents`

The applications a person consented to or that hold a grant. Needs users:read.

Go `GetUsersUserIDConsents`, TypeScript `getUsersUserIDConsents`.

Answers:

| Field | Type | |
|---|---|---|
| `consents` | list of object | always |
| `user_id` | string | always |

### `DELETE /admin/users/{userID}/consents/{clientID}`

Withdraw a consent and revoke the application's refresh grants. Needs users:write.

Go `DeleteUsersUserIDConsentsClientID`, TypeScript `deleteUsersUserIDConsentsClientID`.

Answers:

| Field | Type | |
|---|---|---|
| `client_id` | string | always |
| `config_version` | integer | always |
| `refresh_grants_revoked` | integer | always |
| `user_id` | string | always |

## users / credential-offers

### `POST /admin/users/{userID}/credential-offers`

Mint a Credential Offer for the person. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `PostUsersUserIDCredentialOffers`, TypeScript `postUsersUserIDCredentialOffers`.

Takes:

| Field | Type | |
|---|---|---|
| `client_id` | string |  |
| `credential_configurations` | list of string |  |
| `credential_issuer` | string |  |
| `expires_in_s` | integer |  |
| `tx_code` | boolean |  |
| `tx_code_length` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `expires_at` | string | always |
| `offer` | object | always |
| `offer_uri` | string | always |
| `tx_code` | string |  |
| `user_id` | string | always |

## users / duo

### `PUT /admin/users/{userID}/duo`

Enrol a person in Duo by the username they have there. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `PutUsersUserIDDuo`, TypeScript `putUsersUserIDDuo`.

Takes:

| Field | Type | |
|---|---|---|
| `duo_username` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `duo_username` | string | always |
| `user_id` | string | always |

## users / factors

### `GET /admin/users/{userID}/factors`

What the user can authenticate with. No secret material. Needs users:read.

Go `GetUsersUserIDFactors`, TypeScript `getUsersUserIDFactors`.

Answers:

| Field | Type | |
|---|---|---|
| `factors` | list of object | always |
| `has_second_factor` | boolean |  |
| `recovery_codes_disabled` | boolean |  |
| `recovery_codes_unused` | integer |  |
| `user_id` | string | always |

### `DELETE /admin/users/{userID}/factors/{kind}`

Remove a factor the user holds one of. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteUsersUserIDFactorsKind`, TypeScript `deleteUsersUserIDFactorsKind`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `factor` | string | always |
| `notices_queued` | integer |  |
| `removed` | integer | always |
| `sessions_ended` | integer |  |
| `user_id` | string | always |

### `DELETE /admin/users/{userID}/factors/{kind}/{factorID}`

Remove one of several factors. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteUsersUserIDFactorsKindFactorID`, TypeScript `deleteUsersUserIDFactorsKindFactorID`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `factor` | string | always |
| `notices_queued` | integer |  |
| `removed` | integer | always |
| `sessions_ended` | integer |  |
| `user_id` | string | always |

## users / identity-links

### `GET /admin/users/{userID}/identity-links`

The upstream subjects a person is linked to. Needs users:read.

Go `GetUsersUserIDIdentityLinks`, TypeScript `getUsersUserIDIdentityLinks`.

Answers:

| Field | Type | |
|---|---|---|
| `links` | list of object | always |
| `user_id` | string | always |

### `DELETE /admin/users/{userID}/identity-links/{slug}`

Detach the person from a provider. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteUsersUserIDIdentityLinksSlug`, TypeScript `deleteUsersUserIDIdentityLinksSlug`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `linked` | boolean | always |
| `provider` | string | always |
| `subject` | string | always |
| `user_id` | string | always |

### `PUT /admin/users/{userID}/identity-links/{slug}`

Make a provider's subject act as the person, so its assertions mint for them. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `PutUsersUserIDIdentityLinksSlug`, TypeScript `putUsersUserIDIdentityLinksSlug`.

Takes:

| Field | Type | |
|---|---|---|
| `subject` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `changed` | boolean | always |
| `config_version` | integer | always |
| `linked` | boolean | always |
| `provider` | string | always |
| `subject` | string | always |
| `user_id` | string | always |

## users / passkey-link

### `POST /admin/users/{userID}/passkey-link`

Email the user a single-use link to register a passkey. The token is never returned. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `PostUsersUserIDPasskeyLink`, TypeScript `postUsersUserIDPasskeyLink`.

Takes:

| Field | Type | |
|---|---|---|
| `ttl_seconds` | integer |  |

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer |  |
| `expires_at` | string | always |
| `link_id` | string | always |
| `user_id` | string | always |

## users / sessions

### `DELETE /admin/users/{userID}/sessions`

End all of a user's sessions. Needs users:write.

Go `DeleteUsersUserIDSessions`, TypeScript `deleteUsersUserIDSessions`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `notices_queued` | integer |  |
| `sessions_ended` | integer | always |
| `user_id` | string | always |

### `GET /admin/users/{userID}/sessions`

A user's live sessions. Needs users:read.

Go `GetUsersUserIDSessions`, TypeScript `getUsersUserIDSessions`.

Answers:

| Field | Type | |
|---|---|---|
| `next_cursor` | string |  |
| `sessions` | list of object | always |

## users / throttle

### `DELETE /admin/users/{userID}/throttle`

Clear the sign-in delay and the budgets wrong guesses charged to the user. Needs users:write. A target that may impersonate others also needs privileged-users:write.

Go `DeleteUsersUserIDThrottle`, TypeScript `deleteUsersUserIDThrottle`.

Answers:

| Field | Type | |
|---|---|---|
| `config_version` | integer | always |
| `counts_cleared` | integer |  |
| `user_id` | string | always |

## webauthn-policy

### `GET /admin/organizations/{orgID}/webauthn-policy`

Read the organisation's authenticator policy. Needs config:read.

Go `GetOrganizationsOrgIDWebauthnPolicy`, TypeScript `getOrganizationsOrgIDWebauthnPolicy`.

Answers:

| Field | Type | |
|---|---|---|
| `algorithms` | list of integer |  |
| `allowed_aaguids` | list of string |  |
| `attachment` | string |  |
| `attestation` | string | always |
| `hints` | list of string |  |
| `refuse_cloned` | boolean |  |
| `resident_key` | string |  |
| `timeout_seconds` | integer |  |
| `user_verification` | string |  |

### `PUT /admin/organizations/{orgID}/webauthn-policy`

Set attestation, approved models and cloned-authenticator refusal. Needs organizations:write.

Go `PutOrganizationsOrgIDWebauthnPolicy`, TypeScript `putOrganizationsOrgIDWebauthnPolicy`.

Takes:

| Field | Type | |
|---|---|---|
| `algorithms` | list of integer |  |
| `allowed_aaguids` | list of string |  |
| `attachment` | string |  |
| `attestation` | string |  |
| `hints` | list of string |  |
| `refuse_cloned` | boolean |  |
| `resident_key` | string |  |
| `timeout_seconds` | integer |  |
| `user_verification` | string |  |

Answers:

| Field | Type | |
|---|---|---|
| `algorithms` | list of integer |  |
| `allowed_aaguids` | list of string |  |
| `attachment` | string |  |
| `attestation` | string | always |
| `config_version` | integer | always |
| `hints` | list of string |  |
| `refuse_cloned` | boolean |  |
| `resident_key` | string |  |
| `timeout_seconds` | integer |  |
| `user_verification` | string |  |
