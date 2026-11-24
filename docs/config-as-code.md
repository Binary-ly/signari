# Configuration as code

## Introduction

An organisation's configuration keeps changing: a new application, a new group,
a redirect address that moves. Changes made one command at a time are hard to
review before they happen, and hard to repeat on another deployment.

Signari can keep an organisation's configuration in one YAML file, which you can
review like any other code. `signari plan` shows what the file would change, and
`signari apply` makes the change. Anything the file leaves out is left alone. The
whole file is checked before anything changes, and secrets are never written in
it.

You run both commands on the command line, or send the same file to the
[Admin API](admin-api.md).

## Planning and applying

Run `signari plan` to see what a file would change, then `signari apply` to make
the change:

```sh
signari plan  -f signari.yaml     # what would change
signari apply -f signari.yaml     # make it so
```

The Admin API takes the same file at `POST /admin/organizations/{orgID}/config`.
With `"dry_run": true`, it answers the plan and the version it was computed
against. An apply sent with that version as `If-Match` is refused if anything
changed since, so what is applied is what was reviewed. See [the Admin
API](admin-api.md).

## An example file

This file holds an example of every section the file can have. The comments say
what each field does, and what leaving it out means:

```yaml
version: 1
org: 25924b75-63ad-4dc3-bdeb-4791dcffbdbe

groups:
  - name: platform
    display_name: Platform Engineering
  - name: platform-oncall
    member_of: [platform]       # its members are in platform too (groups.md)

clients:
  - client_id: wiki
    name: Company Wiki
    localized_names: {ja: 社内ウィキ}   # shown to a reader asking for Japanese
    redirect_uris: [https://wiki.example.com/oauth/callback]
    launch_url: https://wiki.example.com/

  - client_id: deploy-cli
    name: Deploy CLI
    public: true
    redirect_uris: [http://127.0.0.1:8765/callback]
    portal_hidden: true

  - client_id: api-gateway
    redirect_uris: [https://gateway.example.com/cb]
    token_exchange:              # RFC 8693; omit to leave as it is
      enabled: true
      audiences: [https://billing.example.com/api]
    access_token_ttl: 10m        # 1m to 1h; omit to leave as it is (default 5m)
    refresh_token_ttl: 168h      # 5m to 8760h (default 720h)
    id_token_signed_response_alg: RS256   # ES256 (default), or one the instance holds a key for
    authorization_signed_response_alg: ES256   # JARM: signs its responses and holds it to asking; "" lets go
    userinfo_signed_response_alg: ES256        # "" goes back to JSON
    introspection_signed_response_alg: ES256   # RFC 9701, when it asks for a JWT; "" goes back to RS256
    id_token_encrypted_response_alg: ECDH-ES   # needs a key `client set-keys` registered; "" stops
    id_token_encrypted_response_enc: A256GCM   # A128CBC-HS256 by default; also userinfo_, authorization_, introspection_
    require_pushed_authorization_requests: true   # RFC 9126; omit to leave as it is
    require_signed_request_object: true           # RFC 9101; omit to leave as it is
    first_party: false           # true skips the consent screen
    issuer_alias: https://old.example.com   # a live alias of the instance; "" clears
    minimum_acr: "2"             # require multi-factor; "1" accepts one factor

saml_providers:
  - entity_id: urn:sharepoint:intranet
    name: Intranet
    acs_urls: [https://intranet.example.com/_trust/]
    artifact_acs_urls: []     # URLs that take the response by artifact; left out is none
    ecp_acs_urls: []          # PAOS URLs, for ECP sign-ins; left out is none, and no ECP
    artifact_resolution: []   # [{index: 1, url: https://...}]: where it resolves the artifacts
                              # it sends requests by; left out is none
    name_id_format: emailAddress
    idp_initiated: true       # a sign-in can start from the portal; see saml.md
    default_relay_state: /sites/home

radius_clients:
  - name: office-ap
    network: 10.0.1.0/24

proxy_hosts:                  # applications behind forward auth
  - host: grafana.example.com
    rules:                    # first match wins; left out keeps what the host has
      - {effect: public, path: /public/**, methods: [GET, HEAD]}
      - {effect: deny, path: /metrics/**}     # /metrics, /metrics/ and below
  - host: wiki.example.com:8443
    enabled: false
  - host: n8n.other.com
    own_cookie: true          # or cookie_domain: other.com; left out keeps what it has

scopes:                       # beyond the standard ones; applied before the clients
  - name: hr
    display_name: HR data
    advertise: true           # list it in discovery

attributes:                   # what a person carries besides their account
  - name: department
    user_readable: true
  - name: badge
    value_type: number        # string (default), number, boolean or date
    personal: true            # sealed under the person's key; fixed once declared

resources:                    # RFC 8707 resources tokens may be audienced to
  - resource: https://api.example.com
    name: Orders API

signup:                       # self-sign-up; omit to leave it as it is
  domains: [example.com]      # or any_domain: true, never assumed from an empty list
  groups: [platform]
  verify_email: true          # the default
  require_approval: false

claim_mappers:                # what is released about a person, and to whom
  - attribute: department
    claim: department
    destination: id_token     # id_token, userinfo or access_token
    client_id: wiki           # or all_clients: true, never assumed
    required_scope: hr

prompts:                      # asked between authentication and the session
  - slug: terms
    title: Terms of use
    body: Read and accept them to go on.
    once: true
    fields:
      - {name: accept, type: checkbox, label: I accept, required: true}

access_policy: |              # the policy document, as `signari policy apply` takes it
  version: 1
  policies:
    - name: wiki-needs-staff
      when: {client: wiki}
      require: {groups: [platform]}
  tests:
    - {name: staff get in, given: {client: wiki, groups: [platform]}, expect: allow}
    - {name: others do not, given: {client: wiki, groups: []}, expect: deny}

sign_in_flow: |               # the flows document, as `signari flow apply` takes it
  version: 1
  flows: [...]

registration:                 # RFC 7591 dynamic client registration; omit to leave it
  open: false                 # true: no initial access token needed
  max_clients: 100
  allowed_scopes: [openid, profile, email]

webauthn_policy:              # written whole: a field left out takes the default
  attestation: direct         # none (default), indirect, direct, enterprise
  allowed_aaguids: [ee882879-721c-4913-9775-3dfcce97072a]
  user_verification: required
  timeout_seconds: 300

uma:                          # resource-owner intervention
  owner_intervention: true
  poll_interval: 30s

brand:                        # written whole; what it leaves out is the instance's
  product_name: Acme
  logo_url: https://acme.example/logo.svg
  support_url: https://help.acme.example
  colour_primary: '#0b5fff'   # the four colours are all set or none
  colour_on_primary: '#ffffff'
  colour_background: '#ffffff'
  colour_text: '#18181b'

messages:                     # the organisation's own words, as plain text
  - locale: en
    key: login.heading        # signari i18n keys prints every key
    text: Sign in to Acme

group_releases:               # which groups an application is told a person is in
  - client_id: wiki
    groups: [platform]        # or all_groups: true, never assumed
  - saml_provider: urn:sharepoint:intranet
    all_groups: true
    attribute: memberOf       # groups by default

radius_authorizations:        # what a network device puts a group's members on
  - group: platform
    vlan: 20                  # 1 to 4094, and/or filter_id
    session_timeout: 28800    # seconds, optional
    class: platform           # echoed by the device in accounting, optional
    vendor_attributes:        # by the numbers the device documents, optional
      - {vendor: 9, type: 1, value: "shell:priv-lvl=15"}
    priority: 10              # for someone in several groups, highest first

authorization_detail_types:   # RFC 9396 types the organisation accepts
  - type: payment_initiation
    fields: [actions, locations]
    required: [actions]
    clients: [bank-app]       # exactly these may ask; omit to leave the grants

client_attesters:             # attestation-based client authentication
  - name: android
    jwks: {keys: [{kty: EC, crv: P-256, x: "...", y: "...", kid: a1}]}   # public keys only

external_factors:             # services an external_factor stage may ask
  - name: push
    url: https://push.example.com/ask
    issuer: https://push.example.com
    amr: [otp]                # the most it may claim to have proved
    jwks: {keys: [{kty: EC, crv: P-256, x: "...", y: "...", kid: p1}]}   # public keys only

credential_configurations:    # what this issuer offers wallets (OID4VCI)
  - config_id: employee
    # format: jwt_vc_json     # left out: dc+sd-jwt; see oid4vci.md
    vct: https://example.com/employee
    always_claims: [sub]
    selective_claims: [email]
    lifetime: 720h            # left out: no expiry
    wallet_initiated: true    # anybody signed in may ask; left out keeps the setting

credential_proof_roots:       # CAs a wallet's key attestation must chain to
  - name: wallet-ca
    certificate: |
      -----BEGIN CERTIFICATE-----
      ...

directory_sources:            # where people are synced from
  - slug: corp-ad
    kind: ldap                # google, entra or ldap; fixed once made
    url: ldaps://dc.corp.example.com
    bind_dn: CN=signari,OU=Service,DC=corp,DC=example,DC=com
    password: {env: AD_BIND_PASSWORD}   # google and entra: credentials: {file: ...}
    base_dn: DC=corp,DC=example,DC=com
    flavour: ad               # openldap, ad or freeipa
    on_missing: report        # or deactivate
    max_deactivate_percent: 10
    dry_run: true             # a new source starts in dry run
    sync_interval_seconds: 3600   # 0 for no schedule
    group_map: [{remote: "CN=Engineering,OU=Groups,DC=corp,DC=example,DC=com", group: platform}]
    attribute_map: {employeeNumber: employee_number, userPrincipalName: email}   # ldap only

duo:                          # Duo for multi-factor sign-in
  client_id: DIXXXXXXXXXXXXXXXXXX
  secret: {env: DUO_SECRET_KEY}
  api_host: api-1234abcd.duosecurity.com

migration_source:             # the old provider first password sign-ins are checked against
  kind: ldap                  # or oidc_password, with client_id and client_secret, or hook
  name: Old directory
  url: ldaps://old.example.com
  bind_dn_template: uid={username},ou=people,dc=example,dc=com
  enabled: false              # off for a new one; on, it forwards each unmigrated password

outposts:                     # each gets a token, minted and printed once
  - {name: ldap-front, kind: ldap, search_group: directory-readers}
  - {name: wifi, kind: radius}

scim_sources:                 # upstreams provisioning people in; a token minted for each
  - {slug: hr, name: HR system, on_delete: deactivate}

ssf_streams:                  # security events a relying party is sent
  - client_id: wiki
    endpoint: https://wiki.example.com/ssf
    receiver_token: {env: WIKI_SSF_TOKEN}     # or poll: true, and no endpoint
    events: [https://schemas.openid.net/secevent/caep/event-type/session-revoked]

ssf_sources:                  # transmitters whose events are accepted
  - issuer: https://idp.partner.example
    name: Partner
    jwks_uri: https://idp.partner.example/jwks
    audience: https://signari.example.com
    events: [https://schemas.openid.net/secevent/caep/event-type/session-revoked]

authorization_model: |        # the relation model, as `signari authz model` takes it
  types:
    document:
      relations: {owner: [], viewer: [owner]}
      permissions: {read: [viewer]}

providers:                    # your own service consulted at a hook
  - hook: token_issue         # or any other hook in extensibility.md
    # name: fraud             # and position: 1, to put a second on a hook; each can refuse
    url: https://hooks.example.com/claims
    mode: fail_open           # or fail_closed; never assumed
    timeout: 2s               # the default; at most 5s
    claims: [department]      # what a token_issue, userinfo or saml_assertion provider may add
    secret: {env: CLAIMS_HOOK_SECRET}   # or {file: path}; left out, one is minted

event_subscriptions:          # where the organisation's events are delivered
  - name: siem
    url: https://siem.example.com/hooks/signari
    event_types: [login.failed, admin.client_updated]   # left out: every event

scim_targets:                 # where people are provisioned to
  - slug: slack
    base_url: https://api.slack.com/scim/v2
    token: {env: SLACK_SCIM_TOKEN}   # the target issued it: by reference only
    on_deactivate: deactivate # delete or nothing
    scope_groups: [platform, data]  # only their members; [] for everybody
    dry_run: false
    recreate_missing: false   # a new account for somebody whose linked one is gone
    compatibility: [no-patch] # no-filter, typed-members; [] for none
  - slug: billing
    base_url: https://billing.example.com/scim/v2
    token: {env: BILLING_CLIENT_SECRET}   # the client secret, with a token URL
    oauth_token_url: https://billing.example.com/oauth/token
    oauth_client_id: signari
    oauth_scope: scim.write   # may be left out
    oauth_client_auth: client_secret_post   # left out, the secret goes by HTTP Basic
  - slug: payroll
    base_url: https://payroll.example.com/scim/v2
    token: {env: PAYROLL_CLIENT_SECRET}
    oauth_token_url: https://payroll.example.com/oauth/token
    oauth_client_id: signari
    oauth_authorize_url: https://payroll.example.com/oauth/authorize   # the authorization code grant:
                              # `signari scim authorize` signs somebody in once; a new grant forgets it
  - slug: workspace
    kind: google              # or entra; fixed once made
    credentials: {file: google-sa.json}
    impersonate: admin@example.com
    target_domain: example.com

rac_connections:              # machines reached through the browser
  - slug: build
    protocol: ssh             # rdp, vnc or ssh; fixed once made
    host: build.internal
    port: 22                  # the protocol's own when left out
    login: {env: BUILD_LOGIN}         # each by reference, compared together
    password: {env: BUILD_PASSWORD}   # left out: the connection keeps what it holds
    private_key: {file: deploy.pem}   # ssh only, a PEM key
    passphrase: {env: DEPLOY_KEY_PASSPHRASE}
    require_group: platform   # "" for everybody in the organisation
    recording_path: /var/lib/guacd/recordings/build
    parameters: {font-size: "12"}
    max_connections: 2        # how many at once, 0 for no limit
    max_duration_seconds: 28800   # how long one session lasts, 0 for no limit

identity_providers:           # where people sign in from
  - slug: github              # the sign-in URL /login/with/github
    kind: github              # a named provider, oidc, saml or assertion; fixed once made
    client_id: Iv1.0123456789abcdef
    client_secret: {env: GITHUB_CLIENT_SECRET}
    attribute_map: [{claim: company, attribute: department}]
  - slug: corp
    kind: oidc                # endpoints written, not discovered
    client_id: signari
    client_secret: {file: corp-secret.txt}
    issuer: https://login.corp.example.com
    authorize_url: https://login.corp.example.com/authorize
    token_url: https://login.corp.example.com/token
    jwks_url: https://login.corp.example.com/jwks
    mfa_amr: [mfa]            # upstream values that count as multi-factor
    forward_parameters: [prompt, login_hint]   # what a sign-in passes on; see social-login.md
    group_claim: roles        # `groups` when left out
    group_map:                # what its groups grant here, replaced whole
      - {remote_group: Engineering, group: platform}
  - slug: adfs
    kind: saml
    saml:
      entity_id: https://adfs.example.com/adfs/services/trust
      sso_url: https://adfs.example.com/adfs/ls
      certificate: |          # public, so in the file
        -----BEGIN CERTIFICATE-----
        ...
```

## Editors check it as you type

Signari publishes a [JSON Schema for the file](config.schema.json),
`config.schema.json`. It is generated from the types `signari plan` decodes into,
and a test fails if the two drift apart.

If your editor uses the YAML language server, start the file with this line,
pointing at a copy of the schema:

```yaml
# yaml-language-server: $schema=./config.schema.json
```

Then a misspelled key or a wrong type is flagged as you write it. So is a value
outside a closed set, such as a mapper's `destination` or a provider's `mode`.

The plan is still the authority. A schema cannot see a name given twice, a group
the deployment lacks or an expired certificate. The schema accepts those, and the
plan refuses them.

## It plans before it applies

The comparable feature elsewhere in this field applies YAML at startup. You
learn what it did afterwards, by looking at what changed. Signari shows you the
change first, as a plan like this one:

```
signari.yaml

  ~ client         wiki   name, redirect_uris

  0 to create, 1 to update, 0 to delete

Nothing was changed. Run `signari apply` to make it so.
Anything not in the file was left alone; -prune would delete it.
```

The plan and the apply share one diff function, and the apply writes only what
the diff covers. So a plan cannot describe something the apply does not do. That
is the one failure a plan exists to prevent.

**A field the file leaves out keeps its value.** Take a client's `name`, `scopes`
and `enabled`, and a Security Assertion Markup Language ([SAML](glossary.md#saml))
provider's `name`, `name_id_format` and `enabled`. They
take their defaults when the object is created, and are left alone afterwards
unless the file names them.

Until October 2026 the plan said this and the apply did not. Any change to an
object rewrote these fields from their defaults. Take an apply that moved one
redirect URI. It switched back on a client an administrator had disabled, renamed
it to its identifier, and reset its scopes.

**A `client_id` belongs to one organisation.** Client IDs are unique across the
deployment. So a file that declares a client another organisation owns is
refused by name. Until October 2026 that client was planned as a create, and the apply
rewrote the other organisation's client, redirect URIs included.

## Absence is not deletion

**A file that omits a client does not delete it.**

In many declarative tools, a thing missing from the file is deleted. That is
right for infrastructure that can be rebuilt. It is wrong for an identity
provider, where a missing line takes down an application and every session
through it. That should never be the result of an edit somebody did not realise
was destructive.

`-prune` turns absence into deletion, and lists every deletion with its
consequence before making any of them:

```
  0 to create, 0 to update, 8 to delete

  These REMOVE things:
    - client cfg-cli — this application stops working immediately
    - group platform — every policy naming this group stops matching
    - radius_client 10.0.1.0/24 — this network device stops authenticating
```

## Everything is validated before anything changes

A bad redirect URI in the tenth client does not create nine and then stop. The
whole file is checked first, every problem is reported at once, and the apply
runs in one transaction. A file with three problems is answered like this:

```
signari: the configuration has 3 problem(s):
  clients[a]: redirect_uri "http://a.test/cb" must be https (or a loopback
    address for development)
  clients[b]: redirect_uri "https://*.b.test/cb" contains a wildcard. They are
    matched exactly, because anything looser lets a request steer where the
    authorization code is delivered
  saml_providers[urn:c]: acs_url "http://c.test/acs" must be https: it carries
    a signed assertion for a real user

Nothing was changed. A file that is half-applied looks like it worked and fails
somewhere in the middle
```

## Secrets are not in the file

A file that writes a secret into itself is refused, and the answer says where the
secret is set instead:

```
signari: radius_clients[ap]: remove `secret`. A RADIUS shared secret in a
repository is in every clone of it, every editor backup and the CI logs of
anyone who forked it. Set it with `signari radius add-client` instead
```

A file that names a secret is **refused**, not quietly ignored. The same applies
to client secrets and SAML certificates. Those are set by their own commands, and
this file leaves them alone.

### Secrets the engine signs with

A provider and an event subscription each sign what they send with a secret. The
file has two ways to give them one, and neither is writing it in:

- **Leave it out**, and the engine mints one when it creates the thing. The
  apply prints it once, as `signari provider add` does, and it is never shown
  again. A provider or subscription that already exists keeps the one it holds.
- **Name it by reference**: `secret: {env: NAME}`, or `{file: path}`. A relative
  path is read from beside the configuration file. `signari plan` and
  `signari apply` read the secret on the machine they run on. They refuse one
  that is unset, empty or shorter than 32 characters. They compare it with the
  one held, so a secret changed where you keep it is planned as an update and
  applied.

### Secrets issued at the far end

A provisioning target's secret is issued by the system at the far end. For a
System for Cross-domain Identity Management ([SCIM](glossary.md#scim)) target it
is the `token`, and for a Google or Entra target the `credentials`. The engine
cannot mint one, so it is always named by reference, in the same way. A target
cannot be created without it. On a target that exists, it is compared and
followed when given, and left as it is when left out.

A SCIM target's `base_url` changes only with its `token` in the same file. The
token held was issued for the old address. Moved without a new one, it would be
sent to whoever answers at the new address.

Some other secrets are named by reference in the same way:

- a directory source's `password`, for a Lightweight Directory Access Protocol
  ([LDAP](glossary.md#ldap)) directory, or its `credentials`, for Google or Entra;
- Duo's `secret`;
- the migration source's `client_secret`.

Each points somewhere new only with its secret given again:

- A directory source moves to another `url`, `bind_dn`, `impersonate` or `domain`
  only with its credentials given again.
- Duo takes a new `client_id` only with its secret.
- The migration source takes a new endpoint or client ID only with its client
  secret.

None of the three is contacted when a file is planned. `signari duo set` checks
Duo's keys against Duo, and `signari dir sync` reaches the directory. A file is
checked for shape only. When pruned, a directory source and the migration source
are switched off and kept. Duo is removed, with its people's enrolments kept.

### Tokens the engine generates

An [outpost's](outposts.md) token and an inbound SCIM source's bearer token are
generated by the engine and stored only as a hash. A file cannot choose one,
because either token can sign people in or create and deactivate them. Each is
minted when the file creates the thing, and printed once, like a provider's
secret.

An outpost's kind and a SCIM source's `on_delete` are fixed once made. A Shared
Signals push stream's `receiver_token` is named by reference, and a new endpoint
needs it again.

### Credentials for connections and providers

A remote-access connection's `login` and `password` are named by reference in the
same way. They are compared and replaced together, and left out they leave what
the connection holds.

A connection holding credentials moves to another `host` or `port` only when the
same file gives them again. Otherwise guacd, the program that makes the
connection, would type them into whatever answers at the new machine. A
connection holding none moves freely.

An identity provider's `client_secret` is named by reference too. It is compared
when given, and kept when left out. A provider holding one gets a new
`client_id`, `issuer` or `token_url` only together with the secret. The secret
was issued with that client ID for that token endpoint, and would otherwise be
sent to the new one.

### What a reference may not name

A reference may not name the engine's own settings or its database connection's
(`SIGNARI_…`, `PG…`). Nor may it name a file that a `SIGNARI_…_FILE` setting
names, under any path. Next to a URL, `{env: SIGNARI_ROOT_KEY}` would send the
key that seals everything to whoever runs that URL. It would be one approval in a
pull request away.

The Admin API refuses a file that names a secret by reference, dry run or not,
with `400 secret_reference`. Read there, the reference would read the engine's
own environment. Without one, the API's apply answers the minted secrets once.

### Changes that need the root key

The secrets are sealed with `SIGNARI_ROOT_KEY`, so these changes need the key:

- Creating a provider, subscription or target.
- Changing a provider. The registration it goes through seals a fresh secret
  before it finds the provider exists and keeps the held one.
- Naming a secret by reference, because the plan opens the held secret to
  compare against.

Without the key, the plan refuses such a change and names it. Any other change
needs no key, and neither does a file that touches none of these kinds.

`signari export org` writes none of these secrets. Applied to another deployment,
the export mints new signing secrets, and each service must then be given its new
one. A target's token or credentials have to be named by reference before the
export will apply there, and the plan says which.

## Two smaller decisions

**A misspelled key is an error.** `redirect_uris_typo` is a line that does
nothing. Silence is the worst possible answer to "I configured that and it had no
effect".

**List order is not a change.** Reordering redirect URIs produces an empty diff.
Order in a YAML list is how a human grouped things. Reporting it would make the
diff cry wolf, raising alarms over nothing, and a diff that cries wolf is a diff
nobody reads.

## What it covers

The file covers all of these:

- Groups, and the groups each is inside (`member_of`).
- OAuth and OpenID Connect ([OIDC](glossary.md#oidc)) clients, their redirect
  URIs, and their names in other languages (`localized_names`).
- SAML applications, which SAML calls "service providers", and their assertion
  consumer service (ACS) URLs, the addresses that receive a sign-in.
- Remote Authentication Dial-In User Service ([RADIUS](glossary.md#radius))
  clients, and RADIUS group authorizations.
- Protected hosts.
- Declared scopes, attributes of people, and resource servers.
- The sign-up rule, claim mappers and prompts.
- The access policy, the sign-in flows and the authorization model.
- Dynamic registration, and the WebAuthn policy.
- User-Managed Access ([UMA](glossary.md#uma)) owner intervention.
- Group releases to clients and SAML providers.
- Authorization details types and their clients.
- Client attesters, credential configurations and proof roots.
- Directory sources and their group maps, the Duo integration and the migration
  source.
- Outposts, inbound SCIM sources, and Shared Signals streams and sources.
- Extension providers and event subscriptions.
- Provisioning targets, remote-access connections and identity providers.

`signari export org` writes all of them. So a deployment's export applied to an
empty one, with each target's token named by reference, plans nothing
afterwards.

### Groups and names

A group's `member_of`, left out, keeps the group where it is, and `[]` takes it
out of everything. A loop among the file's own groups is refused by `signari
plan`. See [groups inside groups](groups.md#groups-inside-groups).

A client's `localized_names` are written by Best Current Practice (BCP) 47 tag,
the standard code for a language. Left out, they are kept, and `{}` takes them away.

### Policies, mappers and prompts

The access policy and the sign-in flows are each one document, kept as the text
it was written in. Each is loaded, and its own tests run, before anything else in
the file is planned. An export carries the text that was applied.

A claim mapper names its client or says `all_clients`, so the wider disclosure is
never what a missing line means. A prompt a pruned file leaves out is **disabled,
not deleted**: its answers are the record of who agreed to what.

### Attributes, scopes and sign-up

An attribute's `personal` is fixed once declared, since it decides whether the
values are sealed. Its `value_type` changes only while nobody holds a value. A
file that asks otherwise is refused at the plan, before anything is written.
Pruning an attribute erases every person's value of it, which the plan says.

A scope a claim mapper is gated on is not pruned while the mapper stays. The
sign-up rule's groups must be the organisation's or the file's own.

### Registration and WebAuthn

Dynamic registration that a pruned file leaves out is **turned off, not
deleted**. Its initial access tokens are still there when it is turned on again.
`enabled: false` turns it off the same way.

A pruned WebAuthn policy returns to the defaults. The plan marks that
destructive, because an allow-list of authenticator models goes with it. The
policy is compared as it is stored. An AAGUID is the identifier of an
authenticator model, and one written in capitals is not planned as a change every
time.

### Group releases

A group release names its groups or says `all_groups`, as a claim mapper names
its client: membership is authorization data. It is refused for a client or
provider the organisation does not have, and for a group the organisation or the
file does not have.

With `-prune`, only the file's own groups count, because the others are about to
be deleted. A release, sign-up rule, provisioning scope or remote-access group
naming one of them would point at nothing.

### Authorization details, attesters and proof roots

An authorization details type's `clients` are exactly the clients that may ask
for it. Moving a type from one client to another takes it from the first, and
keeps each client's other types. A client named there must be the organisation's
own. A grant is written by client ID, and another organisation's client is
refused rather than granted.

An attester's key set and a proof root's certificate are public, so the file
holds them. Each is checked as its command checks it. That refuses a private key,
and a certificate that is not a certificate authority (CA) or has expired. It
also refuses a field that Request for Comments (RFC) 9396 does not define.

### Event subscriptions

An event subscription's `enabled` is left as it is when the file leaves it out.
When deliveries keep failing, the deployment gives up on a subscription and
switches it off. A file that says `enabled: true` switches it back on. One that
says `false` stops delivery, and records that a file did it.

The export leaves `enabled` out. Which subscriptions were given up on is a fact
about this deployment, and not configuration.

### Provisioning targets and remote access

A provisioning target that a pruned file leaves out is **disabled, not
deleted**. Its links are the only record of which accounts at the far end are
this organisation's people, and without them nothing could deactivate those
accounts.

Nor is a group a target is limited to pruned out from under it, because deleting
its last group would widen the target to everybody. Give the target
`scope_groups` without it in the same file, and the group can go. Nothing is sent
to a target the file creates until it is synced.

A remote-access connection that a pruned file leaves out is disabled too, not
deleted: its sessions are the record of who reached that machine. So are an
outpost, an inbound SCIM source and a Shared Signals source. The last is kept
because deleting it takes the record of what it sent.

A pruned stream is removed, and so is a pruned authorization model, after which
no relation check has a model to evaluate. Exported, a connection carries no
credentials. Applied elsewhere, it holds none until the file names them.

### Identity providers

A generic OIDC provider's endpoints are written in the file, not discovered. That
way the plan states exactly what sign-in will use, and planning contacts nothing.
`signari idp add` discovers them, and `signari export org` writes what it found.

A provider's slug is its sign-in URL, `/login/with/<slug>`, which names no
organisation. So a slug another organisation holds is refused by name.

A provider that a pruned file leaves out is **disabled, not deleted**. Its links
are how the people who sign in through it reach their accounts. A SAML upstream
created by a file believes its addresses, as `signari idp add` does, unless the
file says otherwise.

**The brand is not in this file.** It belongs to the instance, and every
organisation on the instance renders with it. So applying one organisation's file
must not change another's sign-in page. Set it with `signari brand set`.
