# Configuration as code

```sh
signari plan  -f signari.yaml     # what would change
signari apply -f signari.yaml     # make it so
```

The Admin API takes the same file at `POST /admin/organizations/{orgID}/config`:
`"dry_run": true` answers the plan and the version it was computed against,
and an apply sent with that version as `If-Match` is refused if anything
changed since, so what is applied is what was reviewed. See
[admin-api.md](admin-api.md).

```yaml
version: 1
org: 25924b75-63ad-4dc3-bdeb-4791dcffbdbe

groups:
  - name: platform
    display_name: Platform Engineering

clients:
  - client_id: wiki
    name: Company Wiki
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
    id_token_signed_response_alg: RS256   # ES256 (default), RS256, PS256, EdDSA
    require_pushed_authorization_requests: true   # RFC 9126; omit to leave as it is
    first_party: false           # true skips the consent screen
    issuer_alias: https://old.example.com   # a live alias of the instance; "" clears
    minimum_acr: "2"             # require multi-factor; "1" accepts one factor

saml_providers:
  - entity_id: urn:sharepoint:intranet
    name: Intranet
    acs_urls: [https://intranet.example.com/_trust/]
    name_id_format: emailAddress

radius_clients:
  - name: office-ap
    network: 10.0.1.0/24

proxy_hosts:                  # applications behind forward auth
  - host: grafana.example.com
  - host: wiki.example.com:8443
    enabled: false

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

group_releases:               # which groups an application is told a person is in
  - client_id: wiki
    groups: [platform]        # or all_groups: true, never assumed
  - saml_provider: urn:sharepoint:intranet
    all_groups: true
    attribute: memberOf       # groups by default

radius_authorizations:        # what a network device puts a group's members on
  - group: platform
    vlan: 20                  # 1 to 4094, and/or filter_id
    priority: 10              # for someone in several groups, highest first

authorization_detail_types:   # RFC 9396 types the organisation accepts
  - type: payment_initiation
    fields: [actions, locations]
    required: [actions]
    clients: [bank-app]       # exactly these may ask; omit to leave the grants

client_attesters:             # attestation-based client authentication
  - name: android
    jwks: {keys: [{kty: EC, crv: P-256, x: "...", y: "...", kid: a1}]}   # public keys only

credential_configurations:    # what this issuer offers wallets (OID4VCI)
  - config_id: employee
    vct: https://example.com/employee
    always_claims: [sub]
    selective_claims: [email]
    lifetime: 720h            # left out: no expiry

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
    group_map: [{remote: "CN=Engineering,OU=Groups,DC=corp,DC=example,DC=com", group: platform}]

duo:                          # Duo for multi-factor sign-in
  client_id: DIXXXXXXXXXXXXXXXXXX
  secret: {env: DUO_SECRET_KEY}
  api_host: api-1234abcd.duosecurity.com

migration_source:             # the old provider first password sign-ins are checked against
  kind: ldap                  # or oidc_password, with client_id and client_secret
  name: Old directory
  url: ldaps://old.example.com
  bind_dn_template: uid={username},ou=people,dc=example,dc=com
  enabled: false              # off for a new one; on, it forwards each unmigrated password

providers:                    # your own service consulted at a hook, one per hook
  - hook: token_issue         # or authorize
    url: https://hooks.example.com/claims
    mode: fail_open           # or fail_closed; never assumed
    timeout: 2s               # the default; at most 5s
    claims: [department]      # what a token_issue provider may add
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
    scope_group: platform     # only its members; "" for everybody
    dry_run: false
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
    login: {env: BUILD_LOGIN}         # both by reference, compared together
    password: {env: BUILD_PASSWORD}   # left out: the connection keeps what it holds
    require_group: platform   # "" for everybody in the organisation
    recording_path: /var/lib/guacd/recordings/build
    parameters: {font-size: "12"}

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

[config.schema.json](config.schema.json) is the file's JSON Schema. It is
generated from the types `signari plan` decodes into, and a test fails if the
two drift apart. With an editor that uses the YAML language server, start the
file with

```yaml
# yaml-language-server: $schema=./config.schema.json
```

pointing at a copy of the schema, and a misspelled key, a wrong type or a value
outside a closed set (a mapper's `destination`, a provider's `mode`) is flagged
as you write it. The plan is still the authority. A schema cannot see a name
given twice, a group the deployment lacks or an expired certificate. The
schema accepts those, and the plan refuses them.

## It plans before it applies

The comparable feature elsewhere in this field applies YAML at startup. You
learn what it did afterwards, by looking at what changed.

```
signari.yaml

  ~ client         wiki   name, redirect_uris

  0 to create, 1 to update, 0 to delete

Nothing was changed. Run `signari apply` to make it so.
Anything not in the file was left alone; -prune would delete it.
```

The plan and the apply share one diff function, and the apply writes only what
the diff covers, so a plan cannot describe something the apply does not do.
That is the one failure a plan exists to prevent.

**A field the file leaves out keeps its value.** A client's `name`, `scopes` and
`enabled`, and a SAML provider's `name`, `name_id_format` and `enabled`, take
their defaults when the object is created and are left alone afterwards unless
the file names them. Until October 2026 the plan said this and the apply did
not. Any change to an object rewrote these fields from their defaults, so an
apply that moved one redirect URI switched back on a client an operator had
disabled, renamed it to its identifier, and reset its scopes.

**A `client_id` belongs to one organisation.** Client ids are unique across the
deployment, so a file that declares a client another organisation owns is
refused by name. Until October 2026 that client was planned as a create, and
the apply rewrote the other organisation's client, redirect URIs included.

## Absence is not deletion

**A file that omits a client does not delete it.**

Declarative-means-delete is right for infrastructure that can be rebuilt and
wrong for an identity provider, where a missing line takes down an application
and every session through it. That should never be the result of an edit
somebody did not realise was destructive.

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
runs in one transaction.

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

```
signari: radius_clients[ap]: remove `secret`. A RADIUS shared secret in a
repository is in every clone of it, every editor backup and the CI logs of
anyone who forked it. Set it with `signari radius add-client` instead
```

A file that names a secret is **refused**, not quietly ignored. The same applies
to client secrets and SAML certificates: those are set by their own commands and
this file leaves them alone.

A provider and an event subscription each sign what they send with a secret,
and the file has two ways to give them one, neither of which is writing it in:

- **Leave it out**, and the engine mints one when it creates the thing. The
  apply prints it once, as `signari provider add` does, and it is never shown
  again. A provider or subscription that already exists keeps the one it holds.
- **Name it by reference**: `secret: {env: NAME}`, or `{file: path}`, a relative
  path being read from beside the configuration file. `signari plan` and
  `signari apply` read it on the machine they run on, refuse one that is unset,
  empty or shorter than 32 characters, and compare it with the one held, so a
  secret changed where you keep it is planned as an update and applied.

A provisioning target's `token` (SCIM) or `credentials` (Google, Entra) is
issued by the system at the far end. The engine cannot mint one, so it is
always named by reference, in the same way. A target cannot be created
without it. On a target that exists it is compared and followed when given,
and left as it is when left out. A SCIM target's `base_url` changes only with
its `token` in the same file. The token held was issued for the old address,
and moved without a new one it would be sent to whoever answers at the new
address.

A directory source's `password` (LDAP) or `credentials` (Google, Entra), Duo's
`secret` and the migration source's `client_secret` are named by reference in
the same way. A directory source moves to another `url`, `bind_dn`,
`impersonate` or `domain` only with its credentials given again. Duo takes a
new `client_id` only with its secret, and the migration source a new endpoint
or client id only with its client secret. None of the three is contacted when
a file is planned. `signari duo set` checks Duo's keys against Duo, and
`signari dir sync` reaches the directory. A file is checked for shape only.
Pruned, a directory source and the migration source are switched off and
kept, and Duo is removed, with its people's enrolments kept.

A remote-access connection's `login` and `password` are named by reference in
the same way. They are compared and replaced together, and left out they leave
what the connection holds. A connection holding credentials moves to another
`host` or `port` only when the same file gives them again, since guacd would
otherwise type them into whatever answers at the new machine. A connection
holding none moves freely.

An identity provider's `client_secret` is named by reference too. It is
compared when given and kept when left out. A provider holding one gets a new
`client_id`, `issuer` or `token_url` only together with the secret, because
the secret was issued with that client id for that token endpoint and would
otherwise be sent to the new one.

A reference may not name the engine's own settings or its database
connection's (`SIGNARI_…`, `PG…`), nor a file that a `SIGNARI_…_FILE` setting
names, under any path. Next to a URL, `{env: SIGNARI_ROOT_KEY}` would send the
key that seals everything to whoever runs that URL, and it would be one
approval in a pull request away.

The Admin API refuses a file that names a secret by reference, dry run or not,
with `400 secret_reference`. Read there, the reference would read the server's
environment. Without one, the API's apply answers the minted secrets once.

The secrets are sealed with `SIGNARI_ROOT_KEY`, so these changes need the key:
creating a provider, subscription or target, changing a provider (the
registration it goes through seals a fresh secret before it finds the provider
exists and keeps the held one), and naming a secret by reference, which the
plan opens the held secret to compare against. Without the key the plan
refuses such a change and names it. Any other change needs no key, and neither
does a file that touches none of these kinds.
`signari export org` writes none of these secrets. Applied to another
deployment, the export mints new signing secrets, and each service must then
be given its new one. A target's token or credentials have to be named by
reference before the export will apply there, and the plan says which.

## Two smaller decisions

**A misspelled key is an error.** `redirect_uris_typo` is a line that does
nothing, and silence is the worst possible answer to "I configured that and it
had no effect".

**List order is not a change.** Reordering redirect URIs produces an empty diff.
Order in a YAML list is how a human grouped things; reporting it would make the
diff cry wolf, and a diff that cries wolf is a diff nobody reads.

## What it covers

Groups, OAuth/OIDC clients and their redirect URIs, SAML service providers and
their ACS URLs, RADIUS clients, protected hosts, declared scopes, user
attributes, resource servers, the sign-up rule, claim mappers, prompts, the
access policy, the sign-in flows, dynamic registration, the WebAuthn policy,
UMA's owner intervention, group releases to clients and SAML providers, RADIUS
group authorizations, authorization details types and their clients, client
attesters, credential configurations and proof roots, directory sources and
their group maps, the Duo integration, the migration source, extension
providers, event subscriptions,
provisioning targets, remote-access connections and identity providers.
`signari export org` writes all of them, so a
deployment's export applied to an empty one, with each target's token named by
reference, plans nothing afterwards.

The access policy and the sign-in flows are each one document, kept as the text
it was written in and loaded, its own tests run, before anything else in the
file is planned; an export carries the text that was applied. A claim mapper
names its client or says `all_clients`, so the wider disclosure is never what a
missing line means. A prompt a pruned file leaves out is **disabled, not
deleted**: its answers are the record of who agreed to what.

An attribute's `personal` is fixed once declared, since it decides whether the
values are sealed, and its `value_type` changes only while nobody holds a value:
a file that asks otherwise is refused at the plan, before anything is written.
Pruning an attribute erases every person's value of it, which the plan says.
A scope a claim mapper is gated on is not pruned while the mapper stays, and the
sign-up rule's groups must be the organisation's or the file's own.

Dynamic registration that a pruned file leaves out is **turned off, not
deleted**, so its initial access tokens are still there when it is turned on
again. `enabled: false` turns it off the same way. A pruned WebAuthn policy
returns to the defaults. The plan marks that destructive, because an
allow-list of authenticator models goes with it. The policy is compared as it
is stored, so an AAGUID written in capitals is not planned as a change every
time.

A group release names its groups or says `all_groups`, as a claim mapper names
its client: membership is authorization data. It is refused for a client or
provider the organisation does not have, and for a group the organisation or
the file does not have. With `-prune`, only the file's own groups count,
because the others are about to be deleted, and a release, sign-up rule,
provisioning scope or remote-access group naming one of them would point at
nothing.

An authorization details type's `clients` are exactly the clients that may
ask for it. Moving a type from one client to another takes it from the first,
and keeps each client's other types. A client named there must be the
organisation's own: a grant is written by client id, and another
organisation's client is refused rather than granted. An attester's key set
and a proof root's certificate are public, so the file holds them. Each is
checked as its command checks it: a private key, a certificate that is not a
CA or has expired, a field RFC 9396 does not define.

An event subscription's `enabled` is left as it is when the file leaves it out.
When deliveries keep failing, the deployment gives up on a subscription and
switches it off. A file that says `enabled: true` switches it back on, and one
that says `false` stops delivery and records that a file did it. The export
leaves `enabled` out, because which subscriptions were given up on is a fact
about this deployment and not configuration.

A provisioning target that a pruned file leaves out is **disabled, not
deleted**. Its links are the only record of which accounts at the far end are
this organisation's people, and without them nothing could deactivate those
accounts. Nor is the group a target is limited to pruned out from under it:
deleting the group would widen the target to everybody. Give the target
another `scope_group` in the same file and the group can go. Nothing is sent
to a target the file creates until it is synced.

A remote-access connection that a pruned file leaves out is disabled too, not
deleted: its sessions are the record of who reached that machine. Exported, a
connection carries no credentials. Applied elsewhere, it holds none until the
file names them.

A generic OIDC provider's endpoints are written in the file, not discovered.
That way the plan states exactly what sign-in will use, and planning contacts
nothing. `signari idp add` discovers them, and `signari export org` writes
what it found. A provider's slug is its sign-in URL, `/login/with/<slug>`,
which names no organisation, so a slug another organisation holds is refused
by name. A provider that a pruned file leaves out is **disabled, not
deleted**: its links are how the people who sign in through it reach their
accounts. A SAML upstream created by a file believes its addresses, as
`signari idp add` does, unless the file says otherwise.

**The brand is not in this file.** It belongs to the instance, and every
organisation on the instance renders with it, so applying one organisation's
file must not change another's sign-in page. Set it with `signari brand set`.
