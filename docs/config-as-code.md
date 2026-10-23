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
```

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
attributes, resource servers and the sign-up rule. `signari export org` writes
all of them, so a deployment's export applied to an empty one plans nothing
afterwards.

An attribute's `personal` is fixed once declared, since it decides whether the
values are sealed, and its `value_type` changes only while nobody holds a value:
a file that asks otherwise is refused at the plan, before anything is written.
Pruning an attribute erases every person's value of it, which the plan says.
A scope a claim mapper is gated on is not pruned while the mapper stays, and the
sign-up rule's groups must be the organisation's or the file's own.

Not yet: identity providers, SCIM targets, RAC connections and sign-in policy,
all of which have their own commands and Admin API routes.
