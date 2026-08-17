# Configuration as code

```sh
signari plan  -f signari.yaml     # what would change
signari apply -f signari.yaml     # make it so
```

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

saml_providers:
  - entity_id: urn:sharepoint:intranet
    name: Intranet
    acs_urls: [https://intranet.example.com/_trust/]
    name_id_format: emailAddress

radius_clients:
  - name: office-ap
    network: 10.0.1.0/24
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

The plan and the apply share one diff function, so a plan cannot describe
something the apply does not do — which is the single failure a plan exists to
prevent.

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
their ACS URLs, and RADIUS clients.

Not yet: identity providers, SCIM targets, RAC connections, brands and signup
rules — all of which have their own commands. Extending the file is adding a
struct and a diff function; the plan, the transaction and the prune safety are
already shared.
