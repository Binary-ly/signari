# Terraform provider for Signari

Manages a Signari deployment through its Admin API.

```hcl
terraform {
  required_providers {
    signari = {
      source = "binary-ly/signari"
    }
  }
}

provider "signari" {
  # or SIGNARI_ADMIN_ENDPOINT / SIGNARI_ADMIN_TOKEN, which is the better place:
  # a token in a .tf file is a token in version control.
  endpoint = "https://admin.internal.example.com"
}

resource "signari_client" "web" {
  client_id     = "web-app"
  org_id        = "bf55447f-3bf0-4275-aed2-c8728678c190"
  display_name  = "Web application"
  redirect_uris = ["https://app.example.com/callback"]
}

resource "signari_group" "engineering" {
  org_id       = signari_client.web.org_id
  name         = "engineering"
  display_name = "Engineering"
}

resource "signari_user" "ada" {
  org_id       = signari_client.web.org_id
  email        = "ada@example.com"
  display_name = "Ada Lovelace"
}

resource "signari_group_member" "ada_engineering" {
  group_id = signari_group.engineering.id
  user_id  = signari_user.ada.id
}
```

## Resources and data sources

| Resource | Changed in place | Replaced by a change of | Imported as |
|---|---|---|---|
| `signari_client` | `enabled`, `display_name`, `redirect_uris` | `client_id`, `org_id`, `public` | the client id |
| `signari_organization` | `status` (`active` or `suspended`) | `slug`, `display_name`, `instance_id` | the id |
| `signari_group` | `display_name`, `description` | `org_id`, `name` | the id |
| `signari_user` | `email`, `username`, the names, `locale`, `active`, `password` | `org_id` | the id |
| `signari_group_member` | nothing | `group_id`, `user_id` | `<group_id>/<user_id>` |
| `signari_client_group_release` | `only_groups` (left out, every group) | `client_id` | the client id |
| `signari_scope` | `display_name`, `description`, `advertise` | `org_id`, `name` | `<org_id>/<name>` |
| `signari_proxy_host` | `enabled` | `org_id`, `host` (in lower case) | `<org_id>/<host>` |
| `signari_organization_configuration` | `document`, `prune` | `org_id` | the organisation id |
| `signari_admin_token` | nothing | every attribute | the id (its `secret` is then empty) |

A `signari_admin_token` is minted for another automation and can be no wider
than the provider's own token, as the API refuses any wider. Its `secret` is in
state from the apply that minted it, because the server keeps only a hash. A
destroy revokes it, and one revoked outside Terraform is dropped at the next
refresh so the plan after it mints another.

`signari_organization_configuration` applies an organisation's configuration
file, as `signari apply` does (see [config-as-code.md](../docs/config-as-code.md)).
It declares everything the file format does, each part checked by its own
writer's rules: attributes, claim mappers, identity providers, SAML providers,
the access policy, the sign-in flow and the rest.

```hcl
resource "signari_organization_configuration" "acme" {
  org_id   = "bf55447f-3bf0-4275-aed2-c8728678c190"
  document = file("${path.module}/signari.yaml")
}
```

- **The plan shows the engine's plan.** `changes` is the dry run of the planned
  document, one line per change, so `terraform plan` lists what will be
  created, updated and deleted, and which of those are destructive.
- **The apply is conditional on that plan.** `planned_at` is the version the dry
  run saw, and the apply is sent it as `If-Match`. A deployment that moved after
  `terraform plan` is refused rather than overwritten with a plan nobody read.
- **Drift is put back.** A refresh runs the dry run of the document in state.
  Anything the deployment holds differently is `drift`, and drift plans an
  apply that restores the document.
- **Secrets are minted, not chosen.** A token or secret the apply generated is
  in `minted`, keyed `<kind>/<name>`, because the server shows it once. A
  document that names a secret by reference is refused, because the server
  cannot read the operator's environment. Set those parts with their own
  commands.
- **A destroy deletes nothing it declared.** It forgets the document and warns.
  A destroy that pruned the organisation empty would be the most destructive
  thing a provider could do by accident. To remove what it declared, apply a
  smaller document with `prune = true` first.

Data sources: `signari_organization` (by `id` or `slug`), `signari_group` (by
`id`, or `org_id` and `name`) and `signari_user` (by `id`, or `email`, with
`org_id` when the address is held in several organisations).

- **An organisation is never deleted by Terraform.** Deleting one erases every
  person in it, and the Admin API does not offer it. A destroy refuses and
  names `signari instance org-delete`, which does it with the database in
  front of you. Run `terraform state rm` after it. Managing organisations needs
  a token scoped to no organisation.
- **A user's password is write-only.** It is sent when the person is made and
  whenever the configuration changes it, and never read back. Left out, the
  person signs in through recovery. An update sends only the fields that
  changed. Sending the address back unchanged used to clear its verified mark,
  and an engine from before that fix still does.
- **`may_impersonate` on a group is read-only.** It is set only with
  `signari group impersonation`, so that no token can grant itself the power.
  Joining such a group needs a token holding `privileged-users:write`.
- **A membership has no read of its own.** The group's members are paged to
  find it. One removed outside Terraform is dropped from state, and the next
  plan adds it back.

## The concurrent-apply hole, and why this provider does not have it

Terraform's read-modify-write cycle has a gap that most providers live with.
`plan` reads the world, a human reads the plan, `apply` writes it — and between
the read and the write, anything may have changed. Another apply from a
colleague, a CI pipeline, somebody clicking in the admin console. Terraform
detects none of it: it sends the update, the server accepts it, and the other
change is gone. Both writes are recorded as successful, because both were.

The usual mitigations all sit outside the API and none of them closes it:

| Mitigation | What it actually protects |
|---|---|
| State locking | The *state file*, against two Terraform runs. Not the server. |
| `-refresh=true` | Narrows the window between read and write. Never closes it. |
| "Don't touch the console" | A convention, enforced by nothing. |

This provider closes it, because Signari's Admin API implements RFC 7232
preconditions. Every read records the deployment's configuration version, and
every write sends it back as `If-Match`. If anything moved in between, the
server refuses with `412 Precondition Failed` and the apply stops:

```
Error: the configuration changed since this plan was made

  with signari_client.web,
  on main.tf line 14, in resource "signari_client" "web":

  the Signari configuration changed while this apply was planned: it was at
  version 42 when read, and is now at 47. Something else has written since --
  another apply, a pipeline, or somebody in the console. Nothing was changed.
  Re-run `terraform plan` to see the current state
```

Nothing is written. Re-run `terraform plan` and the change is proposed against
what is actually there.

This works because of a property the engine already had: every mutation bumps
`core.config_version` inside the same transaction (ADR-008), so a monotonic
number identifying the exact configuration state already existed and was already
transactional. That includes a change made with the `signari` command line,
which until October 2026 moved nothing in all but three commands. A plan made
before somebody ran `signari client disable` would have re-enabled the client. The precondition is that number, used. The check runs inside the
transaction holding the row lock, so it is not itself racy.

A survey of the comparable self-hosted identity providers, read against current
upstream source on 25 August 2026, found no administrative API in the field that
accepts a precondition on a write. A provider for one of those cannot offer this
however it is written — the server has to support it.

### Many writes in one apply

The configuration version belongs to the whole deployment, not to one
resource, and every write moves it on by one. So the second write of an apply
cannot send the version the plan read, because the apply's own first write has
already moved it. Until October 2026 it did send that version, and any apply
that changed two things failed with the conflict above, reporting its own write
as somebody else's.

The provider now sends its writes one at a time and remembers the versions its
own writes produced. A resource that was read at a version from which every
later change was this apply's own is up to date. Its write is sent with the
latest version, and lands. Any other write breaks that run of versions: one
made before the apply started, or one made between two of its writes, by a
colleague, a pipeline or the console. The resource's write is then sent the
version it was read at, and refused, as before. Nothing about the guarantee is
weakened, and a conflict is never retried on the server's say-so, since that
would be the silent overwrite again.

### Waiting out the arrival limit

The Admin API turns away requests beyond its arrival limit with `429` and
`Retry-After`, before it authenticates them, so nothing was done. The provider
waits as long as the server asks, up to thirty seconds a time, and sends the
same request again, up to eight times. An apply of a few dozen objects used to
fail on a request the server had never read.

### Turning it off

```hcl
provider "signari" {
  conditional_writes = false
}
```

Defaults to `true`; a safety property that has to be opted into is one most
deployments never get. Turning it off gives ordinary last-write-wins behaviour,
and exists for a server too old to honour the header.

## `config_version`

A computed attribute, on every resource, recording the version each read
observed. It is deliberately **not** tracked for drift: it moves whenever any
configuration in the deployment changes, so treating a change in it as a change
to *this* resource would produce a permanent diff on every plan. It is state
that exists to be sent back on the next write, not a property of the object.

## What an apply changes in place, and what replaces the client

`enabled`, `display_name` and `redirect_uris` change in place, in one
conditional request. A change to `client_id`, `org_id` or `public`
**replaces** the client, and the plan says so: the client is deleted and
created again, with a new secret, and every token issued under the old one
stops working. Until October 2026 the Admin API could not rename a client or
change its redirect URIs, so a change to either replaced it too.

Before that, there was a time when this was an in-place update that sent
`enabled` alone and wrote the new values into state. The apply reported
success, the next plan was empty, and the server still held the old redirect
URIs. Every create and update is read back, so state records what the server
holds rather than what was asked for, and the server now refuses a field it
cannot set rather than dropping it. `redirect_uris` is a set, because the server
holds one: reordering it is not a change. A change made outside Terraform shows
in the next refresh, and the plan after it puts the configuration back.

## Destroying a client

`terraform destroy` deletes the client, conditional on the version the last
read observed, like any other write. Every code, token, refresh family and
consent issued under it goes with it. The audit trail keeps the record that
it existed and what was done with it, because audit events carry the client id
without a foreign key.

## Configuration

| Provider argument | Environment variable | Notes |
|---|---|---|
| `endpoint` | `SIGNARI_ADMIN_ENDPOINT` | Base URL of the Admin API. |
| `token` | `SIGNARI_ADMIN_TOKEN` | From `signari admin-token create`. |
| `conditional_writes` | — | Defaults to `true`. |

The token needs the read and write scopes of what the configuration manages:
`clients:read` and `clients:write` for clients, `groups:read` and
`groups:write` for groups and memberships, `users:read` and `users:write` for
users, and `config:read` and `organizations:write`, on a token scoped to no
organisation, for organisations:

```
signari admin-token create -name terraform \
  -scopes clients:read,clients:write,groups:read,groups:write,users:read,users:write
```

## Tests

```
go test ./...
```

Unit tests run against an in-process fake and need nothing else.

The end-to-end tests drive the same client against a **real** Admin API, because
a fake proves only that the client is self-consistent — it cannot catch a wrong
belief about the contract, such as an `ETag` the real server never sends on
reads. That failure would silently downgrade every write to unconditional while
every unit test stayed green.

```
SIGNARI_E2E_ENDPOINT=http://127.0.0.1:18081 \
SIGNARI_E2E_TOKEN=sgnadm_... \
SIGNARI_E2E_CLIENT_ID=web-app \
go test -run E2E ./internal/signari/
```

They skip when those are unset.
