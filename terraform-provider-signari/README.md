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
```

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

A computed attribute recording the version each read observed. It is deliberately
**not** tracked for drift: it moves whenever any configuration in the deployment
changes, so treating a change in it as a change to *this* resource would produce
a permanent diff on every plan. It is state that exists to be sent back on the
next write, not a property of the client.

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

The token needs the `clients:read` and `clients:write` scopes:

```
signari admin-token create -name terraform -scopes clients:read,clients:write
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
