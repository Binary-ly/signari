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
transactional. The precondition is that number, used. The check runs inside the
transaction holding the row lock, so it is not itself racy.

A survey of the comparable self-hosted identity providers, read against current
upstream source on 25 August 2026, found no administrative API in the field that
accepts a precondition on a write. A provider for one of those cannot offer this
however it is written — the server has to support it.

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

## Destroying a client

The Admin API has no client-delete operation, so `terraform destroy` **disables**
the client — the operation that actually stops it being used — and emits a
warning saying the record remains. Its audit history stays intact. Remove the row
with the CLI if you need it gone.

Silently dropping it from state instead would be the worst option: Terraform
would report the client destroyed while every application using it carried on
signing people in.

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
