# Deployment artefacts

## Helm chart — shipped

`deploy/helm/signari` deploys the engine on Kubernetes: the Deployment, a
pre-upgrade migration Job (a Helm hook running `migrate all` once, never on engine
boot, because N replicas migrating on startup race and rollback becomes
ambiguous), a Service, and optional Ingress, HPA and PodDisruptionBudget. It
refuses to render without an issuer and a stable root key rather than deploying an
engine that cannot start or one whose signing keys reset on restart. A second hook
makes the instance the engine serves. Validated with `helm lint` and `helm
template`, and installed on kind in November 2026. That run found that no pod
could start, because the image named its user, and that the engine never became
ready, because nothing made its instance. Both are fixed.
See `deploy/helm/signari/README.md`.

The chart deploys the engine, not PostgreSQL: a production identity provider's
database wants backup, HA and tuning that belong to your data platform, not to an
app chart. You bring the database and give the chart a DSN.

## The console's images — shipped

`admin/Dockerfile` builds the console as two images: Laravel under php-fpm (the
default target), and nginx in front of it (`--target web`). Both run as an
unprivileged user, and `.env` never goes into either: a developer's admin token
and database password live there, and an image is something you push somewhere.
The console reads its settings from the environment it is started in.

Under compose, on request:

```sh
CONSOLE_APP_KEY=base64:$(head -c 32 /dev/urandom | base64) \
SIGNARI_ADMIN_ADDR=:8081 SIGNARI_ADMIN_INSECURE=1 \
  docker compose --profile console up -d
docker compose exec engine /signari admin-token create -name console -org <org-uuid> \
  -scopes users:write,clients:write,config:read
# set SIGNARI_ADMIN_TOKEN to what it printed, and run the up again
docker compose exec console php artisan signari:operator-create you@example.com --break-glass
```

It is at `http://localhost:8098/admin`. It connects as `signari_admin`, which
`deploy/postgres-init/` makes with a password before migration 0001 would make it
without one, on an empty volume; for a volume made before that, set the password
with `ALTER ROLE signari_admin PASSWORD '…'`. Measured from an empty volume: the
console's own `signari:verify-boundary` passes every check from inside its container
(connected as `signari_admin`; `core` denied for reads and writes; `core_v1` empty
with no organisation context and not otherwise; no leak past a transaction), and
all 23 screens render in Chrome through its nginx with nothing refused by its
policy and no request to another origin.

The chart has it too, off unless `console.enabled`: one pod with both containers,
a migration Job after the engine's, `signari_admin` as its database user, and its
own pod name, since on the engine's it would sit behind the engine's Service.
It refuses to render without its URL, its database host, its key and password,
and an Admin API to write through. Validated with `helm lint` and `helm template`
(`TestTheHelmChartRendersTheConsole`), and installed on kind in November 2026. The
pod came up 2/2, with php-fpm as uid 82 and nginx as 101. Its boundary and
read-model commands passed every check from inside it, and its token read the
Admin API through the address the chart derives. The chart's README has the rest
of that run.

## Kubernetes operator — configuration as a resource

`operator/` keeps an organisation's configuration file applied
([its README](../operator/README.md)). A `SignariConfig` resource holds the file
that `signari apply` reads. The operator plans it through the Admin API and
applies it with the planned version as `If-Match`. Every `resyncSeconds` it plans
again, so a change made from the console or the CLI is put back. What an apply
mints goes into a Secret the resource owns, and every refusal comes back from the
engine, named, in the resource's `Ready` condition.

That is the one piece of reconciliation it owns, because it is the one a Deployment
cannot express and a CronJob of `signari apply` expresses badly: an apply on a
schedule rather than on a change, with nowhere to say what it refused. The rest
stays where it works: migrations in the Helm hook, and key rotation and the janitor
as `signari` CLI verbs run as CronJobs. The operator is a Go module of its own, like
the Terraform provider, so the engine takes no Kubernetes dependency. It never
touches the database.

## Client SDKs and framework adapters — use the standards' own ecosystems

Signari is a conformant OIDC/OAuth2 provider, and the value of standards
conformance is precisely that clients do not need a vendor SDK: any certified
OIDC relying-party library works against it unchanged — `openid-client` (Node),
`authlib` / `oauthlib` (Python), `coreos/go-oidc` (Go), Spring Security and
`pac4j` (JVM), `AppAuth` (mobile). The discovery document and JWKS are what those
libraries consume, and both are served.

A Signari-branded SDK would mostly re-wrap those, and a wrapper around a certified
library is a place for bugs the library already fixed. Where a first-party
artefact genuinely helps is the ADMIN API (registering clients, users, providers)
— that is Signari-specific and not covered by any OIDC library — and it is the
thing to build first if an SDK is wanted. Recorded rather than stubbed, for the
same reason as the operator: three half-SDKs are worse than the standard
libraries that already work.

## A first run with something to sign in to

The `first-run` profile runs `bootstrap` once the schema is in; the `demo` profile adds
`examples/go-quickstart` as an application at `http://localhost:8097/login`, and the
`demo-client` service applies its public client, `demo`, from `deploy/demo/client.yaml` to
the organisation bootstrap made. `apply` takes the only organisation there is when neither `-org` nor the
file names one, so the file names none, and applied again it plans nothing. Together,
from an empty volume to a signed-in person takes no SQL; the commands are in the
[README](../README.md#quick-start). The demo runs on the host's network so that it reaches
the engine at the issuer's own address, the one the browser uses, and trusts the
development CA under `deploy/tls`, which signs the engine's certificate for `localhost`.

With `first-run` on, the engine starts after `bootstrap` has finished. The first
measured run started them side by side, and the engine found no signing keys yet and
exited for good. Without the profile, the engine does not wait for it. Measured from an
empty volume in November 2026: one `up`, the link, a password, and the demo answered
"Signed in as" the first person, with nothing typed into a database.

## Also present

`deploy/docker-compose.yml` (the development stack and the conformance-suite
target) and `engine/Dockerfile` (a distroless, non-root, static image, optionally
FIPS-validated) predate this and remain the basis the chart builds on.

## Base images are pinned by digest

Every `FROM` in `engine/Dockerfile`, `operator/Dockerfile`, `admin/Dockerfile` and
`examples/go-quickstart/Dockerfile` names its base by tag and digest, for example
`golang:1.26.11@sha256:9579…`. The digest is what gets pulled, and the tag says what
it is. A tag is whatever its registry says today, so a build from a bare tag can
differ from the build that was checked, without anyone changing a line here.
`TestEveryBaseImageIsPinnedByDigest` fails on a `FROM` without a digest.

The cost is that a patched base arrives only when someone moves the pin. To move
one, read the digest of the index the tag names now and put it in place of the
old one:

```sh
docker buildx imagetools inspect --format '{{json .Manifest}}' golang:1.26.11 | jq -r .digest
```

That is the multi-platform index, so the pin holds for every architecture the
image is built for. The console image also installs packages with `apk` as it
builds, and those are not pinned. Its base is fixed, but the image is not one
that rebuilds byte for byte.
