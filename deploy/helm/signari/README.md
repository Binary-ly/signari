# Signari Helm chart

Deploys the Signari OIDC engine on Kubernetes: the engine Deployment, a
pre-upgrade migration Job, a Service, and optional Ingress, HPA and
PodDisruptionBudget.

## What you must provide

You bring the PostgreSQL database; this chart deploys the engine, not the
database (a production identity provider's database wants backup, HA and
tuning decisions that belong to your data platform, not to an app chart).

Three things are required, and the chart refuses to render without the first two
that would otherwise fail silently:

- `issuer` — the public https URL clients reach the engine at. It is the `iss`
  claim in every token; changing it later breaks every relying party.
- `secret.dsn` — the PostgreSQL DSN.
- `secret.rootKey` — 32 random bytes, base64 (`head -c 32 /dev/urandom | base64`).
  A generated-on-boot key would invalidate every stored signing key on restart,
  so it must be supplied and stable.

## Install

```sh
helm install signari ./deploy/helm/signari \
  --set issuer=https://auth.example.com \
  --set secret.dsn='postgres://signari:pass@db:5432/signari?sslmode=require' \
  --set secret.rootKey="$(head -c 32 /dev/urandom | base64)"
```

For production, manage the Secret yourself and reference it, so the root key and
DSN never sit in a values file or Helm release history:

```sh
kubectl create secret generic signari-secrets \
  --from-literal=SIGNARI_DSN=... \
  --from-literal=SIGNARI_ROOT_KEY=... \
  --from-literal=SIGNARI_ROOT_KEY_REF=k8s
helm install signari ./deploy/helm/signari \
  --set issuer=https://auth.example.com \
  --set secret.existingSecret=signari-secrets
```

## Migrations

Run as a `pre-install,pre-upgrade` Helm hook Job (`migrate all`), never on engine
boot — N replicas migrating on startup would race, and rollback would be
ambiguous about which version the schema is at. The Job runs before the engine
pods and is deleted before the next run. `migrations.superuserDsnSecretKey` names
a Secret key holding a bootstrap DSN when the engine's own user is not a
superuser.

## TLS

Two options. Terminate TLS at the ingress (the common case): set
`ingress.enabled` and `ingress.tls`. The issuer is still https and `__Host-`
cookies still work because the browser only sees the https ingress. Or have the
engine serve HTTPS itself: set `tls.certSecretName` to a Secret with `tls.crt`
and `tls.key`.

## The admin API

Off by default. When `adminApi.enabled`, it listens on its own port and gets its
own ClusterIP Service — never routed through the public ingress, because it is
the write surface for the entire identity provider. It serves TLS from
`tls.certSecretName`, and the chart refuses to render it without one unless
`adminApi.insecure=true` asks for plaintext by name, as the engine does.

## The console

Off by default. `console.enabled` adds the administration console beside the
engine: one pod holding php-fpm and nginx, a ClusterIP Service on 8080, and a
migration Job for its own tables that runs after the engine's. Images are built
from `admin/Dockerfile`, the default target and `--target web`. It connects to the
database as `signari_admin` and nothing wider, and writes through the Admin API,
so it needs `adminApi.enabled` or `console.adminUrl`. Give it `console.url`,
`console.database.host`, and `console.secret.appKey` and `.dbPassword` (or
`console.secret.existingSecret` holding `APP_KEY`, `DB_PASSWORD` and
`SIGNARI_ADMIN_TOKEN`); the chart refuses to render without them. The
`signari_admin` role's password is yours to set on the database, as every role's
is. Its pods carry their own name, so the engine's Service, budget and policy do
not select them.

## Metrics, network policy and scheduled commands

- `metrics.enabled` serves Prometheus metrics on their own port and ClusterIP
  Service; `metrics.serviceMonitor.enabled` adds a prometheus-operator
  ServiceMonitor for it.
- `networkPolicy.enabled` admits each port only from the peers you name:
  `httpFrom` (anyone when empty), `metricsFrom` and `adminFrom` (nobody when
  empty).
- `cronJobs` runs engine commands on a schedule with the same Secret, for
  example `signari audit verify` every night.
- `backup.enabled` dumps the database on `backup.schedule` and writes the root
  key beside each dump, keeping `backup.retentionDays` of both. It needs
  `backup.dsnSecretKey`, a superuser or `BYPASSRLS` DSN in the Secret, and
  `backup.persistence.existingClaim`, a PersistentVolumeClaim of yours. See
  [the runbook](../../../docs/runbook-backup-restore.md#on-kubernetes-with-the-chart),
  whose restore CI drills on kind.

## Installing, and what was wrong before

The migration Job runs `args: ["migrate", "all"]` against the image's
`/signari` entrypoint, and the chart's Secret is itself a hook created before
it. Until October 2026 the Job set `command:`, which replaced the entrypoint,
and the Secret was an ordinary resource created after every pre-install hook,
so the chart could not install. Because the Secret is a hook, `helm uninstall`
leaves it behind; delete it by hand, or manage it yourself with
`secret.existingSecret`. Readiness asks `/readyz`, which checks the database and
the signing keys; it used to ask `/healthz`, which only says the process is up.
The pod's `terminationGracePeriodSeconds` is derived from `shutdown.drainSeconds`
and `shutdown.timeoutSeconds`, so the kubelet never kills a request the engine is
still finishing; the chart refuses those two settings in `extraEnv`, where the
grace period could not follow them. `helm test` runs `signari verify`. The image is pinned to the chart's
`appVersion`, not `latest`.

A second hook Job, after the migration, runs `signari instance create -issuer
<issuer>`. `serve` refuses to start until an instance names the issuer it serves,
and nothing else in an install makes one. The command is idempotent, so every
upgrade runs it too.

### Run on a cluster

The chart was installed on kind in November 2026 (Kubernetes from kind's own node
image, postgres 17 beside it), with the Secret managed by hand as above. That run
found two faults that rendering could not:

- **No pod started.** The image named its user `nonroot:nonroot`, and
  `runAsNonRoot` can only check a number, so the migration Job stopped at
  `CreateContainerConfigError`. The image now runs as `65532:65532`.
- **The engine never became ready.** With the user fixed, the migration completed
  and both replicas crash-looped on `no instance with issuer`, which the
  instance Job above now makes.

After those fixes, the chart behaved as follows:

- A fresh install completed both Jobs and both replicas were ready.
- `helm test` ran `signari verify` and reported `schema ok`.
- `helm upgrade` ran both Jobs again and scaled to three ready replicas.
- Prometheus 3.5.0 scraped the metrics Service, with the target `up` and 20
  `signari_` metrics.
- The console's pod came up 2/2. Inside it, `signari:verify-boundary` and
  `signari:read-model-smoke` passed every check once the organisation had a
  person, and its token read the Admin API.

Two settings changed because of that run:

- **Liveness probe.** It now waits five seconds a probe and six probes in a row.
  On the defaults, one second and three, a node short of CPU had every replica
  restarted at once.
- **Network policy.** With `networkPolicy.enabled`, an empty `metricsFrom` closed
  the metrics port to Prometheus and an empty `adminFrom` closed the Admin API to
  the console. Naming each pod opened its port again. A policy turned on did not
  cut connections that were already open, so a scraper with a keep-alive
  connection went on reading until it reconnected.

The `ServiceMonitor` and the drain are exercised by CI on kind. The Prometheus
operator from its v0.94.2 release and a Prometheus selecting the chart's
ServiceMonitor by label found every replica up and the engine's series arriving (264
of them in the first run). With three replicas and a client inside the cluster asking
the Service for discovery every 50 ms, one pod was deleted. Its address left the
Service's EndpointSlice within 100 ms while the pod was still terminating, and none
of the 818 requests failed.

The render tests are `TestTheHelmChartCanInstall`, which also checks the instance
Job's place, and `TestTheHelmChartRendersItsOptions`.

CI repeats the install on kind whenever the chart or anything that goes into the
image changes (`.github/workflows/helm.yml`). It builds the image, starts
PostgreSQL 17 beside the chart and creates the Secret by hand, with a superuser
DSN under its own key for the migration. It then installs with metrics on and
waits for two ready replicas. After that it checks that both hook Jobs ran, that
`helm test` passed, and that `/readyz`, discovery naming the issuer, the key set
and the `signari_` metrics were all served through their Services. Last, it
upgrades to three replicas and checks that both hooks ran again. The console is
not in that job, because building its images would double the job's time.

See `docs/configuration.md` for every environment variable; put optional ones
(SMTP, SMS, GeoIP, audit streaming) under `extraEnv`.
