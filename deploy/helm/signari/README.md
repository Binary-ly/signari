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
the write surface for the entire identity provider.

See `docs/configuration.md` for every environment variable; put optional ones
(SMTP, SMS, GeoIP, audit streaming) under `extraEnv`.
