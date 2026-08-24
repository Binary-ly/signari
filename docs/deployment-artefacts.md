# Deployment artefacts

## Helm chart — shipped

`deploy/helm/signari` deploys the engine on Kubernetes: the Deployment, a
pre-upgrade migration Job (a Helm hook running `migrate all` once, never on engine
boot, because N replicas migrating on startup race and rollback becomes
ambiguous), a Service, and optional Ingress, HPA and PodDisruptionBudget. It
refuses to render without an issuer and a stable root key rather than deploying an
engine that cannot start or one whose signing keys reset on restart. Validated
with `helm lint` and `helm template`. See `deploy/helm/signari/README.md`.

The chart deploys the engine, not PostgreSQL: a production identity provider's
database wants backup, HA and tuning that belong to your data platform, not to an
app chart. You bring the database and give the chart a DSN.

## Kubernetes operator — deliberately not built

An operator earns its place when there is reconciliation a Deployment cannot
express: rotating the root key on a schedule, promoting signing keys, running the
janitor as a leader-elected singleton, reconciling clients and providers from
custom resources. Those are real, and they are a multi-week component with its own
release cadence, RBAC surface and upgrade story.

Building it now would be speculative: the reconciliation it would own is today
handled correctly by simpler means — migrations by the Helm hook, key rotation and
the janitor by `signari` CLI verbs run as CronJobs, clients and providers by the
config-as-code path (`signari apply`, `docs/config-as-code.md`). The honest
sequence is to run the chart, find which of those an operator would genuinely
improve for a real fleet, and build that — not to ship an operator whose CRDs
wrap CLI verbs that already work. Recorded as a roadmap item, not a gap pretended
away.

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

## Also present

`deploy/docker-compose.yml` (the development stack and the conformance-suite
target) and `engine/Dockerfile` (a distroless, non-root, static image, optionally
FIPS-validated) predate this and remain the basis the chart builds on.
