# Monitoring

Alert rules and a Grafana dashboard for the engine's Prometheus metrics. Turn
the metrics on with `SIGNARI_METRICS_ADDR` (or `metrics.enabled` in the Helm
chart); [the series and the label rule](../../docs/configuration.md#metrics-and-the-label-rule)
are documented with the configuration.

| File | What it is |
|---|---|
| `alerts.yaml` | Prometheus alerting rules, in rule-file format |
| `dashboard.json` | A Grafana dashboard: traffic, sign-in, providers, delivery, maintenance, capacity, runtime |

## Loading the rules

With plain Prometheus, list the file under `rule_files:`. Check it first with
`promtool check rules alerts.yaml`.

With the Prometheus operator, wrap it in a PrometheusRule. The operator picks up
rules by label, so add whatever its `ruleSelector` asks for:

```sh
{ printf 'apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata:\n  name: signari\n  labels:\n    release: prometheus\nspec:\n'
  sed 's/^/  /' deploy/monitoring/alerts.yaml; } | kubectl apply -n monitoring -f -
```

## Importing the dashboard

In Grafana, Dashboards → New → Import, then upload `dashboard.json` and choose a
Prometheus data source. The dashboard asks for its data source through a
variable, so the same file works against any of them.

## What the alerts watch

`critical` means users are failing to sign in now, or a security control is
not being applied. `warning` means something will fail, or has failed without
anyone noticing.

| Alert | Fires when |
|---|---|
| `SignariAbsent` | no engine has been scraped for five minutes |
| `SignariDatabaseUnreachable` | an engine's scrape-time queries read NaN for two minutes |
| `SignariServerErrors` | over 5% of responses are 5xx for ten minutes |
| `SignariTokenEndpointSlow` | token endpoint p99 is over a second for ten minutes |
| `SignariRestarting` | a container restarted three times in 30 minutes |
| `SignariVersionSkew` | two releases have served for an hour |
| `SignariSignInFailures` | over half of sign-ins fail for fifteen minutes, given some traffic |
| `SignariAuthFailureBurst` | over one failed authentication a second, by mechanism |
| `SignariSMSRefused`, `SignariSMSFailing` | the SMS budget is refusing, or the provider is failing |
| `SignariProviderFailingOpen` | a fail-open provider failed, so its decision was skipped |
| `SignariProviderFailingClosed` | a fail-closed provider failed, so requests were refused |
| `SignariOutboxBacklog` | a notice still being retried is over fifteen minutes old |
| `SignariOutboxParked` | a notice was given up on after every attempt |
| `SignariAuditStreamStuck` | the audit stream's lag has only grown for fifteen minutes |
| `SignariJanitorStalled` | no janitor pass has completed for fifteen minutes |
| `SignariSigningKeyOld` | the active signing key is over 100 days old |
| `SignariKeyRefreshFailing`, `SignariKeyRefreshUnready` | signing-key refreshes fail; at five in a row the node is unready |
| `SignariRequestPoolSaturated`, `SignariWorkerPoolSaturated` | a database pool has been full for ten or fifteen minutes |
| `SignariPasswordHasherSaturated` | every password-hashing slot has been busy for five minutes |

Thresholds are starting points. The sign-in and authentication-failure rules
depend on traffic, and `SignariSigningKeyOld` assumes a 90-day
`SIGNARI_KEY_ROTATION_PERIOD`; change them to fit.

A provider's `failed_open` and `failed_closed` series are exported at zero from
startup, so the first failure after a restart registers as an increase that
`increase()` can see.

## Kept in step with the engine

`TestTheMonitoringNamesOnlyExportedSeries` in `engine/internal/docsync` fails
when either file names a series the engine does not export. It also fails when
an alert has no severity, summary, description or runbook, or when a runbook
link points at a page that is missing or not published. The test checks names
and structure only, so run `promtool check rules` to check the PromQL itself.
