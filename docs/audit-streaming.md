# Audit streaming

## Introduction

Signari's audit trail is a hash-linked chain in PostgreSQL, which you can verify
there. Until now it never left the box. So a breach of that host put the evidence
and the incident in one blast radius.

That is the case the Open Worldwide Application Security Project (OWASP)
Application Security Verification Standard (ASVS) V16.4.3 exists for: "logs are
securely transmitted to a logically separate system for analysis, detection,
alerting, and escalation."

"Streaming" forwards each new event to a **syslog collector** or an **HTTP
webhook** as it is written. The webhook is usually the ingest endpoint of a
security information and event management (SIEM) system. You turn streaming on
with environment variables.

## Turning it on

Streaming is off by default. Forwarding authentication events off the box is a
data-residency decision an administrator makes, not a default. Set one
destination:

```sh
# A SIEM webhook (Splunk HEC, Elastic, Datadog, a custom collector):
SIGNARI_AUDIT_WEBHOOK_URL=https://siem.example.com/ingest
SIGNARI_AUDIT_WEBHOOK_TOKEN=<optional bearer>          # sent as Authorization

# …or a syslog collector over TCP:
SIGNARI_AUDIT_SYSLOG_ADDR=logs.example.com:6514
SIGNARI_AUDIT_SYSLOG_TLS=1                             # wrap in TLS
SIGNARI_AUDIT_SYSLOG_HOSTNAME=idp-1                    # stamped into each line
```

If both are set, the webhook wins, and the choice is logged. `signari serve` starts
the forwarder automatically when a destination is configured.

## What is sent, and what is not

The **metadata** of each event is sent: its ID, time, event type, organisation,
subject, actor, client, correlation ID, retention class and the non-sensitive
`detail`. So is the chain's `entry_hash`, so that a receiver can tie a line back to
the verifiable trail.

Nothing personal is sent, because nothing personal is in a row. Events name people
by subject ID only. A test checks this over a person's whole life, through the
Admin API. A SIEM is a copy an erasure request cannot reach, so this matters.

An earlier version of this page described an encrypted `detail_enc` held back from
the stream. That column was never written, and has been dropped.

## Delivery guarantees

The forwarder makes these promises:

- **At-least-once.** The forwarder advances its cursor (`core.audit_stream_state`,
  keyed on `audit_events.id`, a bigint sequence) only after the sink accepts a
  batch. A crash between delivery and cursor-advance replays the last batch, which
  a receiver deduplicates on the record ID. The alternative, advancing first, would
  drop events on a crash. A dropped audit event is the one an investigation needs.
- **Ordered.** Events are read `id ASC`, so a collector sees them in the order they
  happened.
- **Once across nodes.** Every engine node runs the forwarder. A pass holds a
  transaction-scoped advisory lock from reading the cursor until it has advanced
  it. So one node sends a batch, and the others find the lock taken. Until October
  2026 each node read the same cursor and sent the same batch. A deployment of N
  nodes sent every event N times. The lag is `signari_audit_stream_lag_events`.
- **Fail-safe.** A sink error leaves the cursor where it was, and the batch retries
  on the next tick, not lost. The lag is visible (the copy falls behind), not silent
  (events vanish).
- **Guarded against server-side request forgery (SSRF).** A webhook URL that
  resolves into the private network is refused at startup. It is the same
  `safedial` guard every other outbound path uses. The destination is set by an
  administrator, but it is still a URL.
- **Syslog framing** is octet-counted RFC 5424 (RFC 6587), over TCP, and over
  Transport Layer Security ([TLS](glossary.md#tls)) when configured. A JSON payload can contain newlines, which newline framing would split
  on. And an audit line dropped by a UDP datagram is a gap nobody sees.

## What this does not do

Streaming does not forward the **diagnostic** stream (stderr slog). That is a
separate decision, with a different sensitivity: the diagnostic log deliberately
carries no subject identifiers. It is best pointed at a collector through the
process manager or a sidecar, rather than from inside the engine.

The [logging inventory](logging-inventory.md), `docs/logging-inventory.md`, covers
the diagnostic stream. This page covers the audit trail.
