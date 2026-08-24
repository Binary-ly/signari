# Audit streaming

The audit trail is a hash-linked chain in PostgreSQL, verifiable there. Until now
it never left the box, so a host breach put the evidence and the incident in one
blast radius — the case OWASP ASVS V16.4.3 exists for: "logs are securely
transmitted to a logically separate system for analysis, detection, alerting, and
escalation."

Streaming forwards each new event to a **syslog collector** or an **HTTP webhook**
(a SIEM's ingest endpoint) as it is written.

## Turning it on

Off by default — forwarding authentication events off the box is a data-residency
decision an operator makes, not a default. Set one destination:

```sh
# A SIEM webhook (Splunk HEC, Elastic, Datadog, a custom collector):
SIGNARI_AUDIT_WEBHOOK_URL=https://siem.example.com/ingest
SIGNARI_AUDIT_WEBHOOK_TOKEN=<optional bearer>          # sent as Authorization

# …or a syslog collector over TCP:
SIGNARI_AUDIT_SYSLOG_ADDR=logs.example.com:6514
SIGNARI_AUDIT_SYSLOG_TLS=1                             # wrap in TLS
SIGNARI_AUDIT_SYSLOG_HOSTNAME=idp-1                    # stamped into each line
```

If both are set the webhook wins and the choice is logged. `signari serve` starts
the forwarder automatically when a destination is configured.

## What is sent, and what is not

The **metadata** of each event: id, time, event type, org, subject, actor,
client, correlation id, retention class, the non-sensitive `detail`, and the
chain `entry_hash` so a receiver can tie a line back to the verifiable trail.

The **encrypted `detail_enc`** — the wrapped plaintext — is never sent. A SIEM is
a copy an erasure request cannot reach, and shipping the plaintext there would
defeat crypto-shredding. The `entry_hash` lets a receiver correlate without ever
holding the shred-able content.

## Delivery guarantees

- **At-least-once.** The forwarder advances its cursor (`core.audit_stream_state`,
  keyed on `audit_events.id`, a bigint sequence) only after the sink accepts a
  batch. A crash between delivery and cursor-advance replays the last batch, which
  a receiver deduplicates on the record id. The alternative — advancing first —
  would drop events on a crash, and a dropped audit event is the one an
  investigation needs.
- **Ordered.** Events are read `id ASC`, so a collector sees them in the order
  they happened.
- **Fail-safe.** A sink error leaves the cursor where it was; the batch retries on
  the next tick rather than being lost. The lag is visible (the copy falls behind)
  rather than silent (events vanish).
- **SSRF-guarded.** A webhook URL that resolves into the private network is
  refused at startup, the same `safedial` guard every other outbound path uses —
  the destination is operator-set but still a URL.
- **Syslog framing** is octet-counted RFC 5424 (RFC 6587), over TCP (and TLS when
  configured), because a JSON payload can contain newlines that newline-framing
  would split on, and an audit line dropped by a UDP datagram is a gap nobody sees.

## What this does not do

It does not forward the **diagnostic** stream (stderr slog). That is a separate
decision with a different sensitivity (the diagnostic log deliberately carries no
subject identifiers), and it is best pointed at a collector through the process
manager or a sidecar rather than from inside the engine. `docs/logging-inventory.md`
covers the diagnostic stream; this covers the audit trail.
