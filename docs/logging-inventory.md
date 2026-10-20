# Logging inventory

OWASP ASVS 5.0.0 **V16.1.1** requires this document to exist:

> "Verify that an inventory exists documenting the logging performed at each
> layer of the application's technology stack, what events are being logged, log
> formats, where that logging is stored, how it is used, how access to it is
> controlled, and for how long logs are kept."

It was the only ASVS requirement met by writing prose rather than code, which is
why it had not been met: nothing in the engine was missing, and nothing failed.

## The two layers, which are not the same thing

Signari logs at two layers with different guarantees, and conflating them is the
mistake this document exists to prevent.

| | Diagnostic log | Audit trail |
|---|---|---|
| Written by | `slog` | `core.audit_events` |
| Destination | stderr | PostgreSQL |
| Format | logfmt or JSON (`SIGNARI_LOG_FORMAT`), level `Info` unless `SIGNARI_LOG_LEVEL` says otherwise | table rows |
| Purpose | operating the server | evidencing what happened to an account |
| Survives a crash | only if collected | yes |
| Tamper-evident | no | yes — hash chained |
| Personal data | subject ids where a line must say whose request it was; no username, email address or certificate subject, which a test enforces. LDAP and RADIUS lines carry the client's address, an application or access point rather than a person | subject ids only, nothing encrypted; this row said avoided, and encrypted per subject |
| Authoritative | no | **yes** |

A question about *whether the server is healthy* is answered from the first. A
question about *what happened to a user* is answered from the second. The
diagnostic log is not evidence and is not treated as any.

## Layer 1 — the diagnostic log

**Personal data.** Until October 2026, LDAP binds and RADIUS logins logged the
username they were given, valid or not, an LDAP write refusal the bound DN, and
an EAP-TLS refusal the certificate's subject. They now log none of it: the
audit trail records each bind and login by subject, and an EAP-TLS refusal
names the certificate by its serial. `TestNoLogLineNamesAPerson` reads every log
call in the engine and fails on a `username`, `email`, `upn`, `bound_dn` or
similar key, or on a certificate's subject.

**Access log.** `SIGNARI_ACCESS_LOG=1` adds one line per request: method, route
pattern, status, bytes, duration and correlation id. The pattern, not the path,
so no identifier in a URL reaches it; no query string; no client address.

**Format.** logfmt via `slog.TextHandler` to stderr at `Info` by default, or JSON
with `SIGNARI_LOG_FORMAT=json`, at the level `SIGNARI_LOG_LEVEL` names. Every call site
uses structured key/value pairs; there are **zero** uses of `fmt.Sprintf` inside a
log call across `internal/`, which is what keeps V16.4.1 (log injection) met —
values are escaped by the handler rather than concatenated into a message.

**Timestamps.** `slog` emits RFC 3339 with an explicit offset, satisfying V16.2.2.

**What is deliberately not written.** Credentials, tokens, secrets, authorization
codes and assertion bodies. Two places look like exceptions and are not:

- `adminapi/server.go` logs `"token", p.Name` — the token's human-readable *name*,
  not its value.
- The panic handler logs `r.URL.Path`, never `r.URL.String()`, because a query
  string here can carry `code`, `state` or `login_hint`.

**Panics.** Caught by `withRecovery`, the last-resort handler required by
V16.5.4. Before it existed, `net/http` caught panics itself and wrote them to
stderr in Go's own format with no correlation id — the one event an operator most
needs, in the one format their log processor cannot parse. Panics now carry
`err`, `method`, `path`, `correlation_id` and `stack`, and the caller receives a
generic 500 with a reference code and nothing else.

**Correlation.** Every request is assigned a correlation id, generated server-side
and never taken from an inbound header (a caller-supplied id lets one client forge
entries into another's trace). It is echoed in a response header, shown to end
users as a short code on error pages, and stored on audit rows — so a user reading
a code aloud is enough to find both layers.

## Layer 2 — the audit trail

**Storage.** `core.audit_events`, PostgreSQL, `occurred_at timestamptz` defaulting
to `now()`.

**Coverage.** 54 distinct event types, emitted from `internal/httpapi` (50 sites)
and `internal/adminapi` (5). Authentication is covered in both directions —
`login.succeeded` and `login.failed`, which is V16.3.1's actual requirement and
the half most systems miss. Beyond authentication: consent granted and denied,
MFA enrolment and removal per factor, federation linking and refusal,
impersonation start/end/refusal, token exchange, credential issuance, SCIM
provisioning, SAML and WS-Fed issuance, RAC sessions, UMA decisions, admin
mutations, and account recovery request/cancel.

**The command line is covered too.** Every `signari` command that changes
something leaves a record. Some write their own, more specific one, for
example `admin.identity_provider_updated` from `idp disable`. Every other
command that wrote gets one `admin.cli_command` record. It names the command
and the flags given, never their values, which can be secrets. It also names
the operating-system account and host as the operator. Migration 0140's
triggers notice that a command wrote, and whether it audited itself, so a new
command needs no code to be covered. Until October 2026 about 115 commands
wrote and recorded nothing, including granting impersonation, rotating keys
and creating admin tokens.

**Tamper evidence.** Each row carries `prev_hash` and `entry_hash`, chained over
the row's plaintext `detail`. It stays verifiable after a crypto-shred because a
shred rewrites no audit row (this said the chain was over ciphertext, which it
never was). Migration 0043
removed the two `ON DELETE SET NULL` foreign keys (`org_id`, `admin_token_id`)
because both columns are inside the chain hash — deleting an organisation silently
rewrote history and broke verification. An audit row is not current state, so
referential integrity does not apply to it.

Note the precise claim, because V16.4.2 says logs "cannot be modified": the chain
makes modification **detectable**, and no ordinary administrative action can
rewrite a row. It is not a database trigger refusing `UPDATE`.

**Personal data.** Kept out by rule rather than by encryption: rows name people by
subject id, never by address, and `detail` is clear JSON that must carry nothing
personal. `detail_enc` exists in the schema for personal detail sealed under the
subject's key, and nothing writes or reads it yet; this said it held
anything personal.

**Retention.** `retention_class` is `security`, `operational` or `profile`,
constrained by a `CHECK` and defaulting to `security`. It exists so an erasure
request can be honoured partially with a documented reason — security events
survive on legitimate-interest grounds, profile events do not.

**This is classification, not expiry.** No job deletes audit rows by age. Rows are
removed only by an erasure request acting on class. An operator who needs
time-based retention has to implement it, and this sentence is here so that is a
decision rather than a surprise.

**Access control.** `signari_admin`, the role the console uses, holds **no grants
on `core`** — it reads 15 views in `core_v1`. `signari_maintenance` is `NOLOGIN`
and `BYPASSRLS` by design (migration 0003). Every org-scoped table, audit included,
carries RLS with `FORCE` (migration 0092).

## What is not covered here, and is the operator's

- **V16.4.3 — shipping logs to a separate system.** The engine writes diagnostics
  to stderr and audit rows to its own database. Neither is forwarded anywhere. If
  the host is breached, both are within reach of the breach. Collecting stderr
  into a log service and replicating or exporting the audit trail off-box are
  deployment decisions the engine deliberately does not make; `docs/audit-export.md`
  covers the export path.
- **V16.2.2 — time synchronisation.** The engine emits offsets correctly; whether
  the clock is right is NTP's job on the host.
- **Alerting and escalation.** Not provided.
