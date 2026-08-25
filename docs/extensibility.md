# Extending the engine

You extend Signari by running **your own service** and registering it for a named
hook. The engine calls it over HTTP with a versioned JSON contract, and **no
third-party code runs inside the engine process**.

```sh
signari provider add -org <uuid> \
  -hook authorize \
  -provider-url https://policy.internal.example.com/decide \
  -mode fail_closed
```

## Why out of process

Three alternatives were considered and rejected:

- **Go's `plugin` package** is Linux-only, requires the identical toolchain, Go
  version and dependency graph, cannot unload — and it shares an address space
  with the signing keys and password hashes.
- **An embedded expression language** evaluated on the authentication path is
  remote code execution with a configuration screen in front of it. The
  highest-severity advisories in this field's recent history live in exactly that
  surface.
- **WebAssembly** is the strongest in-process option and the largest commitment:
  a runtime dependency, plus a host-function ABI that must be designed, versioned
  and supported forever — and the sandbox's real attack surface is whatever the
  host exposes. **Deferred, not refused.**

Out-of-process reuses what is already here: the SSRF-safe dialer that refuses
private destinations, the outbox's retry and parking, and the HTTP-and-JSON shape
every other integration already speaks.

## The rule that makes it safe

**Every provider declares what happens when it cannot be reached. There is no
default, and registration fails without it.**

| | |
|---|---|
| `fail_closed` | The journey stops. Use this for anything enforcing access |
| `fail_open` | The hook is skipped and the decision proceeds without it |

There is no safe default because the right answer differs per hook, and both
mistakes are silent. An authorization hook that fails open stops enforcing
exactly when something is wrong — which is when it mattered. A claims-enrichment
hook that fails closed locks every user out of a deployment because a directory
was slow.

## The `authorize` hook

Called on the AuthZEN evaluation path, **only after every local check has already
allowed**, and it can only turn that allow into a deny.

**It can never grant access the model refused.** That is the whole composition
rule, and it is deliberate. Delegating the decision outright would make the
relation graph, the conditions and the second-factor requirements all advisory —
overridable by whatever answers an HTTP request. Composing them as AND means an
external service can tighten access and cannot loosen it, so adding one can never
weaken a guarantee that already holds. To *grant* access, add a relation; that is
what the model is for.

A consequence worth knowing: a request the model was going to deny never reaches
the provider, so it costs no network round trip.

**The wire format is AuthZEN**, because this engine implements that
specification's PDP side already — so calling somebody else's PDP is the same
protocol pointed the other way. An existing conformant PDP can be pointed at this
hook without changes.

```json
→  {"subject":{"type":"user","id":"alice"},
    "action":{"name":"can_edit"},
    "resource":{"type":"doc","id":"42"}}

←  {"decision": false}
```

Anything other than a 200 with a decodable body is treated as **unreachable**,
not as a decision — including a 4xx. A provider that rejects our request has not
made a decision, and treating "I did not understand you" as an answer is how a
contract mismatch becomes a silent authorization change.

## Constraints on a provider URL

- **https only.** Refused at registration and again in the database.
- **Never a private, loopback or link-local address.** Checked at registration
  and again at dial time, because DNS can change between the two — which is the
  whole DNS-rebinding technique.
- **Timeout capped at 5 seconds.** A provider call happens while somebody is
  waiting, and a configured value cannot remove the bound.
- **One provider per hook per organisation**, enforced by the schema. Two
  providers answering the same question raises "which wins?", and an engine that
  answers it by whichever row sorts first has made a policy decision nobody asked
  for.

## What is not built yet

`signari provider list` reports, per hook, whether any decision point actually
consults it — so registering a provider for a hook nothing calls tells you at
that moment rather than leaving a control that silently never fires. Today
`authorize` is the only hook, and it is consulted.
