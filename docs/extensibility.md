# Extending the engine

## Introduction

Some decisions need something only your own systems know. A fraud check may need
to see a token before it is issued. A policy engine you already run may need to
agree before someone reaches an application. During a migration, an old system
may be the only one that can check a password.

You extend Signari by running **your own service** and registering it for a named
"hook": a point where the engine stops and asks. The service is called a
"provider". **No third-party code runs inside the engine process**, and most hooks
can only take back a yes the engine has already given.

You register a provider with `signari provider add`, or through the Admin API.

## Registering a provider

This registers a service for the `authorize` hook in one organisation. Because
the service enforces access, it is registered to stop the request when it cannot
be reached:

```sh
signari provider add -org <uuid> \
  -hook authorize \
  -provider-url https://policy.internal.example.com/decide \
  -mode fail_closed
```

The engine calls the service over HTTP with a JSON contract. Every call names the
contract's version in a header, and unknown fields in either direction are
ignored. [The contract](#the-contract) says when the version moves.

The Admin API registers, rotates, bounds and removes providers the same way,
under `/admin/organizations/{orgID}/providers`. See [the Admin API](admin-api.md).

## Telling the engine's calls from anybody else's

Registration prints a **signing secret, once**. Every call carries a signature
made with it, in the scheme [event deliveries](events.md) use:

```
Signari-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">
```

Your service computes the same message authentication code (MAC) over the raw
body. It refuses a call that does not match, or whose `t` is more than a few
minutes old. So a stranger who learns the URL is refused, and so is a captured
call replayed later. The secret is sealed under `SIGNARI_ROOT_KEY`, and re-sealed
by `keys rewrap-root`. It never travels in a request.

`signari provider rotate -org <uuid> -hook authorize` prints a new one, and the
old one stops verifying at once. So give your service the new secret in the same
change. Registering the same hook again keeps the secret it had. A provider
registered before October 2026 has none, and is called unsigned until it is
rotated; `provider list` shows which.

## The contract

The [published hook contracts](hook-contracts.json), `hook-contracts.json`, are
the JSON Schema of what each hook sends and may answer. Every call says which
version it was made under:

```
Signari-Hook-Version: 1
```

The version moves when a provider has to act, because something it relies on
changed or went. A new optional member does not move it. So ignore what you do not
know, as this engine ignores what it does not know in your answer.

Check a service before anything depends on it:

```sh
signari provider test -org <uuid> -hook authorize
```

That makes the same call a decision makes, signed and through the same outbound
guard. Its request names nobody and carries `Signari-Hook-Test: 1`, so your
service can answer without recording a decision about nobody. It prints the
decision and how long it took. It exits non-zero when a real call would count as
unreachable or as no answer.

## Why out of process

Three alternatives were considered and rejected:

- **Go's `plugin` package** is Linux-only, and requires the identical toolchain,
  Go version and dependency graph. It cannot unload, and it shares an address
  space with the signing keys and password hashes.
- **An embedded expression language** evaluated on the authentication path is
  remote code execution with a configuration screen in front of it. The
  highest-severity advisories in this field's recent history live in exactly that
  surface.
- **WebAssembly** is the strongest in-process option and the largest commitment.
  It needs a runtime dependency, plus a host-function application binary
  interface (ABI) that must be designed, versioned and supported forever. And the
  sandbox's real attack surface is whatever the host exposes. **Deferred, not
  refused.**

Out-of-process reuses what is already here: the SSRF-safe dialer that refuses
private destinations, and the HTTP-and-JSON shape every other integration already
speaks. Server-side request forgery (SSRF) is tricking a server into calling an
address it should not reach.

A hook is called on the request path and answered there, once. It is not queued,
retried or parked by the outbox, the queue Signari's other deliveries go through.
That is why every provider declares what an unanswered call means. (This page
said the outbox retried them.)

## The rule that makes it safe

**Every provider declares what happens when it cannot be reached. There is no
default, and registration fails without it.** It is one of two modes:

| | |
|---|---|
| `fail_closed` | The journey stops. Use this for anything enforcing access |
| `fail_open` | The hook is skipped and the decision proceeds without it |

There is no safe default because the right answer differs per hook, and both
mistakes are silent. An authorization hook that fails open stops enforcing
exactly when something is wrong, which is when it mattered. A claims-enrichment
hook that fails closed locks every person out of a deployment because a directory
was slow.

## The `authorize` hook

It is called on the [AuthZEN](glossary.md#authzen) evaluation path, **only after
every local check has already allowed**. It can only turn that allow into a deny.

**It can never grant access the model refused.** That is the whole composition
rule, and it is deliberate. Delegating the decision outright would make the
relation graph, the conditions and the second-factor requirements all advisory,
overridable by whatever answers an HTTP request. Composing them as AND means an
external service can tighten access and cannot loosen it. So adding one can never
weaken a guarantee that already holds. To *grant* access, add a relation; that is
what the model is for.

A consequence worth knowing: a request the model was going to deny never reaches
the provider, so it costs no network round trip.

**The wire format is AuthZEN.** This engine already implements that
specification's policy decision point (PDP) side, the side that answers. So
calling somebody else's PDP is the same protocol pointed the other way. An
existing conformant PDP can be pointed at this hook without changes. A call and
its answer look like this:

```json
→  {"subject":{"type":"user","id":"alice"},
    "action":{"name":"can_edit"},
    "resource":{"type":"doc","id":"42"}}

←  {"decision": false}
```

Anything other than a 200 with a decodable body is treated as **unreachable**,
not as a decision, and that includes a 4xx. A provider that rejects the engine's
request has not made a decision. Treating "I did not understand you" as an answer
is how a contract mismatch becomes a silent authorization change.

## The `token_issue` hook

It is called at **every grant** that issues a token:

- authorization code, refresh, client credentials and device code;
- Client-Initiated Backchannel Authentication ([CIBA](glossary.md#ciba)), with
  poll, ping and push;
- token exchange, transaction tokens and jwt-bearer;
- User-Managed Access ([UMA](glossary.md#uma)), and the pre-authorized code.

It is called after this engine has decided to issue, and before the grant's
transaction opens, so a slow provider holds no database connection. It is told
who, which client, which scopes and which grant, and is given no credential:

```json
→  {"subject":"7c1e…","client_id":"web-app","scopes":["openid","offline_access"],
    "grant_type":"refresh_token","org_id":"…"}

←  {"decision": true, "claims": {"department": "research"}}
```

**`"decision": false` vetoes the issuance.** The client gets
`403 access_denied`, the provider's `reason` goes to the log and to a
`token.vetoed` audit record, and the reason never reaches the client. A vetoed refresh does not spend the
refresh token, so if the provider allows it later the same token still works.
The authorization code is spent either way.

**`claims` go into the access token**, for the names `signari provider claims`
allowed and no others. A claim the engine sets wins over a contributed one with
the same name, and so does a claim mapper's. No contributed claim may take a
name the access token defines, `cnf` and `gid` among them, even when this token
has none. A transaction token takes the veto and not the claims, because its
members are fixed by its draft.

Until October 2026 the hook was asked at the authorization code only. The claims
it was allowed to contribute were checked and then thrown away.

## The `password_verify` hook

It is called from the sign-in form for somebody still to be migrated, when the
organisation's [migration source](password-migration.md) is of kind `hook`. It is
for a system the engine cannot reach itself. Such a system speaks neither the
password grant nor the Lightweight Directory Access Protocol
([LDAP](glossary.md#ldap)), and its hashes cannot be exported or read here.

It is the one hook told a password, so it is called for nobody else. It is not
called for somebody with a password here, and not once a person has migrated:

```json
→  {"username":"alice@example.com","password":"…","org_id":"…"}

←  {"verified": true}
```

`"verified": true` takes a local hash in the sign-in's transaction, and the person
never comes this way again. `false` is a wrong password, charged like any other. A
provider that gives no answer is an outage. The person is told to try again and is
not charged, and the failure is recorded against the source.

**It must be registered `fail_closed`**, and `provider add` refuses anything else.
A password nobody could check is not a correct one, so continuing without an
answer would sign anybody in. Check `Signari-Signature` on every call: this is the
one service that would otherwise answer any stranger's question about a password.

## Hooks that can take a yes back

The five below follow the composition rule above. Each is asked after this engine
has decided yes, so a provider can refuse what would have happened, and can grant
nothing. The answer is `{"decision": true}`, or
`{"decision": false, "reason": "…"}`.

A reason goes to the log and to a `provider.refused` audit record, and never to the
person or the client. It is written by somebody outside this deployment.

There is no hook for a refresh, because `token_issue` is asked at every grant, and
says so in `grant_type`.

## The `authenticate` hook

It is asked when every step of a sign-in has passed, before the session. It is
asked for every way in: a password, a passkey, a provider, a one-time code. It is
told `subject`, `org_id`, `amr` and `client_ip`. A refusal shows the person the
same page a deactivated account does.

## The `user_create` hook

It is asked before an account is made for somebody new. That person is signing
themselves up, arriving from an identity provider, or arriving with a ticket from
a Kerberos realm that creates accounts. It is told `org_id`, `email` and
`source`, which is `signup`, `federation` or `kerberos`. For a Kerberos realm that
strips itself off, `email` holds the bare name.

It is not asked about what an administrator does. That covers an invitation, the
Admin API, `signari user create`, System for Cross-domain Identity Management
([SCIM](glossary.md#scim)), a directory sync or an import.

## The `client_access` hook

It is asked when a person reaches an application, after the access policy has let
them. That happens at the authorization endpoint, and when a device or CIBA
request is approved.

It is told an AuthZEN request, a `user` subject, a `client` resource and the
action `access`. So a policy engine you already run out of process can answer it,
as it can `authorize`.

## The `userinfo` hook

It is asked when userinfo answers. It is told `subject`, `client_id`, `scopes` and
`org_id`. A refusal is `403`.

As with `token_issue`, the answer may carry `claims`, and only names on the list
you give `signari provider claims` are kept. Nothing overwrites what is already
there, and no protocol claim can be set.

## The `saml_assertion` hook

It is asked when a Security Assertion Markup Language ([SAML](glossary.md#saml))
assertion is built. It is told `subject`, `entity_id` and `org_id`. A refusal is
told to the SAML application as a policy refusal is.

The answer may add attributes by the same list and the same rule as `userinfo`.
A value that is a list becomes several attribute values. On any other hook a list
is refused rather than ignored.

## The `flow_condition` hook

This one is not a veto. It lets a [sign-in flow](flows.md#conditions) branch on
what only your service knows, and the flow file says what each answer leads to. A
condition adds a stage, as every condition does, so what the service decides is
who is asked for more.

It is asked when a sign-in reaches a stage guarded by a condition it answers. It
is asked once in a request, however many it asks, so a sign-in cannot disagree
with itself. It is not asked at all for a flow that names none of them. A sign-in
that goes on to a second factor is a second request, and asks again.

It is told `subject`, `org_id`, `amr` and `client_ip`, and answers with a
decision and its facts:

```json
←  {"decision": true,
    "facts": {"device_managed": true, "device_compliant": false, "network_trusted": true,
              "risk_elevated": false}}
```

`decision` answers `provider_condition`. `facts` answers the conditions named the
same, and a fact left out reads false. `risk_elevated` joins this engine's own
signals, so either can raise it.

**A `fail_closed` provider that does not answer refuses the sign-in**, with the
reason `flow_provider_down`. A guess would be running a different flow from the
one applied. A `fail_open` one reads every condition false.

With no provider registered, every condition it answers reads false, and
`signari doctor` warns about any flow that asks. A `when:` written with `not`
therefore asks for more, not less.

## Constraints on a provider URL

A provider's address is held to these rules:

- **https only.** Refused at registration and again in the database.
- **Never a private, loopback or link-local address.** Checked at registration
  and again at dial time. The Domain Name System (DNS) can change between the
  two, and that change is the whole DNS-rebinding technique.
- **Timeout capped at 5 seconds.** A provider call happens while somebody is
  waiting, and a configured value cannot remove the bound.
- **Several providers on a hook compose as AND.** See below. `password_verify` and
  `flow_condition` keep one, by the schema, because their answer is a value and
  not a veto. "Which wins?" has no good answer for them.

## Several providers on one hook

An organisation's fraud check and its compliance check can both stand on a sign-in:

```sh
signari provider add -org <uuid> -hook token_issue -name fraud -position 1 \
    -provider-url https://fraud.acme.example/hook -mode fail_closed
signari provider add -org <uuid> -hook token_issue -name compliance -position 2 \
    -provider-url https://compliance.acme.example/hook -mode fail_open
signari provider claims -org <uuid> -hook token_issue -name fraud -claims risk
```

Several providers on one hook behave like this:

- **Everybody has to agree.** They are asked by `-position`, then by name, and the
  first refusal ends it. So a provider further down is not asked about what is
  already refused. Order changes who is asked, never the outcome, so put the cheap
  one first.
- **Each by its own mode.** One going away refuses or carries on as that one was
  registered.
- **A claim has one source.** `provider claims` refuses a claim another provider
  on the hook may add (`409 claim_taken`). So what a token says never depends on
  who was asked last.
- **A change names which.** `-name` tells them apart on `provider remove`,
  `rotate`, `test` and `claims`, and on the Admin API as `?name=`. With several
  and no name, the change is refused (`409 name_required`), never applied to
  whichever came first. With one, nobody has to say.

A provider registered without `-name` is called `provider-<hook>`, as every
provider was before there could be two.

## What is not built yet

`signari provider list` reports, per hook, whether any decision point actually
consults it. So registering a provider for a hook nothing calls tells you at that
moment, rather than leaving a control that silently never fires. All nine hooks
are consulted.
