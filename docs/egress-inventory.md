# Outbound communication inventory

## Introduction

This page lists every place Signari connects to, and every third-party address a
browser fetches from one of its pages. It says which destinations are fixed,
which an administrator configures, and which a client can choose.

OWASP ASVS 5.0.0 **V13.1.1** requires this document to exist:

> "Verify that all communication needs for the application are documented. This
> must include external services which the application relies upon and cases
> where an end user might be able to provide an external location to which the
> application will then connect."

There are two audiences. An administrator writing egress firewall rules needs the
first table. Anyone assessing exposure to server-side request forgery (SSRF)
needs the section on [destinations a client can
choose](#destinations-a-client-can-choose--the-ssrf-surface). That is the half the
requirement is really about.

## Fixed destinations — vendor endpoints compiled in

These are constants in the source. Nothing a client, a person or a request can
change reaches them.

| Destination | Package | Why | Reached when |
|---|---|---|---|
| `api.pwnedpasswords.com/range/` | `passwords/breached` | breached-password check, k-anonymity prefix only — the password never leaves | a password is set or changed, if configured |
| `challenges.cloudflare.com/turnstile/v0/siteverify` | `captcha` | challenge verification | a challenge is submitted |
| `hcaptcha.com/siteverify` | `captcha` | as above | as above |
| `www.google.com/recaptcha/api/siteverify` | `captcha` | as above | as above |
| `verifiedaccess.googleapis.com/v2` | `posture/chrome` | Chrome device-posture attestation | a posture policy demands it |
| `admin.googleapis.com` | `provision/google`, `directory/google` | directory sync | a sync runs. The token request goes to the service-account key's `token_uri`, normally `oauth2.googleapis.com`. It is data, not a constant, so both clients dial through `safedial`, and a key naming an internal address is refused |
| `graph.microsoft.com`, `login.microsoftonline.com` | `provision/entra` | directory sync | a sync runs |

Each is optional: none is contacted unless an administrator configures the
feature.

## Destinations the browser reaches — not the engine

Everything above is the engine opening a connection. This section is different.
It is the **person's browser** fetching something from a third party, while they
are on one of Signari's pages.

That is a separate exposure, and a worse one. A server-to-vendor call reveals the
deployment. A browser-to-vendor call reveals the person: their IP address, and the
fact that they were signing in to this provider at that moment. An egress firewall
does not touch it.

| Destination | Page | Why it is there |
|---|---|---|
| `challenges.cloudflare.com/turnstile/v0/api.js` | any page with a captcha | Turnstile's challenge |
| `hcaptcha.com/1/api.js` | as above | hCaptcha's challenge |
| `www.google.com/recaptcha/api.js` | as above | reCAPTCHA's challenge |

**These are the one thing here that cannot be self-hosted**, and the reason is
worth being precise about: the script *is* the service. A captcha works by the
provider forming a judgement about the visitor and signing it. The engine then
verifies that judgement against the same provider.

Serving a copy of the script from this origin would produce a challenge nothing
could verify. It is not an asset Signari has declined to vendor; there is no
version of it that lives here.

What bounds it: a captcha is **off unless an administrator configures one**, and
it is never on the sign-in path by default. The provider is the administrator's
choice, including the choice not to have one. [CAPTCHA](captcha.md) has the CSP
each provider needs, which is also the list of who is being let in.

**Nothing else on any page is off-origin.** No fonts, no analytics, no CDN
scripts, no remote images. The thirty-three engine pages use a system font stack.
The console serves Instrument Sans from `admin/public/fonts/instrument-sans/`
specifically so that Filament's default font provider, which resolves to the Bunny
Fonts CDN, is not used.

That is a property worth re-checking rather than assuming. Render a page, and look
for any `src` or `href` with a scheme in it.

It was not true of the console until November 2026, and only the sign-in page had
been looked at. Filament's default avatar provider drew the administrator's avatar
at ui-avatars.com, with their initials in the address, on every screen with an
account menu.

The console now draws it as a data URI, and its test reads a signed-in screen as
well. The console's content policy is `default-src 'self'` with `data:` images.
So a fourth default of the kind is refused by the browser, rather than found by
reading. Every one of its 23 screens was swept in headless Chrome with no
violation, and no request to another origin.

## Destinations an administrator configures

An administrator names these. That does not make them safe to dial wherever they
point. A stored setting can be changed by anyone holding the right Admin API scope,
and a name can start resolving somewhere else after it was saved.

So every HTTP destination here goes through `safedial` too. One that really is
internal is named in `SIGNARI_OUTBOUND_ALLOW_PRIVATE` (see
[configuration](configuration.md#internal-destinations)). The table uses three
abbreviations: Lightweight Directory Access Protocol (LDAP), System for
Cross-domain Identity Management (SCIM), and Transport Layer Security (TLS).

| Destination | Package | Notes |
|---|---|---|
| SMTP host | `mail` | **refuses to send at all** if the mail server does not offer STARTTLS. Not HTTP; dialled directly |
| LDAP/AD directory | `directory/ldapsource`, `delegated/ldapbind` | TLS with `MinVersion` 1.2; `InsecureSkipVerify` deliberately absent. Not HTTP; a directory is internal by nature and is dialled directly |
| SMS gateway | `sms/gateway` | `safedial`; a loopback webhook URL is allowed because an administrator wrote that address down |
| Duo API host | `duo` | `safedial` |
| SCIM target | `scim/client` | `safedial`, with `SIGNARI_SCIM_CA_BUNDLE` as its roots when set |
| SSF transmitter keys | `ssf/receive` | `safedial`; fetched when a token names a key id not yet seen, which the sender chooses |
| Upstream identity provider | `httpapi/federation` | `safedial` for the token endpoint and userinfo |
| jwt-bearer issuer keys | `httpapi/jwtbearer` | `safedial`; fetched before anyone has authenticated |
| Old provider behind delegated sign-in | `delegated` | `safedial`; the request carries a password |
| FIDO metadata mirror | `fidomds` | `safedial` |
| OpenID Federation trust anchors | `oidfed/fetch` | `safedial`, plus intermediates discovered while resolving a chain |
| A Security Assertion Markup Language (SAML) application's artifact resolution service | `httpapi/samlartifactrequest` | `safedial`, https only, no redirect followed. Anybody can bring an artifact, which is what makes the call, so it goes only to the address registered under the index the artifact names, for the provider whose SourceID it carries, and once per artifact. See [saml](saml.md#requests-by-artifact) |
| Outpost callbacks | `outpost` | the outpost agent calling its own engine; not a request the engine makes |
| A URL passed to `signari proxycheck` / sign-out test | `proxycheck`, `logouttest` | diagnostics, run by hand, not by the engine |
| Vault or OpenBao transit engine | `keys` | named only by `SIGNARI_VAULT_ADDR`, and not `safedial`, as that server is the administrator's own, usually on their network. Plain http is refused except to loopback, since the token goes with every request. Makes and reads signing keys and asks for signatures; nothing private comes back. See [signing keys in a module](signing-keys-in-a-module.md) |
| OpenTelemetry collector | `tracing` | named only by `SIGNARI_OTLP_TRACES_ENDPOINT`, and not `safedial`, as a collector is usually on loopback or the cluster network. Receives spans, which carry no identifier, and nothing is read back but a status. See [tracing](tracing.md) |

`TestEveryOutboundClientIsSafedialsOrListed` keeps this true. A client built
anywhere outside `safedial` fails the build, unless it is listed with the reason
its destination cannot come from configuration or a request.

## Destinations a client can choose — the SSRF surface

This is the part V13.1.1 is asking about. The honest answer is that an identity
provider is *defined* by connecting to places its applications name.

| Destination | Chosen by | Fetched when |
|---|---|---|
| `backchannel_logout_uri` | the client, at registration | a session ends |
| Webhook endpoint | an administrator, per subscription | an event fires |
| Federation entity statements | the trust chain | resolving a chain |

### What bounds it

**Registration is not open by default.** `/oauth2/register` requires either a
registration token, or an organisation that has *explicitly* opened registration.
It is open only when exactly one organisation has opened it, because "open" plus
several organisations has no answer to which one a stranger meant. It also has
its own rate limiter, deliberately not shared with the device flow.

**`internal/safedial` checks the address, not the name.** These paths refuse
private, loopback, link-local and IPv4-mapped-IPv6 addresses **at dial time**. So
a hostname that resolves to 169.254.169.254 is refused, even though the name
looked fine. Each redirect hop is dialled through the same check, so a 302 into
the private range is refused exactly like a direct attempt.

The check also covers the special-purpose ranges that Go's address predicates
treat as ordinary public unicast:

- `0.0.0.0/8`;
- the shared address space `100.64.0.0/10`, where some clouds put their metadata
  service;
- `192.0.0.0/24`;
- the benchmarking range `198.18.0.0/15`;
- `240.0.0.0/4`, with broadcast;
- the IPv6 discard prefix.

An IPv6 address that carries an IPv4 one is judged by that IPv4 address: NAT64's
well-known prefix, 6to4 and the deprecated IPv4-compatible form. So
`64:ff9b::a9fe:a9fe` is refused as the metadata service it reaches through a
translator. Teredo and NAT64's local-use prefix are refused outright.

No allowance reopens a cloud metadata endpoint: `169.254.169.254`,
`fd00:ec2::254`, the container credentials range `169.254.170.0/24` and
`100.100.100.200`. That covers each one in every form that carries it, and the two
translators whose destination cannot be read.

This holds for `SIGNARI_OUTBOUND_ALLOW_PRIVATE`, a per-client allowance and
`SIGNARI_ALLOW_PRIVATE_DELIVERY` alike. The first version knew only the first
address, so allowing `fd00::/8` or `100.64.0.0/10` reached the others.

> **This sentence was wrong when this document was written, and the correction is
> the reason the document was worth writing.** It said "every outbound connection
> from these paths", and back-channel logout delivery did not go through
> `safedial` at all — `outbox/tls.go` built a plain `http.Client`. Webhooks had
> the check at save time *and* in the dialler; logout, whose destination is chosen
> by the **client** rather than by an operator, had neither. Fixed: logout
> delivery now uses `safedial.Transport()`, with `SIGNARI_ALLOW_PRIVATE_DELIVERY`
> as an explicit opt-out for deployments whose relying parties really are
> internal.

**It is a denylist, not an allowlist.** ASVS V13.2.4 asks for an allowlist of
permitted external systems. This is stated plainly rather than argued away: at the
address level, Signari denies rather than allows.

What supplies the allowlist in practice is *registration*. Every destination above
comes from a registered client or an administrator-configured subscription. So the
reachable set is bounded by what has been enrolled, not by what an arbitrary
request asks for.

An administrator who wants a true allowlist should enforce it at the egress
firewall, and this document is what they need to write it.

## Limits and timeouts

| | |
|---|---|
| SMTP | 15 s default, connection closed after each message |
| Captcha verification | 5 s — "a provider that takes ten seconds has already cost more than it is worth" |
| guacd handshake | 10 s |
| Back-Channel Logout / webhooks | retried with capped backoff, up to 10 attempts, then **parked** so an undelivered event is visible rather than silently dropped |
| Admin token touch | 3 s, out of band |
| Span export | 10 s a batch; a batch the collector does not take is dropped, not retried |
| Transit engine | 10 s a call, a minute to make a key; a signature that fails fails the request that needed it, and is not retried |

`V13.1.2` and `V13.1.3` ask for documented connection-pool limits and per-service
resource strategies. Each node holds two database pools, one for requests and one
for background work, each with its own limit (`SIGNARI_DB_MAX_CONNS` and
`SIGNARI_DB_WORKER_MAX_CONNS`). Their defaults are in [the security
inventories](security-inventories.md#connections-and-resources-v131), and
[connection pooling](connection-pooling.md) explains how to size them.
