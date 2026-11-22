# Outbound communication inventory

OWASP ASVS 5.0.0 **V13.1.1** requires this document to exist:

> "Verify that all communication needs for the application are documented. This
> must include external services which the application relies upon and cases
> where an end user might be able to provide an external location to which the
> application will then connect."

Two audiences. An operator writing egress firewall rules needs the first table.
Anyone assessing SSRF exposure needs the second, which is the half the
requirement is really about.

## Fixed destinations — vendor endpoints compiled in

These are constants in the source. Nothing a client, a user or a request can
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

Each is optional: none is contacted unless an operator configures the feature.

## Destinations the BROWSER reaches — not the server

Everything above is this server opening a connection. This section is different:
it is the **end user's browser** fetching something from a third party while
they are on one of our pages. That is a separate exposure and a worse one. A
server-to-vendor call reveals the deployment; a browser-to-vendor call reveals
the person — their IP address, and the fact that they were signing in to this
provider at that moment. An egress firewall does not touch it.

| Destination | Page | Why it is there |
|---|---|---|
| `challenges.cloudflare.com/turnstile/v0/api.js` | any page with a captcha | Turnstile's challenge |
| `hcaptcha.com/1/api.js` | as above | hCaptcha's challenge |
| `www.google.com/recaptcha/api.js` | as above | reCAPTCHA's challenge |

**These are the one thing here that cannot be self-hosted**, and the reason is
worth being precise about: the script *is* the service. A captcha works by the
provider forming a judgement about the visitor and signing it, which the server
then verifies against the same provider. Serving a copy of the script from this
origin would produce a challenge nothing could verify. It is not an asset we
have declined to vendor; there is no version of it that lives here.

What bounds it: a captcha is **off unless an operator configures one**, it is
never on the sign-in path by default, and the provider is the operator's choice
— including the choice not to have one. `docs/captcha.md` has the CSP each
provider needs, which is also the list of who is being let in.

**Nothing else on any page is off-origin.** No fonts, no analytics, no CDN
scripts, no remote images. The thirty-three engine pages use a system font
stack; the admin console serves Instrument Sans from
`admin/public/fonts/instrument-sans/` specifically so that Filament's default
font provider — which resolves to the Bunny Fonts CDN — is not used. That is a
property worth re-checking rather than assuming: render a page and look for any
`src` or `href` with a scheme in it.

It was not true of the console until November 2026, and only the sign-in page had
been looked at. Filament's default avatar provider drew the operator's avatar at
ui-avatars.com, with their initials in the address, on every screen with a user
menu. The console now draws it as a data URI, its test reads a signed-in screen as
well, and the console's content policy is `default-src 'self'` with `data:` images,
so a fourth default of the kind is refused by the browser rather than found by
reading. Every one of its 23 screens was swept in headless Chrome with no violation
and no request to another origin.

## Operator-configured destinations

An operator names these. That does not make them safe to dial wherever they
point: a stored setting can be changed by anyone holding the right admin scope,
and a name can start resolving somewhere else after it was saved. So every HTTP
destination here goes through `safedial` too, and one that really is internal is
named in `SIGNARI_OUTBOUND_ALLOW_PRIVATE` (see
[configuration](configuration.md#internal-destinations)).

| Destination | Package | Notes |
|---|---|---|
| SMTP host | `mail` | **refuses to send at all** if the server does not offer STARTTLS. Not HTTP; dialled directly |
| LDAP/AD directory | `directory/ldapsource`, `delegated/ldapbind` | TLS with `MinVersion` 1.2; `InsecureSkipVerify` deliberately absent. Not HTTP; a directory is internal by nature and is dialled directly |
| SMS gateway | `sms/gateway` | `safedial`; a loopback webhook URL is allowed because the operator wrote that address down |
| Duo API host | `duo` | `safedial` |
| SCIM target | `scim/client` | `safedial`, with `SIGNARI_SCIM_CA_BUNDLE` as its roots when set |
| SSF transmitter keys | `ssf/receive` | `safedial`; fetched when a token names a key id not yet seen, which the sender chooses |
| Upstream identity provider | `httpapi/federation` | `safedial` for the token endpoint and userinfo |
| jwt-bearer issuer keys | `httpapi/jwtbearer` | `safedial`; fetched before anyone has authenticated |
| Old provider behind delegated sign-in | `delegated` | `safedial`; the request carries a password |
| FIDO metadata mirror | `fidomds` | `safedial` |
| OpenID Federation trust anchors | `oidfed/fetch` | `safedial`, plus intermediates discovered while resolving a chain |
| A service provider's artifact resolution service | `httpapi/samlartifactrequest` | `safedial`, https only, no redirect followed. Anybody can bring an artifact, which is what makes the call, so it goes only to the address registered under the index the artifact names, for the provider whose SourceID it carries, and once per artifact. See [saml](saml.md#requests-by-artifact) |
| Outpost callbacks | `outpost` | the outpost agent calling its own engine; not a request the engine makes |
| A URL passed to `signari proxycheck` / logout test | `proxycheck`, `logouttest` | diagnostics, run by hand, not by the server |
| Vault or OpenBao transit engine | `keys` | named only by `SIGNARI_VAULT_ADDR`, and not `safedial`, as the server is the operator's own, usually on their network. Plain http is refused except to loopback, since the token goes with every request. Makes and reads signing keys and asks for signatures; nothing private comes back. See [signing keys in a module](signing-keys-in-a-module.md) |
| OpenTelemetry collector | `tracing` | named only by `SIGNARI_OTLP_TRACES_ENDPOINT`, and not `safedial`, as a collector is usually on loopback or the cluster network. Receives spans, which carry no identifier, and nothing is read back but a status. See [tracing](tracing.md) |

`TestEveryOutboundClientIsSafedialsOrListed` keeps this true. A client built
anywhere outside `safedial` fails the build unless it is listed with the reason
its destination cannot come from configuration or a request.

## Destinations a CLIENT can choose — the SSRF surface

This is the part V13.1.1 is asking about, and the honest answer is that an
identity provider is *defined* by connecting to places its relying parties name.

| Destination | Chosen by | Fetched when |
|---|---|---|
| `backchannel_logout_uri` | the client, at registration | a session ends |
| Webhook endpoint | an operator, per subscription | an event fires |
| Federation entity statements | the trust chain | resolving a chain |

### What bounds it

**Registration is not open by default.** `/oauth2/register` requires either a
registration token or an organisation that has *explicitly* opened registration —
and only when exactly one organisation has, because "open" plus several tenants
has no answer to which one a stranger meant. It also has its own rate limiter,
deliberately not shared with the device flow.

**`internal/safedial` checks the address, not the name.** These paths refuse
private, loopback, link-local and IPv4-mapped-IPv6 addresses **at dial time**, so
a hostname that resolves to 169.254.169.254 is refused even though the name
looked fine — and each redirect hop is dialled through the same check, so a 302
into the private range is refused exactly like a direct attempt.

The check also covers the special-purpose ranges that Go's address predicates
treat as ordinary public unicast: `0.0.0.0/8`, the shared address space
`100.64.0.0/10` (where some clouds put their metadata service), `192.0.0.0/24`,
the benchmarking range `198.18.0.0/15`, `240.0.0.0/4` with broadcast, and the
IPv6 discard prefix. An IPv6 address that carries an IPv4 one is judged by that
IPv4 address: NAT64's well-known prefix, 6to4 and the deprecated
IPv4-compatible form. So `64:ff9b::a9fe:a9fe` is refused as the metadata
service it reaches through a translator. Teredo and NAT64's local-use prefix
are refused outright.

No allowance reopens a cloud metadata endpoint: `169.254.169.254`,
`fd00:ec2::254`, the container credentials range `169.254.170.0/24` and
`100.100.100.200`. That covers each one in every form that carries it, and the
two translators whose destination cannot be read. This holds for
`SIGNARI_OUTBOUND_ALLOW_PRIVATE`, a per-client allowance and
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
permitted external systems. This is stated plainly rather than argued away: at
the address level we deny rather than allow. What supplies the allowlist in
practice is *registration* — every destination above comes from a registered
client or an operator-configured subscription, so the reachable set is bounded by
what has been enrolled rather than by what an arbitrary request asks for. An
operator wanting a true allowlist should enforce it at the egress firewall, and
this document is what they need to write it.

## Limits and timeouts

| | |
|---|---|
| SMTP | 15 s default, connection closed after each message |
| Captcha verification | 5 s — "a provider that takes ten seconds has already cost more than it is worth" |
| guacd handshake | 10 s |
| Back-channel logout / webhooks | retried with capped backoff, up to 10 attempts, then **parked** so an undelivered event is visible rather than silently dropped |
| Admin token touch | 3 s, out of band |
| Span export | 10 s a batch; a batch the collector does not take is dropped, not retried |
| Transit engine | 10 s a call, a minute to make a key; a signature that fails fails the request that needed it, and is not retried |

`V13.1.2` and `V13.1.3` ask for documented connection-pool limits and per-service
resource strategies. The database pool is `pgxpool`'s default sizing, which is not
documented per service here — that is a real gap and is left stated rather than
implied.
