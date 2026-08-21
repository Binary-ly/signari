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
| `admin.googleapis.com` | `provision/google` | directory sync | a sync runs |
| `graph.microsoft.com`, `login.microsoftonline.com` | `provision/entra` | directory sync | a sync runs |

Each is optional: none is contacted unless an operator configures the feature.

## Operator-configured destinations

An operator names these. They are trusted to the same degree as the binary's own
configuration.

| Destination | Package | Notes |
|---|---|---|
| SMTP host | `mail` | **refuses to send at all** if the server does not offer STARTTLS |
| LDAP/AD directory | `directory/ldapsource` | TLS with `MinVersion` 1.2; `InsecureSkipVerify` deliberately absent |
| SMS gateway | `sms/gateway` | |
| SCIM target | `scim/client` | outbound provisioning |
| SSF transmitter | `ssf/receive` | Shared Signals stream |
| OpenID Federation trust anchors | `oidfed/fetch` | plus intermediates discovered while resolving a chain |
| Outpost callbacks | `outpost` | |
| A URL passed to `signari proxycheck` / logout test | `proxycheck`, `logouttest` | diagnostics, run by hand, not by the server |

## Destinations a CLIENT can choose — the SSRF surface

This is the part V13.1.1 is asking about, and the honest answer is that an
identity provider is *defined* by connecting to places its relying parties name.

| Destination | Chosen by | Fetched when |
|---|---|---|
| `backchannel_logout_uri` | the client, at registration | a session ends |
| Webhook endpoint | an operator, per subscription | an event fires |
| `jwks_uri` | the client, at registration | verifying a signed request object or client assertion |
| `request_uri` | the client, per request | a request object is passed by reference |
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

`V13.1.2` and `V13.1.3` ask for documented connection-pool limits and per-service
resource strategies. The database pool is `pgxpool`'s default sizing, which is not
documented per service here — that is a real gap and is left stated rather than
implied.
