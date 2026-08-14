# Logout

Signing out of Signari runs **three** mechanisms, because no one of them reaches
everything:

| mechanism | reaches | reliability |
|---|---|---|
| **back-channel** (OIDC) | server-side sessions at relying parties | retried, parked failures surfaced |
| **front-channel** (OIDC) | state the browser holds — cookies the RP's server never sees, local storage, service workers | best effort, no completion signal |
| **SAML front-channel chain** | SAML service providers | sequential, per-provider result recorded |

Each is reported separately rather than summed into a single "signed out",
because they succeed and fail independently.

## Why both OIDC channels

Back-channel logout is server-to-server: reliable, retryable, invisible to the
browser. It is the primary mechanism and has been here since the start.

What it cannot reach is state the **browser** holds. A relying party that keeps
its session in a cookie its own server never inspects, or in local storage, or
in a service worker, is still signed in from the user's point of view after a
perfect back-channel logout. The front channel loads a URL in the browser that
the relying party can act on.

Neither is sufficient alone.

## What the front channel cannot promise

It loads each relying party's logout URL in a frame. Whether the RP then clears
anything is entirely up to it, and **no answer comes back** — a cross-origin
frame gives no completion signal that can be trusted.

Third-party cookie restrictions make it weaker still: a frame from another
origin may be denied its own cookies, in which case the RP cannot identify the
session to end.

That is a real and growing limitation. The honest response is to say so, rather
than report success because the frames were rendered.

## Details that are decisions

**`iss` and `sid` are included** when the client asks for them. Without `sid` a
relying party holding several sessions for one person ends all of them or none —
and "all of them" signs the user out of other devices they never touched.

**The URL is built from the registered URI.** Nothing from the request
contributes. This URL is loaded by the user's browser, so anything
caller-supplied would be a way to make somebody's browser fetch a URL of an
attacker's choosing during their logout.

**`https` only, no fragment**, enforced by a CHECK constraint. This URL carries
the session id.

**The page cannot be framed** (`X-Frame-Options: DENY`, `frame-ancestors 'none'`).
A logout page inside somebody else's frame is a way to sign a user out without
their knowledge.

**No JavaScript.** The continuation is a `meta refresh`, because the CSP on this
page forbids script entirely — and adding `'unsafe-inline'` to allow one would
weaken the very page that renders third-party URLs.

**Frames load in parallel**, unlike the SAML chain which must be sequential.
SAML needs each provider to redirect the browser onward, so those hops are
serial by construction; here each frame is independent, so the whole thing takes
as long as the slowest one rather than the sum.

**Targets are read before termination**, because ending the session cascades
`session_clients` away — and with it the record of who to notify.

## Session Management 1.0 is deliberately not implemented

OpenID Connect Session Management defines `check_session_iframe`: the RP embeds a
hidden frame from the OP and polls it with `postMessage` to learn whether the
session changed.

It depends on the OP's cookie being readable inside a third-party frame. Modern
browsers block exactly that — Safari by default for years, Chrome's third-party
cookie work, Firefox's Total Cookie Protection. The mechanism does not fail
loudly when this happens; it reports "unchanged" forever, which is the worst
possible failure for a session monitor.

So `check_session_iframe` is **absent from discovery**, not advertised-and-broken.
Relying parties that need to detect a remote logout should use back-channel
logout, or short access token lifetimes with refresh — both of which work.

This follows the rule the rest of the discovery document follows: an endpoint
appears only once it works.
