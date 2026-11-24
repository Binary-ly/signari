# Logout

## Introduction

When Ada signs out, she expects every Acme application she used to forget her as
well. That is harder than it sounds. Some applications keep their session on
their own server, and some keep it in the browser. Applications that speak
[SAML](saml.md) (Security Assertion Markup Language) are told in another way
again.

Signari therefore runs several mechanisms when somebody signs out, because no one
of them reaches everything. It reports on each one separately.

You register where an application's sign-out leads with
`signari client set-logout`. To send people on to sign out of the identity
provider they came through as well, use `signari idp logout`.

## What a sign-out reaches

Applications that speak OpenID Connect (OIDC) are told on two channels (see the
[glossary](glossary.md#oidc)). A message on the "back channel" goes from
Signari's server straight to the application's server. A message on the "front
channel" travels through the person's browser.

Signing out of Signari runs each of these mechanisms, because no one of them
reaches everything:

| mechanism | reaches | reliability |
|---|---|---|
| **back-channel** (OIDC) | server-side sessions at relying parties | retried, parked failures surfaced |
| **front-channel** (OIDC) | state the browser holds — cookies the RP's server never sees, local storage, service workers | best effort, no completion signal |
| **SAML front-channel chain** | SAML service providers | sequential, per-provider result recorded |
| **SAML SOAP** | SAML service providers with a SOAP address, however the session ended | retried, parked failures surfaced |

In this table, a "relying party" (RP) is OpenID Connect's word for an
application, and SAML calls an application a "service provider".

Each mechanism is reported separately rather than summed into a single "signed
out", because they succeed and fail independently.

**A sign-out ends every account the browser holds**, not only the one in use (see
[several accounts](accounts.md)). The applications of each account are told by
back channel. The front channel and the SAML chain run for the account that was
in use.

**Signing out does not end a grant of `offline_access`.** A "grant" is the
permission a person gave an application. A grant of `offline_access` is access for
an application while the person is *not* signed in. So it outlives the session it
was given in, for the organisation's offline lifetime: thirty days unless changed
with `signari instance session-lifetime -offline`.

The grant ends when the person removes the application at `/account/connected`.
It also ends when every session they have is ended, which happens when:

- a password is changed or reset;
- a factor is reset;
- the person is deactivated;
- the person chooses "sign out everywhere".

An application that wants a sign-out to end its own access revokes its refresh
token, as RFC 7009 describes. Until October 2026 every grant ended with its
session, so `offline_access` lasted only while the person stayed signed in.

## Registering a client's sign-out

To register where the wiki's sign-out may send the browser, and the wiki's
front-channel address, run:

```sh
signari client set-logout -client-id wiki \
  -post-logout-redirects https://wiki.example.com/signed-out \
  -frontchannel-uri https://wiki.example.com/oidc/frontchannel-logout
```

`-post-logout-redirects` lists where the browser may go after a sign-out that the
application started. OpenID Connect calls that "RP-initiated logout". A
`post_logout_redirect_uri` is honoured only when this application registered it.
The same rules as for a redirect URI apply: https, or a loopback address for
development, and no wildcard.

`-frontchannel-uri` is the front-channel URI described below. `-frontchannel-sid`
(on by default) adds `iss`, the issuer, and `sid`, the session's identifier, to
it.

You can set the same three settings in other places too, as
`post_logout_redirect_uris`, `frontchannel_logout_uri` and
`frontchannel_logout_session_required`:

- the client PATCH in the Admin API;
- the client fields of the same names in `signari apply`;
- [dynamic registration](dynamic-registration.md) metadata.

Until October 2026 nothing could register either one. So every
`post_logout_redirect_uri` was refused, and the front channel reached no
application.

A `post_logout_redirect_uri` that is not registered stops the return to the
application, and nothing else. The person is signed out, every channel is told,
and the browser stays at Signari. The engine logs the application that asked.

Until November 2026 Signari answered 400 instead. By then the session at Signari
had ended. But the front channel, the SAML applications and the provider the person
came through had not yet been told. A mistyped address therefore left the
person signed in to all of those.

## Signing out at the provider too

A person may sign in through another identity provider, such as their company's.
After signing out of Signari, they are still signed in at that provider. Their
next sign-in then goes straight through without asking them anything. On a shared
machine, that is the wrong answer.

An administrator can send them on to the provider to sign out there as well:

```sh
signari idp logout -slug corp -url https://idp.corp.example/logout
```

The address is the provider's `end_session_endpoint`, its sign-out address. If you
need to find it, `signari idp check` reads it from the provider's discovery
document. At the provider, register `https://<this issuer>/logout/complete` as a
post-logout redirect.

After a sign-out, the browser goes to the provider with `client_id`,
`post_logout_redirect_uri` and a `state`. It comes back to `/logout/complete`.
From there it carries on to the application's own `post_logout_redirect_uri`, or
Signari reports the sign-out if there was none.

This is the last stop, after the back-channel notices, the front channel and any
SAML chain. It comes last because nothing at Signari can resume once the browser
has left. Sessions at Signari end first, so a provider that fails or refuses
leaves the person signed out at Signari, and only at Signari.

It happens only for a session that came through a provider, and only in the
browser it came through. Signari does not keep the provider's `id_token`. So no
`id_token_hint` goes with the request, and the provider may ask the person to
confirm.

For a SAML provider, the address is its SingleLogoutService, and the sign-out
needs a signing key. See [single logout with an
upstream](saml-source.md#single-logout-with-an-upstream).

## Why both OIDC channels

OpenID Connect's back channel goes from server to server. It is reliable, it can
be retried, and the browser never sees it. It is the primary mechanism, and
Signari has had it since the start. Its standard is called "Back-Channel Logout".

What the back channel cannot reach is state the **browser** holds. An application
might keep its session in a cookie its own server never inspects, in local
storage, or in a service worker. After a perfect back-channel sign-out, that
application is still signed in from the person's point of view. The front
channel loads a URL in the browser that the application can act on.

Neither is sufficient alone.

## What the front channel cannot promise

The front channel loads each application's front-channel URI in a frame. Whether
the application then clears anything is entirely up to it, and **no answer comes
back**. A frame from another origin gives no completion signal that can be
trusted.

Third-party cookie restrictions make it weaker still. A frame from another origin
may be denied its own cookies, and then the application cannot identify the
session to end.

That is a real and growing limitation. The honest response is to say so, rather
than report success because the frames were rendered.

## Details that are decisions

**`iss` and `sid` are included** when the application asks for them. Without
`sid`, an application holding several sessions for one person ends all of them or
none. And "all of them" signs the person out of other devices they never touched.

**The URL is built from the registered URI.** Nothing from the request
contributes. This URL is loaded by the person's browser. So anything the caller
supplied would be a way to make somebody's browser fetch a URL of an attacker's
choosing during their sign-out.

**`https` only, no fragment**, enforced by a CHECK constraint in the database.
This URL carries the session ID.

**The page cannot be framed**
(`X-Frame-Options: DENY`, `frame-ancestors 'none'`). A sign-out page inside somebody else's frame is a way to sign a person
out without their knowledge.

**No JavaScript.** The page moves on with a `meta refresh`, because its Content
Security Policy (CSP) forbids script entirely. Adding `'unsafe-inline'` to allow
one would weaken the very page that renders third-party URLs.

**Frames load in parallel**, unlike the SAML chain, which must be sequential.
SAML needs each application in the chain to redirect the browser onward, so those hops are
serial by construction. Here each frame is independent. So the whole sign-out
takes as long as the slowest frame, rather than the sum of them all.

**Targets are read before termination.** Ending the session deletes its
`session_clients` rows by cascade, and with them the record of who to notify.

## Session Management 1.0 is deliberately not implemented

OpenID Connect Session Management defines `check_session_iframe`. With it, the
application embeds a hidden frame from the identity provider, and polls it with
`postMessage` to learn whether the session changed.

It depends on the identity provider's cookie being readable inside a third-party
frame. Modern browsers block exactly that: Safari by default for years, Chrome
through its third-party cookie work, and Firefox through Total Cookie Protection.

The mechanism does not fail loudly when this happens. It reports "unchanged"
forever, which is the worst possible failure for a session monitor.

So `check_session_iframe` is **absent from discovery**, not advertised and
broken. Applications that need to detect a sign-out elsewhere should use
the back channel, or short access token lifetimes with refresh. Both of those
work.

This follows the rule the rest of the discovery document follows: an endpoint
appears only once it works.
