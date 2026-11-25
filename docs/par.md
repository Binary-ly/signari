# Pushed authorization requests

## Introduction

When Acme's wiki sends Ada to sign in, it puts its whole request in the address
her browser opens. That address can be read and changed by anyone who controls
the browser. "Pushed Authorization Requests" (PAR), defined in RFC 9126, move the
request off the browser (see the [glossary](glossary.md#par)).

With PAR, the application sends its request to Signari directly first, and proves
who it is as it does. Signari answers with a short-lived "handle", and the browser
carries only that handle.

Any application can push its requests. You can require it for one application with
`signari client set-par`, described under [Decisions](#decisions).

## How it works

The application posts its authorization request to `/oauth2/par`, authenticated,
and gets back an opaque handle, the `request_uri`. It then sends the browser to
the authorization endpoint with only its client ID and that handle:

```
POST /oauth2/par        ->  {"request_uri": "urn:ietf:params:oauth:request_uri:...",
                             "expires_in": 300}
GET  /oauth2/authorize?client_id=...&request_uri=...
```

## What it fixes

An ordinary authorization request is a URL, and a URL is **visible**. It shows up
in browser history, and in `Referer` headers to every resource the page loads. It
shows up in reverse-proxy access logs, in the address bar over someone's
shoulder, and in whatever gets pasted into a support ticket.

It is also **editable**. Nothing stops whoever controls the browser changing
`scope` or `redirect_uri` before it arrives.

PAR moves the parameters onto a "back channel", from the application's server
straight to Signari, and from an authenticated client. What the browser carries
is a handle that gives one code and expires in five minutes. It means nothing to
anyone who captures it after use.

## Verified against a running engine

These requests were sent to a running Signari, and each got the answer shown:

```
1. push, valid                    -> request_uri issued, expires_in=300
2. push with NO client auth       -> invalid_client
3. push, unregistered redirect    -> redirect_uri is not registered for this client
4. authorize with the handle      -> 200 (login page), as often as it is loaded
5. sign in, and come back         -> a code
6. the handle again after a code  -> 400 (one code)
7. a DIFFERENT client redeems it  -> 400 (bound to its pusher)
8. query tries to add scope       -> 200, and the extra scope is IGNORED
```

**Line 5 is why line 6 is after it.** A person arrives at the authorization
endpoint several times on one handle. They arrive for the sign-in page, back from
it, back from a second factor and back from the consent screen. Software that
fetches a link to see what is there arrives too.

So a handle is spent in the transaction that issues the code, and nothing before
that uses it up. It used to be spent by the first page. That looked exactly like
single use, and meant nobody who was not already signed in could finish a pushed
request.

**Line 8 is the rule that makes it worth having.** When `request_uri` is
present, the pushed parameters *replace* the query entirely. Only `client_id`
survives, because it is needed to find the handle. Merging the two would undo the
feature: whoever controls the browser could append `scope=admin` to a URL whose
other parameters are protected.

**Line 7:** the handle is bound to the client that pushed it. Otherwise one
application could redeem another's handle. It could then begin an authorization
carrying someone else's registered `redirect_uri`.

**Line 3:** the request is validated at push time, with the same rules the
authorization endpoint applies. Deferring it would let an application push
nonsense, receive a handle, and discover the problem *in a browser*. There the
error has to be rendered to a person, instead of returned to the caller that can
act on it.

## Decisions

**The handle is stored hashed.** It is a credential, since whoever holds it can
begin an authorization. This schema hashes every credential it stores.

**Single use is enforced in the statement that reads it**, so two concurrent
redemptions cannot both succeed.

**Client authentication credentials are never stored** with the pushed
parameters. They authenticate the push, and have no business surviving into the
authorization. There they would sit in a `jsonb` column, being a credential
nobody remembers is there.

**A pushed request may not itself contain `request_uri`** (§2.1). Chained handles
make the parameters that will be authorized depend on a lookup chain. That is the
indirection this endpoint removes.

**A pushed request can be signed**, with the parameters in a `request` object and
nothing beside it but the client's own authentication. See [signed authorization
requests](jar.md).

**`require_pushed_authorization`** can be set per application, with `signari client
set-par`, the client PATCH and `apply` (`require_pushed_authorization_requests`).
The application can also set it itself at dynamic registration, under that
RFC 9126 §6 name.

It is off by default, since turning it on breaks any integration that has not
moved. But without it, PAR is advisory. An application that can also send a plain
request has gained an option, not the integrity property. With it on, a plain
request from such an application is refused, and no session or code comes of it.

**A push is at most 64 KiB**, refused with `413` past it, because a pushed request
is a handful of parameters. Until October 2026 the limit was declared and applied
to nothing. So a push was read up to net/http's 10 MB form ceiling.

**Sixty pushes per address per minute for a public client.** Every push is a
stored row, and a public client authenticates nothing here. So before this, a
stranger could have Signari write rows without limit. A browser pushes one per
sign-in.

**6,000 per minute per confidential client**, counted after it authenticates and
not by address. A confidential application pushes from its own servers, one push
per sign-in, often all from one outgoing address. Counted per address, such an
application could start only sixty sign-ins a minute. That would be on the
endpoint that the FAPI (Financial-grade API) 2.0 security profile requires (see
[FAPI 2.0](fapi2.md)).

The per-client ceiling still limits what a leaked secret can make Signari store.
A failed authentication stores nothing, and is metered by the
client-authentication budgets.

A request over either limit gets `429` with `Retry-After`. A database error is
refused rather than waved through.

## Duplicate parameters are refused

RFC 6749 §3.1 says a request must not include a parameter more than once. The
tempting behaviour is to take the first and ignore the rest. That is "parameter
pollution". Whether the first or the last wins differs between servers, proxies
and libraries. So a request carrying two `redirect_uri` values can be validated
against one and acted on with the other.

This was found because a test accidentally sent two and got a success, since the
valid one happened to come first.

## One bug worth recording

Client authentication at `/oauth2/par` failed outright. The accepted audiences for
a `private_key_jwt` assertion were hardcoded to the issuer and the *token*
endpoint. So an application addressing its assertion to `/oauth2/par`, the
endpoint it was actually calling, was refused.

The endpoint being called is now accepted too. Every value in that list names
Signari and nobody else, which is what the audience check is for. Being strict
about *which* of Signari's own URLs was used buys nothing, and breaks real
applications.

---

## Three properties worth knowing

- **The `request_uri` lifetime is a fixed five minutes**, not configurable, and it
  covers the whole sign-in. A person has that long from the application's redirect
  to the code, a second factor and a consent screen included. RFC 9126 §2.2 says
  only "short-lived" and names no value, and FAPI 2.0 asks for under 600 seconds.
  A fixed default removes the trap of an administrator setting it long enough to
  matter.
- **What a page reads from the push decides nothing.** `login_hint`, `ui_locales`
  and `acr_values` travel beside the handle so the sign-in page can use them. They
  are replaced from the push on every arrival. A `prompt` is answered in the stored
  request, never by the browser, so `prompt=login` cannot be skipped by editing a
  URL.
- **Duplicate parameters are refused** (`dupeparams.go`). The repeats that RFC 8707
  and RFC 8693 legitimately permit, `resource` and `audience`, are preserved as
  lists through the push.
