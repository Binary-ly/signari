# Pushed Authorization Requests

RFC 9126. The client POSTs its authorization request to `/oauth2/par`,
authenticated, and gets back an opaque handle. The browser carries only that.

```
POST /oauth2/par        ->  {"request_uri": "urn:ietf:params:oauth:request_uri:...",
                             "expires_in": 90}
GET  /oauth2/authorize?client_id=...&request_uri=...
```

## What it fixes

An ordinary authorization request is a URL, and a URL is **visible**: browser
history, `Referer` headers to every resource the page loads, reverse-proxy
access logs, the address bar over someone's shoulder, and whatever gets pasted
into a support ticket.

It is also **editable**. Nothing stops whoever controls the browser changing
`scope` or `redirect_uri` before it arrives.

PAR moves the parameters onto a back channel from an authenticated client. What
the browser carries is a handle that is single-use, expires in 90 seconds, and
means nothing to anyone who captures it after use.

## Verified against the running server

```
1. push, valid                    -> request_uri issued, expires_in=90
2. push with NO client auth       -> invalid_client
3. push, unregistered redirect    -> redirect_uri is not registered for this client
4. authorize with the handle      -> 200 (login page)
5. REUSE the same handle          -> 400 (single use)
6. a DIFFERENT client redeems it  -> 400 (bound to its pusher)
7. query tries to add scope       -> 200, and the extra scope is IGNORED
```

**Line 7 is the rule that makes it worth having.** When `request_uri` is
present, the pushed parameters *replace* the query entirely — only `client_id`
survives, because it is needed to find the handle. Merging the two would undo
the feature: whoever controls the browser could append `scope=admin` to a URL
whose other parameters are protected.

**Line 6:** the handle is bound to the client that pushed it. Otherwise a client
could redeem another's handle and begin an authorization carrying someone else's
registered `redirect_uri`.

**Line 3:** the request is validated at push time, with the same rules the
authorization endpoint applies. Deferring it would let a client push nonsense,
receive a handle, and discover the problem *in a browser* — where the error has
to be rendered to a person instead of returned to the caller that can act on it.

## Decisions

**The handle is stored hashed.** It is a credential — whoever holds it can begin
an authorization — and this schema hashes every credential it stores.

**Single use is enforced in the statement that reads it**, so two concurrent
redemptions cannot both succeed.

**Client authentication credentials are never stored** with the pushed
parameters. They authenticate the push and have no business surviving into the
authorization, where they would sit in a `jsonb` column being a credential
nobody remembers is there.

**A pushed request may not itself contain `request_uri`** (§2.1). Chained
handles make the parameters that will be authorized depend on a lookup chain,
which is the indirection this endpoint removes.

**`require_pushed_authorization`** can be set per client. Off by default, since
turning it on breaks any integration that has not moved — but without it PAR is
advisory: a client that can also send a plain request has gained an option, not
the integrity property.

## Duplicate parameters are refused

RFC 6749 §3.1 says a request must not include a parameter more than once. The
tempting behaviour — take the first, ignore the rest — is parameter pollution:
whether the first or last wins differs between servers, proxies and libraries,
so a request carrying two `redirect_uri` values can be validated against one and
acted on with the other.

Found because a test of mine accidentally sent two and got a success, since the
valid one happened to come first.

## One bug worth recording

Client authentication at `/oauth2/par` failed outright: the accepted audiences
for a `private_key_jwt` assertion were hardcoded to the issuer and the *token*
endpoint, so a client addressing its assertion to `/oauth2/par` — the endpoint
it was actually calling — was refused. The endpoint being called is now
accepted too. Every value in that list names this server and nobody else, which
is what the audience check is for; being strict about *which* of our own URLs
was used buys nothing and breaks real clients.

---

## Two properties worth knowing

- **The `request_uri` lifetime is a fixed 90 seconds**, not configurable. RFC 9126
  §2.2 says only "short-lived" and names no value; a fixed short default is
  conformant and removes the footgun of an operator setting it long enough to
  matter.
- **Duplicate parameters are refused** (`dupeparams.go`), while the repeats
  RFC 8707 and RFC 8693 legitimately permit — `resource`, `audience` — are
  preserved as lists through the push.
