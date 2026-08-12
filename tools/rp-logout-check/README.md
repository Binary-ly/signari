# Back-channel logout conformance check

**Does your application actually end a user's session when they sign out?**

Almost every OIDC provider queues a back-channel logout notice. Whether the
relying party does anything useful with it is between the RP and its own session
store, and it is almost never checked. The usual outcome is that logout "works"
in the sense that the IdP sent something and got a 200 back, while the user stays
signed in to the application until the session expires on its own.

This tool does not look at the webhook. It signs in through your application,
signs out **at the identity provider**, and then asks your application whether it
still serves the protected page. That is the only question that matters, and it
cannot be satisfied by a 200 from a handler that does nothing.

```
node check.mjs \
  --rp-login     https://app.example.com/login      # starts sign-in
  --rp-protected https://app.example.com/account    # requires a session
  --idp          https://id.example.com
  --username alice@example.com --password '…'
```

Exit code 0 if your application is conformant, 1 if it is not.

## Why the probe works the way it does

Two designs that look obvious are wrong, and both give a **false pass** — worse
than shipping no tool at all:

1. **Do not navigate to the protected page and see where you land.** While the
   IdP session is alive, an unauthenticated visit silently round-trips through
   the IdP and comes back authenticated. That measures the IdP's session, not
   the application's, and passes everything.

2. **Do not follow redirects.** The probe stands on a public page of your own
   application and asks about the protected URL with `redirect: 'manual'`. A
   `200` means your application still holds a session; a redirect means it does
   not. No round trip, nothing to be fooled by.

## If it fails

The reason is nearly always the same, and it is not that back-channel logout is
hard. Look at `demo-rp.mjs` — the handler is about twenty lines. What most
client libraries never build is the index:

```js
sessionsBySID.set(claims.sid, ourSessionId);   // at login
...
sessions.delete(sessionsBySID.get(claims.sid)); // on logout token
```

Without a way to find your session from the IdP's `sid`, a logout token arrives
and there is nothing to do with it.

A real handler must also verify the token's signature, issuer and audience,
require the back-channel logout member in `events`, reject a token carrying a
`nonce`, and reject replays by `jti`. `demo-rp.mjs` skips those deliberately: it
exists to demonstrate the session-ending half, which is the half that is missing.

## Status

The checker and the demo RP are complete and the probe logic is correct. The
browser driver currently fails to carry the session through `form.submit()`
against a `__Host-` cookie over plaintext localhost, while the identical flow
succeeds via `fetch` and via curl — so this is a harness bug, not a product one,
and it is the next thing to fix here.
