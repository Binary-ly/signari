# Opaque access tokens

## Introduction

By default, a Signari access token is a signed JSON Web Token (JWT, see the
[glossary](glossary.md#jwt)). A resource server, the API the token is for, checks
it with the published keys. It reads the token without asking anybody, and so can
whoever holds it.

You can set an application to "opaque" tokens instead. It then gets a "handle",
which says nothing to anybody. You choose the format for each application with
`signari client set-token-format`.

## Turning it on

To give an application opaque access tokens, run:

```sh
signari client set-token-format -client-id web-app -token-format opaque
```

A resource server takes the handle to the introspection endpoint. That is the
address where an API asks Signari about a token (see the
[glossary](glossary.md#introspection)). It is told what the JWT would have said:
who, for which application, with which scopes, until when, and that it is still
active.

Use this when a token should tell the application holding it nothing. Use it too
when a resource server should hear about a revocation on its next call, rather
than at the token's expiry.

It costs a call to Signari for each check, where a JWT costs none.

## What it is

The handle is a reference. The signed token it stands for is kept in
`core.opaque_access_tokens`, sealed under a key derived from the handle. The row
is found by the handle's hash. So **a read of the table gives nobody a working
token**: the handle is not there, and nothing else opens the row.

Everything that takes an access token takes a handle: userinfo, introspection,
revocation, token exchange, [forward authentication](forward-auth.md), the
credential endpoint and the Admin API.

Binding is by the same rules. A Demonstrating Proof of Possession
([DPoP](dpop.md)) proof's `ath` is the hash of the handle, since that is what the
application holds. An ID token's `at_hash` is too.

A switch applies from the next token issued. Tokens already out stay what they
are, and go on working. Handles past their expiry are refused at once, and swept
by the janitor, Signari's clean-up job.
