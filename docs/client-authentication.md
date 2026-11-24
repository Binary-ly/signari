# Client authentication

## Introduction

An application that runs on a server, such as Acme's wiki, collects its tokens
from Signari directly. Before Signari hands them over, the application has to
prove who it is. The protocols call such an application a "confidential client"
(see the [glossary](glossary.md#confidential-client)), and the address where it
collects tokens the "token endpoint".

This page is about how a confidential client proves who it is at the token
endpoint. Signari accepts a shared secret, or a signed "assertion" made with a key
that only the application holds. The second is safer, and this page explains why.

You register an application's public keys with `signari client set-keys`.

## Registering keys

The keys go in a file, as a JSON Web Key Set (JWKS, see the
[glossary](glossary.md#jwks)). To register them, give the application's client ID
and the file:

```sh
signari client set-keys -client-id my-service -jwks ./client-jwks.json
```

## The methods

An application proves who it is with one of these methods:

| method | credential |
|---|---|
| `client_secret_post` / `client_secret_basic` | a shared secret |
| `private_key_jwt` | a signed assertion; we hold only the public key |
| `none` | for clients that authenticate some other way |

With `private_key_jwt`, the assertion is a short JSON Web Token (JWT) that the
application signs with its private key (see the [glossary](glossary.md#jwt)).
Signari checks the signature with the public key you registered.

## Why private_key_jwt is better

A client secret is "symmetric": both sides hold it, so either side leaking it is
total. It crosses the network on every token request. It sits in environment
variables, appears in `docker inspect`, and gets pasted into support tickets.
Rotating it is a coordinated change on both sides.

With `private_key_jwt`, the private half of the key never leaves the application.
Signari's database holds only the public key. So if the database leaks, it
discloses **nothing** that authenticates as that application. That is not true of
a secret's hash, which can be attacked offline. It is certainly not true of the
plaintext secret some products still store.

Rotation is also one-sided: register both keys, switch, remove the old one. This
is tested.

## What the assertion must prove

An assertion must pass every one of these checks:

| check | what goes wrong without it |
|---|---|
| signed by a **registered** key | anybody could sign one |
| `iss` == `sub` == `client_id` | one client asserts another's identity |
| **`aud` is us** | an assertion the client made for a *different* authorization server is replayable here |
| `exp` present and ≤ 5 minutes | the assertion is a bearer credential with no expiry — a client secret again |
| `jti` unique | a captured assertion is replayable within its lifetime |
| asymmetric algorithm | HMAC is `client_secret_jwt`, verified with a key both sides hold |

In this table, `iss` says who made the assertion, `sub` who it is about, and `aud`
who it is for. `exp` is when it expires, and `jti` is its unique identifier. An
"authorization server" is the protocol's word for a service that issues tokens,
as Signari does.

The application can leave `client_id` out of the form, because the assertion's
`sub` names the client. If it is sent, it has to be the same one.

The audience check is the one most often skipped, because everything works
without it right up until it matters. An application can legitimately talk to
several authorization servers. The audience check is the only thing stopping an
assertion made for one being reused at another.

Signari accepts both its issuer and its token endpoint URL as `aud`.
Implementations differ about which to use. Rejecting one would break real
applications for no gain, since either value names Signari and nobody else.

## Verified against the running server

These six requests were sent to a running Signari, and each got the answer shown:

```
1. valid assertion, no secret anywhere -> ACCESS TOKEN ISSUED
2. REPLAY of that same assertion       -> invalid_client
3. DOWNGRADE to a client secret        -> invalid_client
4. assertion for ANOTHER server        -> invalid_client
5. assertion valid for a year          -> invalid_client
6. BOTH assertion and secret           -> refused
```

**Line 3 is the one that matters.** An application configured for
`private_key_jwt` cannot fall back to a secret. That holds even if a stale hash
is still in its row. Otherwise an attacker holding the old secret would keep working, and the
move to keys would have bought nothing. The method is read from configuration and
dispatched on. It is never inferred from whichever credential the request happens
to carry.

`client set-keys` also **removes the secret**, for the same reason. `-keep-auth`
is for keys that are not how the application authenticates, and it leaves all of
this as it was. See [signed and encrypted responses](response-encryption.md).

**Line 6:** two credentials in one request are refused, rather than resolved by
precedence. Accepting both would leave which one authenticated the caller up to
whichever check runs first.

## Two bugs found by running it

**`RequireClientAuth` demanded a secret**, and ran before the assertion was ever
looked at. So a correctly authenticated application was refused, and told
*"client authentication is required"* when it had supplied exactly that.

**A confidential client was required to have a secret** by a CHECK constraint in
the database. The constraint was written when a secret was the only kind of
credential. The rule is now "some credential", stated in the database rather than
left to application code. A confidential client with no way to authenticate would
fail at first use.

## Keys are validated at registration

`client set-keys` parses the JWKS. It refuses an empty set, refuses unusable keys,
and refuses **private key material**. The whole point is that Signari never holds
anything that can authenticate as the application. Picture a key set that turns out to
be unusable at 3am, during somebody's first token request. That is a much worse
discovery than one refused when it was registered.

There is no `jwks_uri`. Fetching a URL an administrator supplied, on the
authentication path, is a request-forgery primitive. It is also a hard dependency
on somebody else's uptime during sign-in.
