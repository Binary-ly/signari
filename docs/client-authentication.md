# Client authentication

How a confidential client proves who it is at the token endpoint.

```sh
signari client set-keys -client-id my-service -jwks ./client-jwks.json
```

| method | credential |
|---|---|
| `client_secret_post` / `client_secret_basic` | a shared secret |
| `private_key_jwt` | a signed assertion; we hold only the public key |
| `none` | for clients that authenticate some other way |

## Why private_key_jwt is better

A client secret is symmetric: both sides hold it, so either side leaking it is
total. It crosses the network on every token request, sits in environment
variables, appears in `docker inspect`, and gets pasted into support tickets.
Rotating it is a coordinated change on both sides.

With `private_key_jwt` the private half never leaves the client. Our database
holds only a public key — so it leaking discloses **nothing** that authenticates
as that client. That is not true of a secret hash, which can be attacked
offline, and certainly not of the plaintext some products still store.

Rotation is also unilateral: register both keys, switch, remove the old one.
Tested.

## What the assertion must prove

| check | what goes wrong without it |
|---|---|
| signed by a **registered** key | anybody could sign one |
| `iss` == `sub` == `client_id` | one client asserts another's identity |
| **`aud` is us** | an assertion the client made for a *different* authorization server is replayable here |
| `exp` present and ≤ 5 minutes | the assertion is a bearer credential with no expiry — a client secret again |
| `jti` unique | a captured assertion is replayable within its lifetime |
| asymmetric algorithm | HMAC is `client_secret_jwt`, verified with a key both sides hold |

The audience check is the one most often skipped, because everything works
without it right up until it matters. Clients legitimately talk to several
authorization servers, and it is the only thing stopping an assertion to one
being reused at another.

Both the issuer and the token endpoint URL are accepted as `aud` — implementations
differ about which to use, and rejecting one breaks real clients for no gain,
since either value names this server and nobody else.

## Verified against the running server

```
1. valid assertion, no secret anywhere -> ACCESS TOKEN ISSUED
2. REPLAY of that same assertion       -> invalid_client
3. DOWNGRADE to a client secret        -> invalid_client
4. assertion for ANOTHER server        -> invalid_client
5. assertion valid for a year          -> invalid_client
6. BOTH assertion and secret           -> refused
```

**Line 3 is the one that matters.** A client configured for `private_key_jwt`
cannot fall back to a secret, even if a stale hash is still in the row —
otherwise an attacker holding the old secret keeps working and the migration to
keys bought nothing. The method is read from configuration and dispatched on,
never inferred from whichever credential the request happens to carry.

`client set-keys` also **removes the secret**, for the same reason.

**Line 6:** two credentials in one request are refused rather than resolved by
precedence. Accepting both leaves which one authenticated the caller up to
whichever check runs first.

## Two bugs found by running it

**`RequireClientAuth` demanded a secret** and ran before the assertion was ever
looked at — so a correctly authenticated client was refused, and told
*"client authentication is required"* when it had supplied exactly that.

**A confidential client was required to have a secret** by a CHECK constraint
written when a secret was the only kind of credential. The rule is now "some
credential", stated in the database rather than left to application code,
because a confidential client with no way to authenticate fails at first use.

## Keys are validated at registration

`client set-keys` parses the JWKS, refuses an empty set, refuses unusable keys,
and refuses **private key material** — the whole point is that we never hold
anything that can authenticate as the client. A key set that turns out to be
unusable at 3am during somebody's first token request is a much worse discovery
than one refused when it was registered.

No `jwks_uri`. Fetching an operator-supplied URL on the authentication path is a
request-forgery primitive and a hard dependency on somebody else's uptime during
login.
