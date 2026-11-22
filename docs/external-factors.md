# External factors

An `external_factor` stage sends the browser to a service you run and believes
the answer it signs. Use it for what no built-in factor does: a push to your own
app, a check against a card system, a device your organisation already trusts.

The service is not given a shared secret and holds nothing of Signari's. It
registers public keys, and an answer is believed because one of them signed it.

```yaml
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - one_of:
          - {stage: passkey, when: proved_by_passkey}
          - password
      - {stage: external_factor, factor: push}
      - session
    tests:
      - name: by password
        given: {}
        expect: [password, external_factor, session]
```

## Registering a service

```sh
signari external-factor add -org "$ORG" -name push \
  -url https://push.example.com/ask \
  -issuer https://push.example.com \
  -jwks push-public.jwks.json \
  -amr otp,mfa
```

| | |
|---|---|
| `url` | Where the browser goes, https, with `challenge` added to its query. |
| `issuer` | The `iss` of every answer, and the `aud` of every challenge. |
| `jwks` | The service's public keys, held by value. A private key or a shared key is refused. |
| `amr` | The most it may claim to have proved. |

Or `PUT /admin/organizations/{orgID}/external-factors/{name}`, or
`external_factors:` in a [configuration file](config-as-code.md). A key changes
when you change it here: nothing is fetched, so an answer is never believed
because of a key that arrived on its own.

`amr` may not hold `pwd`, `fed`, `krb` or `user`. Those say how somebody arrived,
which flows read to tell one route from another, so a service claiming one could
turn a password sign-in into a federated one.

A flow that names a service nobody registered is refused when it is applied, and
a service a flow names cannot be removed until that flow is replaced.

## What goes out

The browser arrives at `url` with `challenge`, a JWT this server signed, with
header `typ: factor-challenge+jwt`. Check it against this issuer's JWKS before
acting on it.

| Claim | |
|---|---|
| `iss` | This server. |
| `aud` | The service's registered `issuer`. |
| `sub` | The person. The answer must name the same one. |
| `login_hint` | Their username, or else their address, for a service that keys people on those. Absent when they have neither. |
| `nonce` | Copy this into the answer. |
| `return_to` | Where to send the browser. |
| `iat`, `exp` | Five minutes apart. |

## What comes back

Send the browser to `return_to` with `response`, a JWS the service signed, with
header `typ: factor-response+jwt`:

```json
{
  "iss": "https://push.example.com",
  "aud": "https://id.example.com",
  "sub": "the challenge's sub",
  "nonce": "the challenge's nonce",
  "amr": ["otp"],
  "iat": 1798800000,
  "exp": 1798800060
}
```

Every claim is required. `aud` is this server's issuer, a string or a list
holding it. `amr` is what was proved this time, and must hold at least one value,
all of them registered.

| Refused | Why |
|---|---|
| A symmetric algorithm, or `none` | A shared key is one this server would hold, so it could have written the answer itself. |
| Any other `typ` | An ID token the service signed with the same key is not an answer. |
| A key that is not registered | |
| Another `iss`, or an `aud` that is not this server | |
| Another `sub` | The person challenged is the person answered about. |
| An `amr` value that was not registered | The whole answer, rather than the value: dropping it would sign somebody in on a claim nobody agreed to read. |
| A nonce already spent, expired, or issued to another sign-in | Each is good once, for one person at one service. |
| Two `response` parameters | What was verified and what was recorded must describe the same request. |

The callback is a `GET`, so a redirect is all a service needs, and it has to come
back to the browser that left: the sign-in in progress is held in a cookie sent
only on a top-level navigation. A refused answer ends the sign-in, and the person
starts again. A service that wants to say no sends the browser back with no
`response`.

## What a pass means

The `amr` the service reported joins the session's, reaches the ID token, and
counts toward `acr` as any second factor does. So `amr: [otp]` after a password
is multi-factor, and an `mfa` stage after it has nothing left to ask.

The stage does not establish who somebody is. It is asked of a person something
else has already proved, which is how the challenge can name them, so a flow must
put a proving stage before it, and `{stage: external_factor}` cannot stand in for
one. Only a sign-in runs it: `on: authentication`.

A later stage does not ask again, in the same sign-in. A new sign-in does.

## If the service is down

The browser leaves and does not come back, and the person sees whatever the
service's address shows. There is no health check and no fail-open: a flow that
names a service requires it. If it should be optional, say so in the flow with
`when:`, or give the person another branch of a `one_of`.

Each sign-in records `mfa.external_factor_passed` or `mfa.external_factor_failed`
([events](events.md)). A refusal's reason goes to the log, never to the person.

## See also

- [Sign-in flows](flows.md)
- [Extensibility](extensibility.md), for hooks that decide rather than prove
