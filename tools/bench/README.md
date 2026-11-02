# bench

A load driver for an identity provider. It measures throughput and latency
per operation and prints one JSON object per scenario. Every scenario except
`signin` and `admin-list` speaks a published protocol and finds its endpoints in
the provider's discovery document. So a comparison between two deployments is the
same command run twice with a different `-issuer`, at the same concurrency, from
the same machine.

```sh
cd tools/bench && go build .
./bench scenarios
./bench run -issuer https://id.example.com -client-id bench -client-secret "$SECRET" -cc-scope api \
  -username bench-1@bench.invalid -password "$PW" -c 8 -d 20s \
  discovery jwks client-credentials introspect signin refresh userinfo
```

| scenario | what one operation is |
|---|---|
| `discovery`, `jwks` | GET the discovery document, the key set |
| `client-credentials` | a token by the client credentials grant; `-cc-scope` names what to ask for |
| `introspect` | introspect one token (RFC 7662), issued before the window opens |
| `signin` | a person's password sign-in through Signari's login and consent forms, to a redeemed code (PKCE) |
| `refresh` | one refresh in a chain that spends each token, after one `signin` per worker |
| `userinfo` | userinfo with that person's access token |
| `ldap-bind`, `ldap-search` | a simple bind on an open connection; a subtree search for one person |
| `radius-pap` | an Access-Request with PAP and a Message-Authenticator, answered Access-Accept |
| `scim-list` | the first hundred SCIM users |
| `revoke` | an access token issued and revoked (RFC 7009), the pair, as a token revokes once |
| `par` | a pushed authorization request (RFC 9126), which nothing redeems. Signari paces these at 6,000 a minute per client, so a longer window measures the pacing and `shed` says so |
| `admin-list` | a page of the Admin API's people, with `-admin` and `-admin-token` |
| `device-start` | a device authorization started (RFC 8628), which nobody approves |
| `device-poll` | one poll of a device nobody has approved, which is what a waiting fleet does |
| `token-exchange` | a person's access token exchanged for another (RFC 8693), after one `signin` per worker |
| `ciba-start` | a person's approval asked for over the back channel (CIBA), taking turns through `-people`, as a provider limits the prompts in front of one person |
| `end-session` | a sign-out (RP-Initiated Logout). The sign-in before each is kept out of the latency, so read the latency and not `per_second` |
| `jwt-bearer` | an assertion traded for a token (RFC 7523 §2.1), with `-assertion-key`, `-assertion-issuer`, `-assertion-subject` |
| `federated` | a whole sign-in through an upstream provider, `-via` naming it, from a browser with nothing in it, to a redeemed code |
| `passkey` | a passkey sign-in from a software authenticator, begin to finish. Each worker enrols one for a seeded person of its own, past `-people`, as a passkey is a second factor. The instance needs an RP ID, which cannot be an address, so the issuer needs a name |
| `mfa` | the one request that spends a TOTP code at sign-in. The password before it is kept out of the latency, and a code is good once, so `-people` take turns, each holding `-totp-seed` |
| `authzen` | one AuthZEN access evaluation |

Each scenario runs a warm-up (`-warmup`, default 5 s), then a measured window
(`-d`, default 20 s) with `-c` workers, each with its own cookie jar and
connection. The output has the operation count, throughput, nearest-rank p50,
p95 and p99, and the maximum. It also has **`errors` and `shed` kept apart**:
a 429 is the server refusing load it was configured to refuse, and counting it
as a failure would hide whether anything is actually broken. A worker that cannot
be set up, for example because a sign-in for a refresh chain was refused, fails
the scenario instead of reporting a number from fewer workers than were asked
for.

## A directory of realistic size

```sh
./bench seed -dsn postgres://signari_engine@localhost/signari -org <uuid> \
  -template alice@example.com -users 100000
./bench seed -dsn ... -org <uuid> -remove
```

This adds `bench-1@bench.invalid` and upwards, each with the template account's
password hash, so `-username bench-N@bench.invalid` works with the template's
password. It writes the database directly as `signari_engine`: it is for a
benchmark database, and none of it is audited. It never writes or removes an
address outside `bench.invalid`, which is reserved and resolves nowhere, so
nothing is ever mailed to one.

## Something on the far side

```sh
./bench upstream -addr 127.0.0.1:18991 -tls-cert cert.pem -tls-key key.pem -people 1000
```

An OpenID provider, a SCIM server and, with `-ldap-addr`, a directory, for what the
engine does outward. The provider has discovery, a key set and signed ID tokens, and
signs in whoever comes next at once, as a person's minutes at somebody else's password
page are no part of what the engine does. The SCIM server keeps what it is sent, so a
second sync finds it there. The directory answers a bind and a paged search over
`-directory` people. `/stats` counts tokens issued and people created and replaced.

The key must be a PKCS#8 P-256 key, which also signs ID tokens, and is what
`-assertion-key` takes. The engine has to trust the certificate and be allowed to
reach the address, with `SIGNARI_CA_BUNDLE` and `SIGNARI_OUTBOUND_ALLOW_PRIVATE`:

```sh
signari idp add -org <uuid> -slug up -name Up -kind oidc -issuer https://127.0.0.1:18991 \
  -client-id-ext ext -client-secret s -trust-email-verification
./bench run -issuer https://id.example.com -insecure -client-id bench -client-secret "$SECRET" \
  -scope openid -via up federated

signari scim add -org <uuid> -slug sink -name Sink -base-url https://127.0.0.1:18991/scim/v2 -token t
time signari scim sync -slug sink -apply

signari dir add -org <uuid> -kind ldap -slug corp -name Corp -ldap-url ldaps://127.0.0.1:18992 \
  -ldap-ca cert.pem -ldap-bind-dn cn=reader,dc=load,dc=test -ldap-password x \
  -ldap-base-dn dc=load,dc=test -ldap-flavour openldap
signari dir set -org <uuid> -slug corp -dry-run=false
time signari dir sync -slug corp -apply
```

Those two have no scenario here, as each is one long run and not many short ones: time
the command. `bench totp <seed>` prints the code a seed gives now, for a script
enrolling the people of the `mfa` scenario, as `user assign-otp` asks for one.

## Making a measurement worth comparing

- **Same budget.** Give the server and its database one CPU limit between them.
  A server measured with its database outside the quota is being given free
  CPU that the other side was not.
- **Same key and hash costs.** An ES256 signature costs a small fraction of an
  RS256 one, and a password check costs whatever the hash parameters say. State
  both, or the comparison is between configurations, not implementations.
- **More than one run.** Single runs have shown p99 spreads above 70% here.
  Report the median of several and the spread.
- **Rate limits are configuration.** One source address hits per-address
  limits quickly (JWKS is limited per address, for example). Either raise them
  for the benchmark and say so, or read `shed` as the result.
- **Analyse after loading.** A table filled a moment ago has no statistics until
  autovacuum gets to it, and a planner that takes 100,000 rows for a handful makes
  a good query look like a bad one. `bench seed` does this for you. After any other
  load, `ANALYZE` first, as the table's owner: anybody else is skipped with a warning.
- **Take turns.** To compare two builds, alternate them, and run each more than
  once. One run here read a quarter of the others, for nothing in the code.
