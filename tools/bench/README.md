# bench

A load driver for an identity provider. It measures throughput and latency
per operation and prints one JSON object per scenario. Every scenario except
`signin` speaks a published protocol and finds its endpoints in the provider's
discovery document. So a comparison between two deployments is the same command
run twice with a different `-issuer`, at the same concurrency, from the same
machine.

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
