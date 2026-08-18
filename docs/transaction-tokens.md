# Transaction Tokens

[draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/),
**in IETF Working Group Last Call**. Signari issues them.


## How "nobody else has this" was checked


## The problem

An access token proves who asked **at the edge**. Six services deep, the seventh
has no way to know whether the request it is serving came from a person, from a
batch job, or from the fifth service deciding on its own to delete something. So
internal services either trust their callers completely — the flat network, in
token form — or each re-authenticates the user, which is both slow and wrong.

A Txn-Token carries the subject, an immutable transaction id, and the
authorization context down the whole chain in a short-lived signed JWT scoped to
one trust domain.

## Using it

A Txn-Token request is an RFC 8693 token exchange with a different
`requested_token_type`, at the ordinary token endpoint — so client
authentication, revocation checking and session liveness are the ones that
already work rather than a second set to get wrong.

```http
POST /oauth2/token
Authorization: Basic <client credentials>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:txn_token
&audience=trust-domain.example
&scope=openid profile
&subject_token=<access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&request_context={"req_ip":"203.0.113.9","authn":"pwd"}
&request_details={"action":"BUY","ticker":"MSFT"}
```

```json
{"token_type": "N_A",
 "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
 "access_token": "<JWT>"}
```

`token_type: "N_A"` is the draft's literal value, not a bug. A Txn-Token is not
a bearer token for an `Authorization` header, and saying "Bearer" would invite a
workload to use it as one.

Between workloads it travels in its **own header**:

```
Txn-Token: <JWT>
```

Not `Authorization` — the draft is explicit, because workloads use that header
for their own purposes and a proxy that rewrites it would silently destroy the
transaction context.

## What a token looks like

```json
{"typ": "txntoken+jwt", "alg": "ES256", "kid": "…"}
```
```json
{"iss": "https://id.example",
 "aud": "trust-domain.example",
 "txn": "jr-WM28kjwYD7Nilq3FQB0V_Q8tpe8QfmERpyGPFBic",
 "sub": "551049cd-…",
 "req_wl": "tts-gateway",
 "scope": "openid profile",
 "tctx": {"action": "BUY", "ticker": "MSFT"},
 "rctx": {"req_ip": "203.0.113.9", "authn": "pwd"}}
```

## Conformance review against draft-11, August 2026

The first implementation was written from a summary of the draft. Reading the
**actual text of draft-11** found two defects, one of them a MUST violation:

| Finding | Section | Status |
|---|---|---|
| **The Call Chain was destroyed at the first replacement.** `req_wl` is singular and was overwritten each hop, so the history of which workloads touched a transaction — the audit property this format exists for — was lost. §13.15 says a TTS **MUST maintain** it | §13.15 | **fixed** |
| **`subject_token_type` was defaulted, not enumerated.** Any unrecognised value fell through to the access-token path, including `refresh_token`, which §11.2 excludes outright and §13.3 explains the reason for. It was refused only because a refresh token happens not to parse as an access-token JWT — an exclusion that holds by accident stops holding when the accident changes | §11.2, §13.3 | **fixed** |

Checked and already correct: `typ` (§9.1), every required claim (§9.2), the
`N_A` response shape with no `refresh_token` (§11.4), issuance rules (§11.3),
expiry of the presented token (§6), the `Txn-Token` header (§12.1), and the
replacement rules on `txn`/`sub`/`aud` immutability and scope narrowing (§13.15).

Where we are **stricter than the draft**: §6 and §13.15 both permit a Txn-Token
to outlive the token it came from, "subject to the policy of the TTS". We cap it
instead. A chain that can extend its own life one hop at a time turns a
five-minute token into a permanent one across enough services, and §13.15's own
"SHOULD limit the number of times a Txn-Token is replaced" exists because of
that risk. Capping removes the risk rather than bounding it.

### The Call Chain claim

`req_wl_chain`, an array of workload identifiers, oldest first, including the
current one. §13.15 leaves the mechanism out of scope; §9.2 permits additional
claims. Set from the **first** token rather than only from the first
replacement, so a consumer never has to special-case hop one.

Verified live across three workloads:

```
hop 1 gateway  chain=[tts-gateway]
hop 2 orders   chain=[tts-gateway, tts-orders]
hop 3 ledger   chain=[tts-gateway, tts-orders, tts-ledger]
```

Bounded at 32 hops. It is built from the **previous token**, never from the
request, so a caller cannot write its own history — and it is copied rather than
appended in place, because one token replaced twice would otherwise have the two
branches scribble over each other. That last one needed a test with spare
capacity in the slice to catch: with a literal slice, `append` always
reallocates and the aliasing bug hides.

## The rules that make a chain worth anything

Verified against a running engine, two hops, gateway → orders:

| | |
|---|---|
| `txn` never changes | It ties every hop to one transaction. A hop that could mint a new one severs the trail exactly where an investigation would follow it |
| `sub` and `aud` never change | A replacement that could change the subject is a privilege escalation with a spec reference |
| `tctx` never changes | What is being done does not change because the request moved one service to the right |
| `req_wl` **does** change | Each hop says who it is — taken from **client authentication**, never the request body. A workload that could name itself can name somebody else |
| `rctx` **does** change | The environment legitimately differs per hop |
| Scope only narrows | A service asking for more authority than it was given is the attack this format exists to stop |
| A replacement never outlives its predecessor | Otherwise a chain extends its own life one hop at a time and a five-minute token becomes permanent across enough services |

Eight attacks, all refused against the running engine:

```
hop 2 widens scope back to profile              invalid_scope
hop 2 invents a scope never granted             invalid_scope
replacement into a different trust domain       invalid_target
a trust domain the client may not mint for      invalid_target
a txn-token presented as an access token        invalid_grant
an access token presented as a txn-token        invalid_grant
initial request asking beyond the access token  invalid_scope
a garbage subject token                         invalid_grant
```

The two type-confusion refusals are what the distinct `typ` buys. A resource
server that accepted `at+jwt` and `txntoken+jwt` interchangeably would let one be
presented as the other, and they carry different authority — RFC 8725's
explicit-typing rule exists for exactly this.

## Why an identity provider must issue these

A Txn-Token asserts who the subject is and what they were allowed to do. That is
a statement only the party that authenticated them can make honestly. A
standalone service has to be *told*, and a token whose subject came from the
request body proves nothing except that the caller can type.

The consequence is concrete. Verified live:

```
session live                                        ISSUED
after the user signs out, same unexpired token      refused: the session behind
                                                    the subject token has ended
```

A standalone transaction token service cannot do that. It has no idea the user
signed out. Every internal service would keep honouring a token minted from a
dead session for as long as it lived — and the internal services have no way to
check either.

## Configuration

A client needs `may_exchange` and the trust domain in `exchange_audiences`. An
**empty** audience list means none may be minted: an empty list is not permission
for everything, and reading it that way turns a forgotten configuration into an
open door.

Lifetime is 5 minutes by default, 15 maximum. Short on purpose — a Txn-Token is
minted for one transaction in flight, and if it outlives the transaction it is a
bearer credential lying around a network where every service can read it.
