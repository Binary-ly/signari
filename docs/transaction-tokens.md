# Transaction tokens

## Introduction

Inside a company's network, one request from Ada can pass through many internal
services, each calling the next. A "transaction token", written Txn-Token, carries
who Ada is and what she asked for through that whole chain. Signari issues them,
following
[draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/),
which is **in IETF Working Group Last Call** at the Internet Engineering Task
Force.

The draft calls the service that issues them a "Transaction Token Service" (TTS).
Here, that is Signari. An application asks for a Txn-Token with a token exchange
at the ordinary token endpoint. Each internal service then passes it on in its own
header.

An application needs permission to exchange tokens, and the trust domain among its
audiences, as [Configuration](#configuration) describes.

## The problem

An access token proves who asked **at the edge**. Six services deep, the seventh
has no way to know where the request it is serving came from. It might be a
person, a batch job, or the fifth service deciding on its own to delete something.

So internal services either trust their callers completely, or each one
re-authenticates the person. The first is the flat network, in token form. The
second is both slow and wrong.

A Txn-Token carries the subject, an immutable transaction ID and the authorization
context down the whole chain. It is a short-lived signed JSON Web Token (JWT, see
the [glossary](glossary.md#jwt)). It is scoped to one "trust domain": a group of
systems that share a common set of security controls and policies.

## Using it

A Txn-Token request is an RFC 8693 token exchange, with a different
`requested_token_type`, at the ordinary token endpoint. So client authentication,
revocation checking and session liveness are the ones that already work, rather
than a second set to get wrong.

A request looks like this:

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

Signari answers with the token in `access_token`:

```json
{"token_type": "N_A",
 "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
 "access_token": "<JWT>"}
```

`token_type: "N_A"` is the draft's literal value, not a bug. A Txn-Token is not a
bearer token for an `Authorization` header, and saying "Bearer" would invite a
workload to use it as one.

Between workloads it travels in its **own header**:

```
Txn-Token: <JWT>
```

It is not `Authorization`, and the draft is explicit about that. Workloads use that
header for their own purposes. A proxy that rewrites it would silently destroy the
transaction context.

## What a token looks like

The token's header says what kind of token it is:

```json
{"typ": "txntoken+jwt", "alg": "ES256", "kid": "…"}
```

Its body carries the transaction:

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

Checked and already correct:

- `typ` (§9.1).
- Every required claim (§9.2).
- The `N_A` response shape, with no `refresh_token` (§11.4).
- Issuance rules (§11.3).
- Expiry of the presented token (§6).
- The `Txn-Token` header (§12.1).
- The replacement rules on `txn`/`sub`/`aud` immutability and scope narrowing
  (§13.15).

Signari is **stricter than the draft** in one place. The draft's §6 and §13.15
both permit a Txn-Token to outlive the token it came from, "subject to the policy
of the TTS". Signari caps it instead.

A chain that can extend its own life one hop at a time turns a five-minute token
into a permanent one, across enough services. The draft's own "SHOULD limit the
number of times a Txn-Token is replaced", in §13.15, exists because of that risk. Capping
removes the risk rather than bounding it.

### The Call Chain claim

The claim is `req_wl_chain`, an array of workload identifiers, oldest first,
including the current one. The draft's §13.15 leaves the mechanism out of scope,
and §9.2 permits additional claims.

It is set from the **first** token, rather than only from the first replacement.
So a consumer never has to special-case hop one.

Verified live across three workloads:

```
hop 1 gateway  chain=[tts-gateway]
hop 2 orders   chain=[tts-gateway, tts-orders]
hop 3 ledger   chain=[tts-gateway, tts-orders, tts-ledger]
```

The chain is bounded at 32 hops. It is built from the **previous token**, never
from the request, so a caller cannot write its own history.

It is also copied rather than appended in place. Otherwise one token replaced
twice would have the two branches scribble over each other. Catching that last one
needed a test with spare capacity in the slice. With a literal slice, `append`
always reallocates, and the aliasing bug hides.

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
presented as the other. They carry different authority, and RFC 8725's
explicit-typing rule exists for exactly this.

## Why an identity provider must issue these

A Txn-Token asserts who the subject is and what they were allowed to do. That is a
statement only the party that authenticated them can make honestly. A standalone
service has to be *told*. A token whose subject came from the request body proves
nothing, except that the caller can type.

The consequence is concrete. Verified live:

```
session live                                        ISSUED
after the user signs out, same unexpired token      refused: the session behind
                                                    the subject token has ended
```

A standalone transaction token service cannot do that. It has no idea the person
signed out. Every internal service would keep honouring a token minted from a
dead session for as long as it lived. And the internal services have no way to
check either.

## Configuration

An application needs `may_exchange`, and the trust domain in
`exchange_audiences`. `signari client set-exchange` sets both, with
`-may-exchange` and `-exchange-audiences`.

An **empty** audience list means none may be minted. An empty list is not
permission for everything, and reading it that way turns a forgotten
configuration into an open door.

Lifetime is 5 minutes by default, 15 maximum. It is short on purpose: a Txn-Token
is minted for one transaction in flight. If it outlives the transaction, it is a
bearer credential lying around a network where every service can read it.

## Re-review against draft-11, August 2026

The draft was re-checked at the Datatracker before re-reading the code: still
**revision 11**, last updated 2026-08-04. The implementation is therefore current,
rather than written against a superseded text.

That check is worth repeating. An emerging-standard implementation reviewed
against draft-N is worthless once draft-N+1 lands, and nothing in the code says
which one it was.

Every MUST NOT in the draft was checked against the implementation. Three are
worth recording:

| Requirement | Where | Result |
|---|---|---|
| TTS MUST NOT issue if the presented token has expired | §5.1 | satisfied — `VerifyAccessTokenAny` checks `exp`, and the Txn-Token's own expiry is clamped to the subject's, which is stricter than the draft's "MAY exceed" |
| Response MUST NOT include `refresh_token` | §6.1 | satisfied structurally — `Response` has three fields and no such member to populate |
| **Txn-Token MUST NOT contain the presented access token** | **§13.4** | **was violable by a caller — now refused** |

### The defect: a caller could make us violate §13.4

The draft says, in §13.4:

> When creating Txn-Tokens, the Txn-Token MUST NOT contain the access token
> presented to the external endpoint. If an access token is included in a
> Txn-Token, an attacker may extract the access token from the Txn-Token, and
> replay it to any Resource Server that can accept that access token. Txn-Token
> expiry does not protect against this attack since the access token may remain
> valid even after the [Txn-Token has expired].

`tctx` and `rctx` are `map[string]any` taken straight from the request body
(`request_details` and `request_context`) and copied verbatim into the signed
token. Nothing filtered them and nothing bounded them.

Suppose a workload puts its incoming `Authorization` header into
`request_context`: for tracing, for debugging, or because it looked like useful
context. It then gets a long-lived bearer credential embedded in a short-lived
token. That token is then forwarded to **every service in the transaction**.

The draft names exactly that consequence, including the part that makes it worse:
the access token outlives the Txn-Token carrying it.

The requirement is written on the TTS, because the TTS is what creates the token.
`CheckContext` now refuses it before anything is minted.

The check is a **substring** match rather than equality. The realistic shape is
not `{"token": "eyJ..."}` but `{"headers": {"authorization": "Bearer eyJ..."}}`.
§13.4 is about the value being extractable, not about how it was framed. Nested
structures are covered, because the comparison is against the serialised JSON.

A size bound came with it: 8 KiB across both maps combined, not per map. Caller
input inside something Signari signs deserves a limit anyway. This token also
rides an HTTP header on every hop. So its size is paid for repeatedly, by every
workload in the chain, rather than once by whoever sent it.

A "mutation" is a deliberate break in the code, made to prove a test notices it.
Each of these was caught by the test beside it:

| Mutation | Test that caught it |
|---|---|
| Drop the containment check | `TestTheContextClaimsCannotCarryTheSubjectToken` |
| Bound each map separately rather than in total | `TestTheContextClaimsAreBounded` |

The second mutation matters. A per-map limit is trivially doubled by splitting the
payload across `tctx` and `rctx`. That is the obvious way to write it, and the
wrong one.

## Harsh review against draft-11 (August 2026)

Currency first: **draft-ietf-oauth-transaction-tokens-11, 30 July 2026, In WG
Last Call**. That was verified at the Datatracker, and it is the revision Signari
implements.

Every normative requirement was re-read and checked against the code.

### What holds

| §9.2 REQUIRED claim | emitted |
|---|---|
| `iat`, `exp`, `aud`, `txn`, `sub`, `scope`, `req_wl` | all seven |

- Under §9.1, `typ` is `txntoken+jwt`, and `verifyTxnToken` requires it. An
  access token presented as a Txn-Token is refused, which is the confusion the
  distinct `typ` exists to prevent.
- Under §11.4, `token_type` is the literal `N_A`, and `issued_token_type` is the
  txn_token URN. **`refresh_token` is not merely omitted but absent from the
  response struct**, so §11.4's "MUST NOT include" cannot be violated by an edit.
- Under §13.6, requested scope ≤ the subject token's: enforced, and read from the
  *verified* token rather than the form. A caller cannot describe its own token as
  carrying anything, and thereby choose its own ceiling.
- Under §13.15, the four rules on replacement all hold:
  - `txn`, `sub` and `aud` are copied from the verified previous token, so they
    cannot be modified.
  - Scope may narrow but never widen.
  - The call chain is appended from the previous token's history, not from
    anything the caller supplies.
  - The trust domain cannot change mid-chain.

### The defect: an expiry check disabled by the missing expiry

§9.2 makes `exp` REQUIRED. Both the verifier and `Replace` guarded on its
presence:

```go
if c.Expiry > 0 && time.Now().Unix() >= c.Expiry     // verifyTxnToken
if r.Previous.Expiry > 0 && exp > r.Previous.Expiry  // Replace
```

A Txn-Token carrying no `exp` therefore **verified, never expired, and could be
replaced indefinitely**. The clamp that stops a replacement outliving its
predecessor was skipped for the same reason. So every hop received a fresh full
lifetime, and the chain never ended.

That is precisely what §13.15's "MUST NOT issue a new Txn-Token when the Txn-Token
being replaced has expired" forbids.

**Not reachable.** The token must be signed by Signari's own key and carry
`typ=txntoken+jwt`, and every path that mints one sets an expiry. The shape was
still wrong. A guard whose condition is the absence of the safety-critical field
is a guard that fails open. It is the inverse of every other check in this file.

Both now refuse a token with no expiry outright.

### `verifyTxnToken` had no test at all

It is the function on which every rule in §13.15 rests: it decides whether the
token presented for replacement is real. Nothing exercised it. Five tests now do.

The mutation pass then found that the fix in `Replace` was **itself untested**.
Restoring the original condition broke nothing, because `verifyTxnToken` rejects
such tokens first.

The check is kept, because `Replace` is exported and a future caller may not
verify. But a reason to keep a check only holds if the check is known to work. So
it got the two tests it was missing.
