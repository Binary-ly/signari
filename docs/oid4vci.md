# OID4VCI: the authorization server's half

OpenID for Verifiable Credential Issuance 1.0, **Final, 16 September 2025**.

## Which half, and why that is the whole job

OID4VCI separates two roles:

- The **Credential Issuer** holds the credential endpoint and knows how to mint
  an SD-JWT VC or an ISO mdoc.
- The **Authorization Server** issues the access token that credential endpoint
  will accept.

Signari is the second. Its entire contribution to OID4VCI is the **Pre-Authorized
Code grant** and the **Credential Offer** that carries it.

Nothing here mints a credential, and nothing advertises that it can. An
implementation that published a `credential_endpoint` it could not serve would be
the same mistake as advertising a federation fetch endpoint that 404s — and this
repository's rule is that an endpoint enters a metadata document only once it
works.

## Why this grant needs more care than it looks

§6.1: *"For the Pre-Authorized Code Grant Type, authentication of the Client is
OPTIONAL."*

So the pre-authorized code **is** the credential — whoever presents it receives a
token. Two things carry the weight a client secret normally would:

1. The code *"MUST be short lived and single use"* (§3.5).
2. The optional Transaction Code, whose purpose §3.5 states exactly: *"to bind
   the Pre-Authorized Code to a certain transaction to prevent replay of this
   code by an attacker that, for example, scanned the QR code while standing
   behind the legitimate End-User."*

That last sentence is the threat model, and it is unusually concrete for a
specification: a pre-authorized code is a QR code on a screen, and the attacker
is a person with a phone standing behind the holder. The transaction code travels
by a different channel so that photographing the screen is not enough.

## The distinction the specification hinges on

§6.1, on `tx_code` in a token request:

> This value MUST be present if a `tx_code` object was present in the Credential
> Offer **(including if the object was empty)**.

An empty `"tx_code": {}` in an offer — no length, no input mode, no description —
still demands a value at the token endpoint. So **"no transaction code" and "a
transaction code with nothing declared about it" are different states**, and the
obvious implementation collapses them.

`TxCode` is therefore a pointer, and `StoredCode` carries an explicit
`RequiresTxCode` rather than deriving it from whether some stored value is
non-empty. Deriving it is the mutation that turns a required check into an
optional one, and it passes every test that does not specifically look for it.

The converse is enforced too: a transaction code arriving for an offer that never
asked for one is refused. A wallet sending one means it and the issuer disagree
about what this offer is, and proceeding accepts the wallet's version.

## Guessing is bounded per code, not per address

A transaction code is a handful of digits — §3.5's `length` exists so a wallet
can size an input box — so unbounded guessing removes the protection entirely.

The limit is **per pre-authorized code**, and the contrast with the device flow is
the interesting part. A device flow user code is drawn from one space shared by
every device, so an attacker guessing there is attacking the *space*, and the
limit belongs on the guesser — which is why that one is per-address (and why
making it global was a denial of service, fixed earlier in this review).

A transaction code belongs to one offer. An attacker is attacking *that offer*, so
a per-address limit would let them change address while a per-code limit ends the
offer. Five attempts, then the offer is spent.

| Mutation | Test that caught it |
|---|---|
| Derive "requires tx_code" from the value rather than the flag | `TestAnEmptyTxCodeObjectStillRequiresAValue` |
| Accept a transaction code that was never asked for | `TestATransactionCodeArrivingUnaskedIsRefused` |
| Allow unlimited transaction code guesses | `TestGuessingTheTransactionCodeEndsTheOffer` |
| Let a redeemed code be used again | `TestAPreAuthorizedCodeIsSingleUseAndShortLived` |

## Storage

`core.preauthorized_codes` (migrations 0077 and 0078). The code is stored **hashed**, for
the same reason authorization codes are: read access to the table must not be
read access to live credentials, and this code is a bearer credential by design.
The transaction code is hashed too.

`tx_code_input_mode`, `tx_code_length` and `tx_code_description` are stored so the
offer can be reconstructed, and the column being NULL is what records "this offer
had no `tx_code` object" as distinct from "it had an empty one".

## Wiring: who the token is for

§6.1 again, and this is the sentence that decides the design:

> For the Pre-Authorized Code Grant Type, authentication of the Client is
> OPTIONAL... and, as a consequence, the `client_id` parameter is **only needed
> when a form of Client Authentication that relies on this parameter is used**.

So a conformant wallet redeems with `grant_type` and `pre-authorized_code` and
nothing else. Our token endpoint resolved a client before it dispatched on the
grant type, which would have refused every such request as `invalid_client` —
refusing the ordinary case while appearing to support the grant.

There is still a client, because a token needs an audience, scopes and a
lifetime. It is chosen when the **offer** is minted, by the operator who knows
which credential issuer the offer is for, and read back from the code at
redemption (`client_id` on `core.preauthorized_codes`, migration 0078).

That is also the stronger position. If the wallet named the client, the wallet
would be choosing which client's scopes its own token carries. A wallet that
*does* send `client_id` must send the one the offer was issued to — the parameter
is unnecessary, not free.

## Minting an offer

```sh
signari credential offer \
  -org <uuid> \
  -email holder@example.com \
  -client-id wallet \
  -credential-configuration UniversityDegree_JWT \
  -credential-issuer https://credentials.example.com \
  -tx-code
```

Prints the offer JSON, the `openid-credential-offer://` deep link from §G.7.1,
and — separately, with the reason attached — the transaction code.

The separation is not presentation. §3.5 requires the transaction code to travel
by a different channel than the offer, because the whole mechanism assumes the
offer may have been photographed. Printing both into one message that somebody
copies to the holder defeats it entirely, so the output says so.

`-offer-expires` defaults to five minutes and is capped at an hour: §3.5 says the
code MUST be short lived, and it is redeemed within seconds of being scanned.

## Registering the grant

A client may only use grants it is registered for — RFC 6749 §5.2's
`unauthorized_client` is "The authenticated client is not authorized to use this
authorization grant type":

```sh
signari client set-grants -client-id wallet \
  -grant-types urn:ietf:params:oauth:grant-type:pre-authorized_code
```

Checked when the offer is **minted**, not only when it is redeemed. The person
who finds out at redemption is the holder, standing wherever they scanned the QR
code, with nothing they can do about it.

Reviewing this turned up that the **device grant was gated nowhere** — any
registered client could run a device flow whatever it was registered for, and the
default value of `grant_types` does not include it. Both endpoints now check, and
the check for every grant the token endpoint dispatches lives in one place rather
than being repeated per handler, which is how the device one got missed. See
`device-flow.md`.

## Order of operations at redemption

The sequence is **read, check the transaction code, then claim** — not the
authorization code path's claim-as-you-read.

A wrong transaction code charges an attempt and does **not** spend the offer. If
it did, one wrong guess would destroy the holder's credential, which turns a
shoulder-surfing defence into a denial of service anybody who photographed the QR
code can perform. Five wrong guesses end the offer; the sixth attempt fails even
with the right code.

Every refusal is `invalid_grant`, whatever the reason — unknown code, spent code,
expired code, missing transaction code, too many guesses. The `description` says
which, because a wallet has to render something to a person who is standing there
wondering why their credential did not arrive; the error `code` does not vary, so
nothing parsing the response programmatically can tell a code that never existed
from one already spent.

## The Credential Issuer half

Everything above is the authorization server. This is the other role: Signari now
**mints the credential**.

```
POST /oid4vci/nonce                          §7  — unauthenticated
POST /oid4vci/credential                     §8  — bearer or DPoP
GET  /.well-known/openid-credential-issuer   §12.2
```

Format: **SD-JWT VC**, `draft-ietf-oauth-sd-jwt-vc-18` (10 August 2026).

### Why SD-JWT rather than a plain signed credential

An ordinary credential is all-or-nothing. To prove you are over 18, you hand over
a document carrying your name, address and date of birth — the verifier learns
everything, because the signature covers everything and removing a field breaks
it.

SD-JWT signs **digests** of individual claims. The holder gets the signed JWT
plus one *disclosure* per claim, and presents only the ones they choose. The
signature still verifies, because it was never over the values.

An issued credential looks like:

```
<jwt>~<disclosure>~<disclosure>~<disclosure>~
```

### The detail that decides whether any verifier accepts it

§4.2.3 of the SD-JWT specification, emphatically:

> The digest MUST be taken over the US-ASCII bytes of the **base64url-encoded**
> value that is the Disclosure… The input to the hash function MUST be the
> base64url-encoded Disclosure, **not** the bytes encoded by the base64url string.

Hashing the decoded JSON is the obvious reading, produces a plausible digest, and
yields a credential nothing on earth will accept. The specification publishes a
test vector precisely because of this, and
`TestTheSpecificationsOwnDigestVector` uses it:

| | |
|---|---|
| Disclosure | `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0` |
| Digest | `X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0` |

Two related details, both found by mutation rather than by reading:

- **`Disclosure.Digest()` and `DigestOf()` were two implementations of that one
  rule.** The specification's vector exercised the second; issuance called the
  first. Breaking the issuance path exactly as §4.2.3 warns broke no test. They
  are now one function.
- **`typ` is `dc+sd-jwt`.** draft-18 renamed it from `vc+sd-jwt` "to avoid
  conflict with the vc media type name". The test asserting it originally
  compared the header against our own constant — a tautology that passed when the
  constant was changed to the deprecated value. It compares a literal now.

### Key binding, which is the point of the proof

§8.2 requires a key proof, and the credential carries `cnf` naming the key it was
bound to. Without that, a credential is a bearer token: whoever copied it could
present it.

Appendix F.1's rules, each enforced and each tested:

| Rule | Why refusing matters |
|---|---|
| `typ` is `openid4vci-proof+jwt` | an ID token is also signed JSON with `aud` and `iat` |
| `alg` is asymmetric, never `none` | a MAC would make the verification key the forgery key |
| exactly one of `kid`/`jwk`/`x5c` | two key sources means the key *verified* and the key *bound* can differ |
| signed by the key it carries | otherwise anybody binds a credential to somebody else's public key |
| `aud` is the Credential Issuer | a proof for another issuer would be replayable here |
| `iat` present and recent | an undated proof never ages out |
| carries this issuer's `c_nonce` | a captured proof would otherwise be replayable forever |

And one rule worth its own line. §F.1 on `iss`:

> This claim MUST be omitted if the access token authorizing the issuance call
> was obtained from a Pre-Authorized Code Flow through **anonymous** access to
> the token endpoint.

That is exactly our flow — §6.1 lets the wallet send no `client_id`, and we
honour it. So `ProofContext` carries `Anonymous` separately from an empty
`ClientID`: *"we do not know the client"* and *"there deliberately was no
client"* are different states, and only the second forbids the claim.

### `c_nonce` is single use

§7 requires a Nonce Endpoint when proofs must carry a nonce, and §8.2 has the
nonce establish freshness. A nonce that can be presented twice establishes it
once, so it is spent in the statement that reads it.

The endpoint is **unauthenticated**, which §7.1 states outright and which is
worth not second-guessing: a wallet needs the nonce *before* it can build the
proof that the token-bearing request depends on.

The nonce is also **not organisation-scoped**. Migration 0081 scoped it and 0082
took that back, because it forced an unauthenticated endpoint to guess a tenant.
A `c_nonce` proves freshness and identifies nobody; which organisation a
credential is issued for comes from the access token's subject, at an endpoint
where there genuinely is one.

### Defining what this issuer mints

```sh
signari credential define -org <uuid> \
  -credential-configuration IdentityCredential \
  -vct https://example.com/identity \
  -always sub \
  -selective email,preferred_username,email_verified \
  -valid-for 720h
```

The `always`/`selective` split is the whole feature, so it is two flags rather
than one list with a flag per claim: a claim under `always` is visible to **every
verifier the holder ever presents to**, and putting the more dangerous option
behind the easier typo would be a poor trade.

Claim names come from a fixed list (`sub`, `email`, `email_verified`,
`preferred_username`). Every value ends up inside a credential the holder can
show anybody, so what may appear is a decision rather than a projection of
whatever the users table happens to hold.

### Verified end to end

A wallet script — one EC key, `openssl`, no libraries — run against a live
server:

```
c_nonce: ZvzT7BS1g4bu4dbY...
typ        : dc+sd-jwt
vct        : https://vci-e2e.test/identity
cnf bound  : True
_sd_alg    : sha-256
in payload : ['cnf', 'exp', 'iat', 'iss', 'sub', 'vct']

disclosures the holder may reveal:
  email              = 'holder@vci-e2e.test'  digest in _sd: True
  email_verified     = False                  digest in _sd: True
  preferred_username = 'holder@vci-e2e.test'  digest in _sd: True
```

The access token was obtained by redeeming a pre-authorized code **with no
`client_id`**, which is the ordinary wallet case §6.1 describes.

## What is still not built

- **ISO mdoc** (`mso_mdoc`). The `format` column has a CHECK constraint listing
  only SD-JWT VC, so adding it is a migration rather than a rewrite.
- **Deferred issuance** (§9) and the **notification endpoint** (§11).
- **Credential response encryption** (§10) and encrypted requests.
- The **authorization code flow** variant (`issuer_state`).
- **Key attestation** (Appendix D) and the `kid`/`x5c` proof forms — a proof must
  carry its key inline as `jwk`. `kid` names a key we would have to resolve and
  `x5c` a chain we would have to trust; accepting either without doing that work
  would be accepting a proof we did not verify.
