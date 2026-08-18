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

## What is not built

- The **credential endpoint** and any credential format. That is the Credential
  Issuer's role, not the Authorization Server's.
- The **Credential Issuer Metadata** document. Signari would only publish it if
  it were also the Credential Issuer, which it is not.
- The **authorization code flow** variant of OID4VCI (`issuer_state`), the nonce
  endpoint, and deferred issuance.
