# Issuing credentials to wallets (OID4VCI)

## Introduction

A "verifiable credential" is a signed digital document, such as a staff card or a
degree. A person keeps it in a wallet app on their phone. The person, called the
"holder", can show it to anyone who needs to check it. OpenID for Verifiable
Credential Issuance ([OID4VCI](glossary.md#oid4vci)) 1.0, **Final, 16 September
2025**, is the standard for putting one into a wallet.

Signari issues credentials this way. An administrator makes a one-time "offer",
and the holder scans it as a QR code. The wallet then collects a credential bound
to a key that only the wallet holds. A wallet can also ask first, by sending the holder to
sign in. Each credential Signari issues is built on a signed JSON Web Token
([JWT](glossary.md#jwt)).

You define what Signari issues, and make offers, with the command line or the
Admin API.

## The two roles, and which Signari plays

OID4VCI separates two roles:

- The **Credential Issuer** holds the credential endpoint, and knows how to mint
  a Selective Disclosure JWT ([SD-JWT](glossary.md#sd-jwt)) VC or an ISO mdoc.
- The **Authorization Server** issues the access token that credential endpoint
  will accept.

Signari began as the second, with the **Pre-Authorized Code grant** and the
**Credential Offer** that carries it. It is now both: see [the Credential Issuer
half](#the-credential-issuer-half).

An implementation that published a `credential_endpoint` it could not serve would
make the same mistake as advertising a federation fetch endpoint that 404s. So an
endpoint enters a metadata document only once it works.

## Why this grant needs more care than it looks

§6.1: *"For the Pre-Authorized Code Grant Type, authentication of the Client is
OPTIONAL."*

So the pre-authorized code **is** the credential: whoever presents it receives a
token. Two things carry the weight a client secret normally would:

1. The code *"MUST be short lived and single use"* (§3.5).
2. The optional Transaction Code, whose purpose §3.5 states exactly: *"to bind
   the Pre-Authorized Code to a certain transaction to prevent replay of this
   code by an attacker that, for example, scanned the QR code while standing
   behind the legitimate End-User."*

That last sentence is the threat model, and it is unusually concrete for a
specification. A pre-authorized code is a QR code on a screen, and the attacker
is a person with a phone, standing behind the holder. The transaction code travels
by a different channel, so that photographing the screen is not enough.

## The distinction the specification hinges on

§6.1, on `tx_code` in a token request:

> This value MUST be present if a `tx_code` object was present in the Credential
> Offer **(including if the object was empty)**.

An empty `"tx_code": {}` in an offer, with no length, no input mode and no
description, still demands a value at the token endpoint. So **"no transaction
code" and "a transaction code with nothing declared about it" are different
states**, and the tempting implementation collapses them.

`TxCode` is therefore a pointer. `StoredCode` carries an explicit `RequiresTxCode`,
instead of deriving it from whether some stored value is non-empty. Deriving it is
the mutation that turns a required check into an optional one. It passes every
test that does not specifically look for it.

The converse is enforced too. A transaction code arriving for an offer that never
asked for one is refused. A wallet sending one means it and the issuer disagree
about what this offer is, and proceeding accepts the wallet's version.

## Guessing is bounded per code, not per address

A transaction code is a handful of digits. §3.5's `length` exists so a wallet can
size an input box. So unbounded guessing removes the protection entirely.

The limit is **per pre-authorized code**, and the contrast with the device flow is
the interesting part. A device flow user code is drawn from one space shared by
every device. So an attacker guessing there is attacking the *space*, and the
limit belongs on the guesser. That is why that one is per-address, and why making
it global was a denial of service, fixed earlier in this review.

A transaction code belongs to one offer. An attacker is attacking *that offer*. So
a per-address limit would let them change address, while a per-code limit ends
the offer. Five attempts, then the offer is spent.

Each of these deliberate faults was caught by a test:

| Mutation | Test that caught it |
|---|---|
| Derive "requires tx_code" from the value rather than the flag | `TestAnEmptyTxCodeObjectStillRequiresAValue` |
| Accept a transaction code that was never asked for | `TestATransactionCodeArrivingUnaskedIsRefused` |
| Allow unlimited transaction code guesses | `TestGuessingTheTransactionCodeEndsTheOffer` |
| Let a redeemed code be used again | `TestAPreAuthorizedCodeIsSingleUseAndShortLived` |

## Storage

Pre-authorized codes are kept in `core.preauthorized_codes` (migrations 0077 and
0078). The code is stored **hashed**, for the same reason authorization codes are.
Read access to the table must not be read access to live credentials, and this
code is a bearer credential by design. The transaction code is hashed too.

`tx_code_input_mode`, `tx_code_length` and `tx_code_description` are stored so the
offer can be reconstructed. The column being NULL is what records "this offer had
no `tx_code` object", as distinct from "it had an empty one".

## Wiring: who the token is for

§6.1 again, and this is the sentence that decides the design:

> For the Pre-Authorized Code Grant Type, authentication of the Client is
> OPTIONAL... and, as a consequence, the `client_id` parameter is **only needed
> when a form of Client Authentication that relies on this parameter is used**.

So a conformant wallet redeems with `grant_type` and `pre-authorized_code`, and
nothing else. Signari's token endpoint resolved a client before it dispatched on
the grant type. That would have refused every such request as `invalid_client`,
refusing the ordinary case while appearing to support the grant.

There is still a client, because a token needs an audience, scopes and a lifetime.
It is chosen when the **offer** is minted, by the administrator who knows which
credential issuer the offer is for. It is read back from the code at redemption
(`client_id` on `core.preauthorized_codes`, migration 0078).

That is also the stronger position. If the wallet named the client, the wallet
would be choosing which client's scopes its own token carries. A wallet that
*does* send `client_id` must send the one the offer was issued to. The parameter
is unnecessary, not free.

## Minting an offer

To mint an offer of a credential for one person, with a transaction code:

```sh
signari credential offer \
  -org <uuid> \
  -email holder@example.com \
  -client-id wallet \
  -credential-configuration UniversityDegree_JWT \
  -credential-issuer https://credentials.example.com \
  -tx-code
```

It prints the offer JSON and the `openid-credential-offer://` deep link from
§G.7.1. Separately, with the reason attached, it prints the transaction code.

The separation is not presentation. §3.5 requires the transaction code to travel
by a different channel than the offer, because the whole mechanism assumes the
offer may have been photographed. Printing both into one message that somebody
copies to the holder defeats it entirely, so the output says so.

`-offer-expires` defaults to five minutes, and is capped at an hour. §3.5 says the
code MUST be short lived, and it is redeemed within seconds of being scanned.

A front desk with no shell mints the same offer at
`POST /admin/users/{userID}/credential-offers` in the [Admin API](admin-api.md#users).
The Admin API also defines credentials, and trusts `x5c` roots, under the
organisation (`credential-configurations`, `credential-proof-roots`). It answers
the transaction code beside the offer only so the caller can send it by another
channel.

## Registering the grant

A client may only use grants it is registered for. RFC 6749 §5.2's
`unauthorized_client` is "The authenticated client is not authorized to use this
authorization grant type". To register the wallet client for this grant:

```sh
signari client set-grants -client-id wallet \
  -grant-types urn:ietf:params:oauth:grant-type:pre-authorized_code
```

It is checked when the offer is **minted**, not only when it is redeemed. The
person who finds out at redemption is the holder, standing wherever they scanned
the QR code, with nothing they can do about it.

Reviewing this turned up that the **device grant was gated nowhere**. Any
registered client could run a device flow, whatever it was registered for, and
the default value of `grant_types` does not include it. Both endpoints now check.
The check for every grant the token endpoint dispatches lives in one place, not
repeated per handler, which is how the device one got missed. See [Device
authorization grant](device-flow.md).

## Order of operations at redemption

The sequence is **read, check the transaction code, then claim**. It is not the
authorization code path's claim-as-you-read.

A wrong transaction code charges an attempt, and does **not** spend the offer. If
it did, one wrong guess would destroy the holder's credential. That would turn a
shoulder-surfing defence into a denial of service, which anybody who photographed
the QR code could perform. Five wrong guesses end the offer, and the sixth attempt
fails even with the right code.

Every refusal is `invalid_grant`, whatever the reason: an unknown code, a spent
code, an expired code, a missing transaction code, or too many guesses. The
`description` says which. A wallet has to render something to a person who is
standing there, wondering why their credential did not arrive.

The error `code` does not vary. So nothing parsing the response programmatically
can tell a code that never existed from one already spent.

## The Credential Issuer half

Everything above is the authorization server. This is the other role: Signari now
**mints the credential**. It serves these endpoints:

```
POST /oid4vci/nonce                          §7  — unauthenticated
POST /oid4vci/credential                     §8  — bearer or DPoP
POST /oid4vci/notification                   §11 — bearer or DPoP
POST /oid4vci/deferred_credential            §9  — bearer or DPoP
GET  /oid4vci/offer/{handle}                 §4.1.3 — unauthenticated
GET  /.well-known/openid-credential-issuer   §12.2
```

Format: **SD-JWT VC**, `draft-ietf-oauth-sd-jwt-vc-18` (10 August 2026).

### Which tokens it accepts

It accepts only a token that a redeemed offer minted, and only for the
configurations that offer named. The specification's §5.1.2 has the issuer read
what a token authorizes as the issuance of particular credential types
(`specs/oid4vci.txt:1332`). And §8.3.1.1 answers a token that does not enable the
requested one with an RFC 6750 error. So:

| The token | The answer |
|---|---|
| audienced to anything but this endpoint, which is every sign-in token | `401`, `error="invalid_token"` |
| audienced here and minted by no offer | `401`, `error="invalid_token"` |
| from an offer that did not name the requested configuration | `403`, `error="insufficient_scope"` |
| from an offer naming a configuration since removed | `400`, `unknown_credential_configuration` (§8.3.1.2) |
| revoked, or from a revoked grant or an ended session | `401`, read at the request as userinfo reads it |

The redemption records the access token it minted on the offer (migration 0133),
in the minting transaction. That is the binding, not an `authorization_details`
claim. Returning `openid_credential` details obliges the wallet to use the
`credential_identifiers` that come with them (§6.2), and an offer's wallet already
knows the configuration IDs. A token from the [authorization code
flow](#a-wallet-that-asks-first) carries the claim instead.

The audience runs the other way too. A redeemed token's `aud` is the credential
endpoint and nothing else, because nobody signed in to get it. So userinfo refuses
it, introspection reports it inactive to every caller, and token exchange and
transaction tokens refuse it as a subject or an actor. A wallet that wants an
ordinary token has to sign somebody in.

**Until October 2026 this endpoint accepted any access token audienced to the
issuer.** A sign-in token from an unrelated client minted any configuration for
its subject, bound to whatever key the caller proved. A token its client had
revoked kept minting until it expired.

### Why SD-JWT rather than a plain signed credential

An ordinary credential is all-or-nothing. To prove you are over 18, you hand over a
document carrying your name, address and date of birth. The verifier learns
everything, because the signature covers everything, and removing a field breaks
it.

SD-JWT signs **digests** of individual claims. The holder gets the signed JWT,
plus one *disclosure* per claim, and presents only the ones they choose. The signature still verifies, because it was never over the
values.

An issued credential looks like:

```
<jwt>~<disclosure>~<disclosure>~<disclosure>~
```

### The detail that decides whether any verifier accepts it

§4.2.3 of the SD-JWT specification, emphatically:

> The digest MUST be taken over the US-ASCII bytes of the **base64url-encoded**
> value that is the Disclosure… The input to the hash function MUST be the
> base64url-encoded Disclosure, **not** the bytes encoded by the base64url string.

Hashing the decoded JSON is the natural reading. It produces a plausible digest,
and yields a credential nothing on earth will accept. The specification publishes
a test vector precisely because of this, and
`TestTheSpecificationsOwnDigestVector` uses it:

| | |
|---|---|
| Disclosure | `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0` |
| Digest | `X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0` |

Two related details, both found by mutation rather than by reading:

- **`Disclosure.Digest()` and `DigestOf()` were two implementations of that one
  rule.** The specification's vector exercised the second, and issuance called
  the first. Breaking the issuance path exactly as §4.2.3 warns broke no test.
  They are now one function.
- **`typ` is `dc+sd-jwt`.** draft-18 renamed it from `vc+sd-jwt` "to avoid
  conflict with the vc media type name". The test asserting it originally
  compared the header against Signari's own constant. That was a tautology, which
  passed when the constant was changed to the deprecated value. It compares a
  literal now.

### Key binding, which is the point of the proof

§8.2 requires a key proof, and the credential carries `cnf` naming the key it was
bound to. Without that, a credential is a bearer token: whoever copied it could
present it.

Appendix F.1's rules are each enforced, and each tested:

| Rule | Why refusing matters |
|---|---|
| `typ` is `openid4vci-proof+jwt` | an ID token is also signed JSON with `aud` and `iat` |
| `alg` is asymmetric, never `none` | a MAC would make the verification key the forgery key |
| exactly one of `kid`/`jwk`/`x5c` | two key sources means the key *verified* and the key *bound* can differ |
| signed by the key it carries | otherwise anybody binds a credential to somebody else's public key |
| `aud` is the Credential Issuer | a proof for another issuer would be replayable here |
| `iat` present and recent | an undated proof never ages out |
| carries this issuer's `c_nonce` | a captured proof would otherwise be replayable forever |

And one rule is worth its own line. §F.1 on `iss`:

> This claim MUST be omitted if the access token authorizing the issuance call
> was obtained from a Pre-Authorized Code Flow through **anonymous** access to
> the token endpoint.

That is exactly Signari's flow. §6.1 lets the wallet send no `client_id`, and
Signari honours it. So `ProofContext` carries `Anonymous` separately from an empty
`ClientID`. *"We do not know the client"* and *"there deliberately was no
client"* are different states, and only the second forbids the claim.

### `c_nonce` is single use

§7 requires a Nonce Endpoint when proofs must carry a nonce, and §8.2 has the
nonce establish freshness. A nonce that can be presented twice establishes it
once, so it is spent in the statement that reads it.

It is spent once per request, not once per proof. A batch's proofs, each for a key
of its own, carry the one nonce the wallet fetched, and that is no replay. Spent at
the first proof, it refused the second, so no batch could be issued until November
2026.

A nonce already spent, or never given out, is answered `invalid_nonce`. After
that, "the wallet should retrieve a new c_nonce value" (§8.3.1.2). A proof with no
nonce at all is `invalid_proof`. Both were `invalid_proof`, which tells a wallet
to give up. A request with no `proofs` is `invalid_proof` too, "if the field is
missing", where it was `invalid_credential_request`.

The endpoint is **unauthenticated**, which §7.1 states outright, and which is
worth not second-guessing. A wallet needs the nonce *before* it can build the
proof that the token-bearing request depends on.

The nonce is also **not organisation-scoped**. Migration 0081 scoped it and 0082
took that back, because it forced an unauthenticated endpoint to guess an
organisation. A `c_nonce` proves freshness and identifies nobody. Which
organisation a credential is issued for comes from the access token's subject, at
an endpoint where there genuinely is one.

### Defining what this issuer mints

A "credential configuration" says what one kind of credential holds. This command
defines one, with the subject always shown and three claims the holder can choose
to reveal:

```sh
signari credential define -org <uuid> \
  -credential-configuration IdentityCredential \
  -vct https://example.com/identity \
  -always sub \
  -selective email,preferred_username,email_verified \
  -valid-for 720h
```

The `always`/`selective` split is the whole feature, so it is two flags, not one
list with a flag per claim. A claim under `always` is visible to **every verifier
the holder ever presents to**. Putting the more dangerous option behind the easier
typo would be a poor trade.

Claim names come from a fixed list (`sub`, `email`, `email_verified`,
`preferred_username`). Every value ends up inside a credential the holder can show
anybody. So what may appear is a decision, not a projection of whatever the
`core.users` table happens to hold.

### Verified end to end

A wallet script, with one EC key, `openssl` and no libraries, was run against a
live server:

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

## An offer too big for a QR code

An offer by value carries everything in the code a person scans. `signari
credential offer -by-reference`, or `"by_reference": true` on the Admin API, keeps
it here instead. The person scans a short address (§4.1.3):

```
openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fid.example%2Foid4vci%2Foffer%2F...
```

The offer holds a pre-authorized code. So it is sealed under the root key, only
the handle's hash is stored, it is served `no-store`, and it goes when the code
does. The address is as good as the code to whoever has it. So use a transaction
code for an offer shown where others can see it.

## What became of a credential

A Credential Response carries a `notification_id`, and the metadata names
`POST /oid4vci/notification` (§11). A wallet may report `credential_accepted`,
`credential_failure` or `credential_deleted`, with the token that asked, and that
token only.

Each is recorded as `oid4vci.credential_notified`. Nothing depends on it, since a
wallet may never say, and the window is the token's lifetime.

## A credential somebody has to look at first

Some credentials are not issued on the strength of a code alone. `signari
credential define -deferred`, `"deferred": true` on the Admin API, or
`deferred: true` in a configuration file holds each request for a decision (§9).
An administrator lists the requests waiting, and decides each one:

```sh
signari credential requests -org <uuid>
signari credential decide -org <uuid> -request <id> -decision approve
```

The wallet's proofs are checked when it asks. It is answered `202`, with a
`transaction_id` and an `interval`. It then asks `POST /oid4vci/deferred_credential`
with the same token until there is an answer:

| The decision | The wallet is answered |
|---|---|
| none yet | `202`, with the same `transaction_id` |
| approved | `200` with the credentials, bound to the keys it proved, once |
| denied | `400 credential_request_denied` |
| the configuration has been removed | `400 credential_request_denied` |
| an id not given to this token, or already used | `400 invalid_transaction_id` |

What waits is the public keys, not the proofs, because a nonce is spent once. A
person deactivated while waiting gets nothing. Their token stops working, as it
does at the Credential Endpoint.

**A decision has as long as the wallet's token lasts.** That is five minutes,
unless `signari client set-lifetimes -access-ttl` says otherwise for the wallet
client, and at most an hour. §9 requires a token valid for the issuance. An
offer's code is spent, so a wallet cannot get another. A request nobody decides in
that time is swept. This suits a person at a counter, and not a review that takes
days.

## A wallet that asks first

Everything above starts with an offer. The authorization code flow (§3.3) can start
with the wallet. It sends the holder to the authorization endpoint with details of
type `openid_credential`. They sign in and approve what they are shown, and the
token response names what they were granted. The wallet's request looks like this:

```
GET /oauth2/authorize?response_type=code&client_id=wallet&code_challenge=...
    &code_challenge_method=S256&redirect_uri=https://wallet.example/cb
    &authorization_details=[{"type":"openid_credential",
                             "credential_configuration_id":"Employee"}]
```

`scope` can be left out, as the specification's own example does, and then no ID
token comes back. The client has to be allowed the type, as for any other detail:

```sh
signari rar register -org <uuid> -type openid_credential -fields locations
signari rar allow -client-id wallet -type openid_credential
```

**Who may ask.** A wallet can ask for anything the metadata lists. The claims
coming from the person's own record does not make holding the credential theirs to
decide. So a configuration is closed until it says otherwise. To open one:

```sh
signari credential define -org <uuid> -credential-configuration Employee ... -wallet-initiated
```

That opens it to anybody who can sign in here. Asking for one that is closed
answers `access_denied`, and says nothing about whether somebody else was offered
it.

**An offer to sign in with.** `credential offer -authorization-code` (or
`authorization_code` at the Admin API) makes an offer of a closed credential, which
the holder signs in to take up. It carries an `issuer_state` and no code:

```json
{"credential_issuer": "https://id.example.com",
 "credential_configuration_ids": ["Employee"],
 "grants": {"authorization_code": {"issuer_state": "..."}}}
```

§5.1.3 warns that a state "could have been injected by an attacker", so it decides
nothing about who is signing in. It counts only for the person the offer names,
through the client it names, for what it names, once. For anybody else it is as
good as absent.

The offer is spent when the code is issued, not when the consent screen is drawn.
So looking twice costs nothing, and of two racing requests one gets a code.

A state is kept in the column a pre-authorized code is, under a hash no code can
match. That is because a code is a bearer secret, and a state travels through a
browser's address bar. Presented as a code, it is unknown, to this release and to
the last.

**The token** is good at the credential endpoint and nowhere else, and a refresh
of the grant is the same. So details of this type are asked for alone. Another
detail beside them would be approved on the screen, and carried by a token no
resource server accepts.

The token says what it was granted, in its own signed `authorization_details`
claim, and needs no offer behind it. The token response returns those details with
`credential_identifiers`, here the configuration's ID, since each configuration
makes one credential from one person's record.

A wallet then asks by identifier. §8.2 lets it use nothing else, and in turn an
identifier from a token that was given none is refused. A wallet's request then
looks like this:

```json
{"credential_identifier": "Employee", "proofs": {"jwt": ["..."]}}
```

## A W3C credential as a JWT

Some verifiers read W3C Verifiable Credentials, not SD-JWT VCs. For them, define a
configuration in the `jwt_vc_json` format:

```sh
signari credential define -org <uuid> \
  -credential-configuration DegreeCredential -credential-format jwt_vc_json \
  -vct UniversityDegreeCredential -always email,given_name -valid-for 8760h
```

`jwt_vc_json` is Appendix A.1.1. `-vct` is the credential's own type. The metadata
gives `credential_definition.type` as
`["VerifiableCredential", "UniversityDegreeCredential"]`, with no `vct`. The
credential is a JWT with a `vc` claim, shaped as the appendix's example is, and
nothing in it is processed as JSON-LD.

The holder's key is bound as a `did:jwk`, in `sub` and `credentialSubject.id`. So
`cryptographic_binding_methods_supported` says `did:jwk`, and there is no `cnf`.
The person the credential is about is not named by an identifier of Signari's,
only by the claims you list.

It is disclosed whole. This format has no way to show one claim and hide another,
so a configuration of it naming `-selective` is refused. Use `dc+sd-jwt`, the
default, when a holder should choose. Everything else here applies to both: key
proofs, attestation, deferred issuance, wallet-initiated requests and the
notification endpoint.

## A credential only the wallet can read

Transport Layer Security ([TLS](glossary.md#tls)) ends where it ends. A wallet with
a backend, or an issuer behind something that terminates TLS, can have a credential
pass through a component that should not see it. So a wallet can ask for the
credential sealed to a key of its own (§10). To make the issuer's key for this:

```sh
signari credential encryption-key
```

That makes a key and publishes it, as `credential_request_encryption.jwks` in the
issuer metadata, with `credential_response_encryption` beside it. Until there is a
key, the metadata mentions neither, and a request with
`Content-Type: application/jwt` is refused. An issuer with no key offers nothing
it could not do.

The key is for this alone. It is a P-256 key used for `ECDH-ES`. It signs nothing,
and is never in the JSON Web Key Set ([JWKS](glossary.md#jwks)). It is sealed under
the root key like any other, so `signari keys rotate` leaves it alone and
`signari keys rewrap-root` carries it.

The wallet sends its request as a JSON Web Encryption (JWE) in `application/jwt`,
with `credential_response_encryption` inside it: `{"jwk": {...}, "enc": "A256GCM"}`,
the key carrying an `alg` of `ECDH-ES` or `RSA-OAEP-256`. The answer comes back as a
JWE in `application/jwt`, with that key's `kid` in the header.

It works the same at the deferred endpoint. There, the object in each request
decides that request's answer, whatever the first one said.

**A request for encryption has to arrive encrypted.** §8.2: "Credential Request
encryption MUST be used if the credential_response_encryption parameter is
included, to prevent it being substituted by an attacker". Whoever could read the
credential could otherwise have swapped the key for theirs. So the request is
refused with `invalid_encryption_parameters`. It works the other way round: a
sealed request that does not ask gets a plain JSON answer.

**What cannot be sealed is refused before anything is issued.** These all answer
`invalid_encryption_parameters`, with no proof spent and no credential minted: a
compressed answer, an `enc` or `alg` not on offer, a key with no `alg`, or a
signing key. If sealing fails after that, the wallet gets a 500, and not the
credential in the clear. Errors are `application/json` either way, as §8.3.1 has
them.

**Running the command again rotates.** The new key goes into the metadata. The old
one keeps opening what a wallet sealed from a cached copy, and the one before that
stops opening anything. So a key you believe lost takes two runs.

Wallets have nothing to redo. They take the key from the metadata, and a refusal
sends them back for it. There is no dwell as with a signing key, since nothing
verifies against this key later. Each run is recorded as `keys.rotated`, with
`purpose` saying which key.

Under `fips140=only`, the offered `enc` values are the CBC ones ([FIPS
140-3](fips.md)).

## Taking a credential back

A credential is signed and handed over, and after that the holder has it. To be
able to take one back, ask for that when you define it:

```sh
signari credential define -org <uuid> -credential-configuration Employee ... -revocable
```

Each credential then carries a place in a [Token Status
List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), the
`status` claim, and is remembered. Signari remembers who it was issued to, from
which configuration, when, and where its bit is. Without `-revocable`, nothing
about a credential is kept and it can only expire. So turning it on covers
credentials issued from then on.

To list what a person holds, and revoke one credential or everything they hold:

```sh
signari credential issued -org <uuid> -email ada@example.com
signari credential revoke -org <uuid> -credential <id>     # one
signari credential revoke -org <uuid> -email ada@example.com   # everything they hold
```

A revocation cannot be undone. There is no suspended state. The draft warns
(§12.8) that any status besides valid and invalid tells whoever reads the list more
than it needs to. Revoking and issuing a new one comes to the same. A new
credential gets a new place.

**A verifier fetches `GET /oid4vci/status/{list}`**, anonymously, from the `uri`
in the credential. It gets a `statuslist+jwt` signed with the same key as the
credential. It has one bit per place, 131,072 of them, and `sub` equal to that
`uri`.

The token is made from the database at each request, so the moment a revocation
commits, it is in the next fetch. It carries a `ttl` of five minutes and an `exp`
of an hour. A verifier that follows the `ttl` learns within five minutes. That
wait is the verifier's, and how far behind one is willing to be is up to it.

**The list is what keeps the holder private.** A verifier asks about one
credential by fetching all of them. So the issuer learns that somebody looked at a
list, and not which credential. That is why there are not more lists than needed.
An organisation has one filling at a time, and it stops taking credentials at half
full.

The other half are never handed out, which hides how many are real. Each place is
chosen at random, since one handed out in order says how many came before it. Each
credential of a batch gets its own (§13.2), so revoking a batch shows up as a
batch.

**A person who is deleted takes their credentials with them.** However a person
goes, by erasure, System for Cross-domain Identity Management
([SCIM](glossary.md#scim)), the Admin API or anything else, their places read as
revoked in the next fetch. That is because a place with nobody behind it counts as
revoked. Deactivating somebody does not do this. An administrator who wants it
says so with `credential revoke`.

A list goes away once it is full and everything in it expired a day ago, which the
janitor, Signari's background clean-up, sees to. One holding a credential with no
expiry stays for good, so give a revocable credential a `-valid-for`.

Credentials are JWT only, as SD-JWT VC requires of a status list, so there is no
CWT form. `?time=` asks about the past (§8.4), and answers `501`: only the present
is kept.

## What is still not built

- **ISO mdoc** (`mso_mdoc`), which needs COSE, and **`ldp_vc`**, which needs JSON-LD
  canonicalization. The `format` column has a CHECK constraint listing what is
  signed, so adding one is a migration, not a rewrite.
- **Requiring encryption.** `encryption_required` is `false` both ways, and the
  metadata names no `zip_values_supported`, so a compressed request is refused.
- A credential requested by **`scope`** (§5.1.2). A wallet asks with
  authorization details, and the metadata names no scope for it to use instead.
- **Issuing fewer claims than a configuration carries** because a wallet's `claims`
  asked for fewer. A credential holds what its configuration says, and the holder
  chooses what to disclose of it.

## What a wallet asks to have in its credential

The `claims` of an `openid_credential` authorization detail (§5.1.1) are claims
description objects (Appendix B.1). Each is a claim path pointer, and whether the
wallet takes no credential without the claim.

They are held to Appendix B.3. Each of these refuses the request at the
authorization endpoint with `invalid_authorization_details`:

- A claim described twice.
- One array addressed whole and by an index.
- One claim taken for an array and an object.
- A path that is not one (Appendix C).
- An empty list.

A claim marked `mandatory` must be one the configuration carries. It is named as
its format names claims: the first key for `dc+sd-jwt`, and the key under
`credentialSubject` for `jwt_vc_json`. Otherwise the request is refused before
anybody signs in, since no credential of that configuration would be one the
wallet takes.

Sometimes the configuration carries a claim, and the person's record has no value
for it, such as an address on an account that has only a username. That is refused
at the credential endpoint with `credential_request_denied`, before a proof spends
its nonce. A claim not marked mandatory and not carried is let go, as the wallet
said it could be.

Until November 2026, nothing decoded `claims`. So a wallet that marked a claim
mandatory was given a credential without it, and nothing said so.

## `x5c` key proofs — built

A proof may name its key with an `x5c` chain, leaf first, instead of `jwk`. The
chain must verify, with each certificate in its validity window, to a certificate
authority (CA) the organisation registered. These commands register a root, list
the roots, and remove one:

```sh
signari credential trust-root -org <id> -name wallet-provider -root-cert ./ca.pem
signari credential roots
signari credential untrust-root -org <id> -name wallet-provider
```

With none registered, every `x5c` proof is refused. It is never accepted on its own
signature, which a self-signed certificate satisfies. The file must hold one CA
certificate and no private key. A server holding the CA's key could mint the
chains it is meant to be checking. The roots are read on every credential request,
so a withdrawal holds at the next one.

## Key attestation (Appendix D) — built

A key proof says "I hold this key". A **key attestation** adds "and a party you
trust vouches for how it is stored". `internal/oid4vci/attestation.go` accepts
`key_attestation` JWTs (`typ: key-attestation+jwt`), and resolves a proof's `kid`
against the attested key set.

The attester's signature is **required**. With no trusted attesters configured,
the header is refused, not ignored. Accepting an unverified attestation is taking
the wallet's word about its own security. A wallet that sends one and receives a
credential concludes the attestation was checked.

Register one with `signari attester add -org <id> -name <n> -attester-jwks <file>`.
The same registry serves attestation-based client authentication. The party that
vouches for a wallet's keys is the wallet's provider, which is the party that
vouches for the wallet.

The credential endpoint reads the organisation's attesters for every request, so
one added or removed holds at the next credential. Until October 2026 it read
none, and every attested proof was refused while this page said to register one.

An attestation is accepted when it is offered. To *require* one for a credential,
define it with `-require-key-attestation`:

```sh
signari credential define -org <uuid> -credential-configuration IdentityCredential \
  -vct https://example.com/identity -selective email -require-key-attestation
```

The credential endpoint then refuses a proof whose key no trusted attester vouches
for. The issuer metadata lists `key_attestations_required: {}` under that
configuration's `jwt` proof type. It is empty because it puts no constraint on
`key_storage` or `user_authentication`.

It is listed for those configurations and no others. The specification says the
member "MUST NOT be present" when the issuer does not require one
(`specs/oid4vci.txt:2429`). An attestation that vouches for a key other than the
one the proof is signed with is refused, for every key source.


## Harsh review of SD-JWT against RFC 9901 (August 2026)

This section is the record of a review pass. It is kept as it was found.

### The core specification is no longer a draft

`draft-ietf-oauth-selective-disclosure-jwt` was published as **RFC 9901,
"Selective Disclosure for JSON Web Tokens", Internet Standards Track, November
2025**. Signari's code still cited the draft: the same shape as the AuthZEN
finding, nine months old.

### The code is conformant; the citations were not

This is the first review in this pass that found **no defect in the
implementation**, and saying so plainly is better than manufacturing one. Every
issuer-side requirement holds:

| RFC 9901 | |
|---|---|
| §4.2.3 digest over the base64url string, not the decoded bytes | correct, with the specification's own test vector |
| §4.1 the same digest MUST NOT appear twice | a `seen` set covering decoys, made falsifiable by an injectable decoy source |
| §4.2.1 a Disclosure name MUST NOT be `_sd` or `...` | refused, on both the always-visible and the selective side |
| §4.2.1 nor a name already permanently present | refused |
| §4.1.1 `_sd_alg` | written explicitly as `sha-256` rather than relying on the default |
| §4.2.5 decoy digests | present, with a **random** count — a fixed one is worse than none, since a verifier subtracts it |
| §4.2.4.1 hide the original claim order | digests sorted |
| §9.3 salt entropy | 16 bytes from `crypto/rand` |
| trailing `~` when there is no Key Binding JWT | written unconditionally |

One subtlety is worth keeping. Disclosures are JSON-encoded with HTML escaping
**off**. Go's default encoder rewrites `<`, `>` and `&`, which changes the bytes,
and §4.2.3 hashes the bytes.

**RFC 9901's verifier requirements do not apply to Signari.** Signari issues, and
`Split` and `Parse` have no production callers. That is stated, not assumed. A
review that checked Signari's verifier against §7 would have been checking
something that does not exist.

### Reading found nothing; mutating found two things

The review above was done by reading, and reading is not harsh testing. Every
guarantee in the package was then broken deliberately, to see whether a test
noticed. Eight of ten mutants died. Two survived, and both were real.

**1. The salt could be halved and nothing failed.** RFC 9901 §9.3 requires at
least 128 bits. Shrinking `newSalt` from 16 bytes to 8 broke no test. That is a
security parameter with nothing measuring it.

The salt is the only thing that stops a verifier confirming a *withheld* claim by
hashing candidate values until one matches a public digest. For a claim with a
small domain, such as a date of birth, a postcode or a boolean, the search is
trivial. It is now tested, including that salts do not repeat.

**2. The test guarding the package's headline subtlety could not fail.**

`TestValuesContainingHTMLCharactersHashPortably` existed to check that disclosures
are encoded without Go's HTML escaping. It asserted:

```go
if strings.Contains(string(mustDecode(t, d.Encoded)), `<`) {
```

`mustDecode` does not decode the wire bytes. It `Parse`s the Disclosure, and then
**re-marshals it with `json.Marshal`**, which escapes HTML by default. So it
returned escaped bytes whatever the package had produced, and the literal `<` was
never present either way. The assertion could not fire. Turning
`SetEscapeHTML(false)` into `true` broke nothing.

The code was correct throughout. The test was inert, and it was inert around
exactly the detail the package documentation singles out as the one
implementations get wrong. It now decodes the base64 directly, which is what a
verifier hashes under §4.2.3. It checks for `\u003c` and `\u0026`, not for a
literal that cannot appear.

While fixing it, the package comment turned out to **overstate** the case.
Hashing is self-consistent either way. Signari hashes the encoding it transmits,
and a conformant verifier hashes the string as received. So an escaped Disclosure
would still verify, and still decode to the same value.

What escaping costs is interoperability with anything that re-serialises before
hashing, and readability when somebody is debugging a credential by hand. It is
defensive, not load-bearing, and the test now says it that way.

### Section numbers that moved, and a date

The numbering shifted between SD-JWT VC drafts, and nobody re-checked:

| cited | actual |
|---|---|
| `typ` at §3.2.1 | **§2.2.1** |
| Registered claims red list at §3.2.2.2 (×4 sites) | **§2.2.2.3** |
| salt entropy at §4.2.1 | **§9.3** |
| draft-18 dated 10 August 2026 | **3 August 2026** |

It is not a code defect. It matters anyway. In this codebase the comment carries
the argument, and a reviewer sent to §3.2.2.3 finds a section about something else
and cannot check the claim. RFC 9901's own numbering turned out to be unchanged
from the draft. That is good news, and precisely the kind of thing that should be
verified, not assumed.
