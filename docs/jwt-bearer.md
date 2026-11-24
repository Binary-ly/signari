# The jwt-bearer grant (RFC 7523 §2.1)

## Introduction

A program with nobody present, such as a deployment job, often already holds a
short-lived token from the platform it runs on. A party you trust signs a JSON
Web Token (JWT, see the [glossary](glossary.md#jwt)) about a subject, and an
application presents it to Signari. Signari then mints its own access token for
the local account that subject is linked to. There is no browser, no person, and
no long-lived secret stored anywhere.

RFC 7523 calls this the "jwt-bearer grant", and the signed token an "assertion".
It is what "workload identity federation" is built on. A continuous integration
(CI) job, a Kubernetes pod or a cloud service account already holds a short-lived
JWT signed by its platform. It trades that for a token here, instead of you
putting a client secret in the pipeline.

You turn it on with a handful of `signari idp` and `signari client` commands,
shown in [Setting it up](#setting-it-up).

## Setting it up

These commands register GitHub Actions as an issuer, allow it to sign assertions,
and pair an application called `ci-deploy` with it:

```sh
signari idp add-issuer -org <uuid> -slug github-actions \
    -issuer https://token.actions.githubusercontent.com \
    -jwks-url https://token.actions.githubusercontent.com/.well-known/jwks

signari idp assertions -slug github-actions -allow-assertions

signari client set-assertion-issuers -client-id ci-deploy -issuers github-actions
signari client set-grants -client-id ci-deploy \
    -grant-types urn:ietf:params:oauth:grant-type:jwt-bearer

# the account each workload acts as: the assertion's `sub`, linked to a person
signari idp link -slug github-actions \
    -subject repo:acme/deploy:ref:refs/heads/main -email deploy-bot@acme.example
```

The application also needs the grant itself, like every grant the token endpoint
serves. Until October 2026 `set-grants` did not accept this one, so no
application could be given it.

An assertion mints tokens for the local account its `sub` is linked to. An issuer
that only publishes keys is never a sign-in option, so no sign-in creates that
link. Instead, `idp link` creates one, `idp links` lists them and `idp unlink`
removes one. Until October 2026 nothing could, and this set-up minted nothing
without SQL.

A subject acts as one person, and a person is one subject at an issuer. So to
point a workload at another account, run `idp unlink` and then `idp link`.
Linking it again is refused, rather than taken as a move.

The Admin API does the same under the person, at `PUT` and
`DELETE /admin/users/{userID}/identity-links/{slug}` (see
[the Admin API](admin-api.md#users)). It registers the issuer itself at
`POST /admin/organizations/{orgID}/identity-providers`.

`idp add-issuer` and `idp assertions` are two commands because they are two
decisions. The first records that an issuer exists and where its keys are. The
second grants it the power to mint tokens here.

The issuer is added with `idp add-issuer` rather than `idp add`. `idp add`
discovers a provider's endpoints and refuses one that has none, and an assertion
issuer has none.

GitHub Actions, Kubernetes service-account issuers and SPIFFE (Secure Production
Identity Framework for Everyone) bundles publish a JSON Web Key Set (JWKS) and
nothing else. There is no authorization endpoint to send a browser to.

Such a provider can never become a sign-in option. The schema refuses
`allow_signup` and `allow_linking` on it, and the interactive sign-in path refuses
the kind outright.

## Turning it on is two decisions, not one

Registering an identity provider means *a person may sign in through it in a
browser*. It does **not** mean *any JWT that provider signs mints tokens with
nobody present*. Those are different powers, and the second is much larger.

So `allow_jwt_bearer` defaults to false on every provider, including ones you
registered years ago. Upgrading changes nothing until you run `idp assertions`,
which then prints:

```
github-actions: assertions allowed. JWTs it signs may now be exchanged for our tokens
  by any client registered for the jwt-bearer grant, on behalf of the local
  account each assertion's subject is linked to.
```

The assertion list is deliberately **separate** from the list of providers people
sign in through in a browser. That is why `idp assertions` exists as its own
command, rather than being implied by `idp add`.

Sharing one list between the two looks like reuse, and is not. A provider trusted
to authenticate a human, behind a redirect, a consent screen and a session, is not
thereby trusted to mint assertions. Those assertions become tokens with no human
present at all.

Merging the lists silently widens the second trust to everything granted for the
first. This feature has a track record across the industry of exactly that
mistake.

## What has to be true for a grant to succeed

1. The application is **confidential**, registered for
   `urn:ietf:params:oauth:grant-type:jwt-bearer`, and **paired with this specific
   issuer**. See below.
2. A provider **in the application's organisation** is enabled and opted in, and
   its effective issuer equals the assertion's `iss`.
3. The signature verifies against that provider's published JWKS.
4. The claims satisfy RFC 7523 §3. See below.
5. The assertion's `sub` is linked to a local account whose status is `active`.
6. The assertion's `jti` has not been seen before.
7. The account has no unmet obligation. An account flagged as needing a password
   change cannot mint tokens through a door that involves no password.
8. The person has not withdrawn their consent from this application on the
   account page.

No consent is asked for beforehand. A workload never sees a consent screen, and
pairing the application with the issuer is your authorisation. But a person who
disconnected the application is not minted for by its next assertion. Until
October 2026 they were. Consenting again at sign-in restores it.

Every failure returns the **same** `invalid_grant` and the same sentence. The real
reason is in the log, against a correlation ID. That matters more than it looks.

The issuer is resolved *before* any signature is checked, because `iss` selects
the verification key. So a distinct "issuer not trusted" reply would let anyone
with client credentials enumerate a deployment's trusted issuers. They could do it
using assertions that are not signed at all.

Separating "subject not linked" from "account disabled" would enumerate accounts.
A test asserts that seven different causes produce one identical response.

## Pairing, and why registering the grant is not enough

Two gates are not sufficient on their own, because they do not relate to each
other. The provider must be opted in, and the application must hold the grant.

Take an organisation that trusts both a CI platform and a Kubernetes cluster. An
application that exists to let one pipeline reach one API could otherwise spend a
pod's service-account token. Nothing crosses an organisation's boundary, and it is
still authority nobody granted.

So an application also carries the list of issuers it may use:

```sh
signari client set-assertion-issuers -client-id ci-deploy -issuers github-actions
```

**An empty list permits nothing**, not everything. That is the default for every
application, including ones registered before this existed, which is the
population the pairing is for.

The same rule is written down elsewhere in this engine, for Shared Signals
Framework (SSF) event sources (see [Shared Signals](ssf-caep.md)).
Reading an empty list as "everything" is how a half-made configuration becomes a
live grant.

A refusal here returns the same sentence as every other refusal. A distinct "this
client may not use that provider" would confirm that the named issuer *is* trusted
here. It would confirm it to the one caller who has a moment ago been told they
may not use it.

## The claim rules

A "claim" is one statement inside the assertion (see the
[glossary](glossary.md#claim)). Every one is a MUST in RFC 7523 §3:

| Claim | Rule |
|---|---|
| `iss` | Required. Selects the trusted provider. |
| `sub` | Required. Resolved against `(provider, subject)`, never `subject` alone. |
| `aud` | Required, must **name this issuer** (§3.1), and must name **only** this issuer. Accepts either spelling (RFC 7519 §4.1.3). |
| `exp` | Required, in the future, and **`exp − iat` must not exceed one hour** — the ceiling is on total lifetime, not on remaining time. |
| `nbf` | Optional. Binding when present. |
| `iat` | Optional. Refused if in the future. When present it is what the lifetime ceiling is measured from. |
| `jti` | Optional per the RFC and **required here** — see below. |

**The audience rule is the one worth understanding.** Without it, an assertion the
platform minted for some *other* application can be forwarded here and spent. The
issuer, having done nothing wrong, cannot tell.

Either spelling of "us" is accepted: the **issuer identifier** or the **token
endpoint URL**. Two conventions grew up around RFC 7523's "a value that identifies
the authorization server".

OpenID-shaped deployments use the issuer. Google's service-account flow, which
most RFC 7523 client libraries were written against, uses the token endpoint.
Accepting either means a library written for either works here. Both values name
Signari, so nothing is widened.

**The one-hour cap** is a ceiling on blast radius, rather than a guess at issuer
behaviour. An assertion valid for a year is a bearer credential valid for a year,
whatever the issuer intended. No major platform needs longer: Google caps
service-account assertions at an hour, and CI tokens last minutes.

**The ceiling is on total lifetime**, which is the part people miss. Bounding only
the remaining time lets through an assertion minted ninety minutes ago with five
minutes left. That is exactly the shape of one recovered from a log or a crash
report.

Measuring `exp − iat` bounds both ends at once. The assertion cannot reach further
than an hour, and it cannot have been sitting around longer than one either.

**Only one audience.** This is stricter than the specification, which permits an
array. An assertion carrying `aud: ["https://us", "https://partner"]` is a working
credential at the partner too. The partner can present it here and act as its
subject.

Replay protection does not catch that, because the partner's use of it leaves no
record in Signari's table. It is the confused-deputy form of the attack the
audience check exists to prevent.

## Replay protection, which the RFC does not require

RFC 7523 §6 is explicit: *"The specification does not mandate replay protection…
It is an optional feature, which implementations may employ at their own
discretion."*

Signari employs it. Without it, an assertion is a password for the length of its
`exp`. Anything that observes it once, such as a proxy log, an error report or a
misrouted request, holds a working credential until it expires.

The record is keyed by `(provider, jti)`. So two issuers cannot invalidate each
other's assertions by choosing colliding identifiers. The record carries the
assertion's own `exp`, so the janitor, Signari's clean-up job, can drop it exactly
when it stops mattering.

**`jti` is required**, which is also stricter than the RFC.

An earlier version accepted assertions without one, and skipped replay protection
for them, documented as a known limit. That was the wrong call. It was a
protection the documentation claims, silently absent for some inputs, with nothing
telling the administrator which issuers are unprotected. Failing closed is the
only version of "replay protected" that is true.

The practical cost is nil, because every issuer this grant is for emits `jti`. An
issuer that does not gets a specific error in the log, rather than silent
exposure.

## What this grant deliberately does not do

**No refresh token.** A refresh token would outlive the assertion. It would turn a
short-lived, revocable statement into a long-lived credential: precisely the
property workload identity exists to avoid. The application can get another
assertion whenever it needs one, and that stays revocable at the issuer.

**No `openid` scope, and no ID token.** An ID token states that *Signari*
authenticated this person. Signari did not: a third party did. What `acr` and
`amr` should then say is a question RFC 7523 does not answer. So the scope is
refused with that reason, rather than answered with invented claims.

**No session.** Nothing was signed in, so nothing can be signed out. The token
carries no `sid`, because inventing one would make a sign-out appear to reach a
token it cannot.

## The same token through token exchange

A JWT from a registered issuer can also be presented to RFC 8693 token exchange.
It goes in as `subject_token`, with
`subject_token_type=urn:ietf:params:oauth:token-type:jwt`.

Use this rather than the grant when the token is going to be passed on. It can be
addressed to one of the application's `set-exchange` audiences, and the result
records who is acting.

To let an application called `gateway` exchange tokens from the issuer `partner`
for one audience, run:

```sh
signari client set-exchange -client-id gateway -exchange-audiences https://api.acme.example
signari client set-assertion-issuers -client-id gateway -issuers partner
```

Every rule above applies, with the same one sentence for every refusal:

- The issuer has opted in.
- The application is paired with it.
- The claim rules hold.
- The person is linked and active.
- Their consent has not been withdrawn.
- The access policy allows it.
- Each `jti` is used once, shared with the grant.

A token spent either way cannot be spent the other. On top of those:

- The application needs exchange too. One without it is refused before any keys
  are fetched.
- The ceiling is the application's registered scope. A `scope` claim in the token
  is its issuer's vocabulary, and buys nothing here.
- `openid` is refused, as with the grant. So is an application whose registration
  carries it when no `scope` was asked for.
- An `act` chain in the token is kept, with the calling application added above
  it. A `may_act` in it is held to.
- The result never outlives the token it came from, and has no session.
- Only `...token-type:jwt`. An access token from elsewhere means whatever its
  issuer says it means, and nothing asks them. So it is refused, as any invalid
  token is.

The audit record, `oauth.token_exchanged`, names the `subject_issuer`. Refusals of
a subject or actor token are `invalid_request`, as RFC 8693 §2.2.2 requires. This
grant's refusals are `invalid_grant`.

## Key fetching

Provider keys are cached, with three behaviours worth knowing:

- A **rotation** is picked up automatically. An assertion naming a `kid` the cache
  does not hold forces one refresh.
- That refresh is **rate-limited**, so invented `kid`s cannot turn each token
  request into an outbound fetch at the provider.
- A **failed refresh keeps the keys already held**. A provider having a bad minute
  does not invalidate keys that are still theirs.
