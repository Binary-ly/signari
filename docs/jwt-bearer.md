# The jwt-bearer grant (RFC 7523 §2.1)

```sh
signari idp add-issuer -org <uuid> -slug github-actions \
    -issuer https://token.actions.githubusercontent.com \
    -jwks-url https://token.actions.githubusercontent.com/.well-known/jwks

signari idp assertions -slug github-actions -allow-assertions
```

Two commands because they are two decisions: the first records that an issuer
exists and where its keys are, the second grants it the power to mint tokens
here.

`idp add-issuer` rather than `idp add`, because `idp add` discovers a provider's
endpoints and refuses one that has none — and an assertion issuer has none. GitHub
Actions, Kubernetes service-account issuers and SPIFFE bundles publish a JWKS and
nothing else; there is no authorization endpoint to send a browser to. Such a
provider can never become a sign-in option: the schema refuses `allow_signup` and
`allow_linking` on it, and the interactive login path refuses the kind outright.

A party you trust signs a JWT about a subject; a client presents it; Signari mints
its own access token for the local account that subject is linked to. No browser,
no person, no long-lived secret stored anywhere.

This is what workload identity federation is built on. A CI job, a Kubernetes pod
or a cloud service account already holds a short-lived JWT signed by its platform,
and trades that for a token here — instead of you putting a client secret in the
pipeline.

## Turning it on is two decisions, not one

Registering an identity provider means *a person may sign in through it in a
browser*. It does **not** mean *any JWT that provider signs mints tokens with
nobody present*. Those are different powers, and the second is much larger.

So `allow_jwt_bearer` defaults to false on every provider, including ones you
registered years ago. Upgrading changes nothing until you run the command above.

```
github-actions: assertions allowed. JWTs it signs may now be exchanged for our tokens
  by any client registered for the jwt-bearer grant, on behalf of the local
  account each assertion's subject is linked to.
```

Sharing one provider list between browser sign-in and this grant looks like reuse
and is not: the two trusts are different, and merging them silently widens one
to everything granted for the other.

## What has to be true for a grant to succeed

1. The client is **confidential** and registered for
   `urn:ietf:params:oauth:grant-type:jwt-bearer`.
2. A provider **in the client's organisation** is enabled, opted in, and its
   effective issuer equals the assertion's `iss`.
3. The signature verifies against that provider's published JWKS.
4. The claims satisfy RFC 7523 §3 — see below.
5. The assertion's `sub` is linked to a local user whose status is `active`.
6. The assertion's `jti` has not been seen before.

6. The account has no unmet obligation — an account flagged as needing a password
   change cannot mint tokens through a door that involves no password.

Every failure returns the **same** `invalid_grant` and the same sentence, with the
real reason in the log against a correlation id. That matters more than it looks:
the issuer is resolved *before* any signature is checked, because `iss` selects the
verification key — so a distinct "issuer not trusted" reply would let anyone with
client credentials enumerate a deployment's trusted issuers using assertions that
are not signed at all. Separating "subject not linked" from "account disabled"
would enumerate accounts. A test asserts that seven different causes produce one
identical response.

## The claim rules

Every one is a MUST in RFC 7523 §3:

| Claim | Rule |
|---|---|
| `iss` | Required. Selects the trusted provider. |
| `sub` | Required. Resolved against `(provider, subject)`, never `subject` alone. |
| `aud` | Required, must **name this issuer** (§3.1), and must name **only** this issuer. Accepts either spelling (RFC 7519 §4.1.3). |
| `exp` | Required, must be in the future, and must not be *"unreasonably far in the future"* — capped at one hour. |
| `iat` age | When present, the assertion must have been issued **within the last hour**. Not just unexpired. |
| `nbf` | Optional. Binding when present. |
| `iat` | Optional. Refused if in the future, or more than an hour old. |
| `jti` | Optional per the RFC and **required here** — see below. |

**The audience rule is the one worth understanding.** Without it, an assertion the
platform minted for some *other* relying party can be forwarded here and spent —
and the issuer, having done nothing wrong, cannot tell.

**The one-hour cap** is a ceiling on blast radius rather than a guess at issuer
behaviour. An assertion valid for a year is a bearer credential valid for a year,
whatever the issuer intended. No major platform needs longer: Google caps
service-account assertions at an hour and CI tokens are minutes.

**The age bound is separate from the expiry cap**, and it is the one people miss.
The cap bounds how far ahead an assertion reaches; it says nothing about how long
one may sit around before being spent. An assertion issued ninety minutes ago with
five minutes left passes the cap — and is exactly the shape of an assertion
recovered from a log or a crash report. So when `iat` is present, the assertion
must also have been *minted* within the hour.

**Only one audience.** This is stricter than the specification, which permits an
array. An assertion carrying `aud: ["https://us", "https://partner"]` is a working
credential at the partner too, and the partner can present it here and act as its
subject — replay protection does not catch it, because their use of it leaves no
record in our table. It is the confused-deputy form of the attack the audience
check exists to prevent.

## Replay protection, which the RFC does not require

RFC 7523 §6 is explicit: *"The specification does not mandate replay protection…
It is an optional feature, which implementations may employ at their own
discretion."*

Signari employs it. Without it an assertion is a password for the length of its
`exp` — anything that observes it once (a proxy log, an error report, a misrouted
request) holds a working credential until it expires.

The record is keyed by `(provider, jti)`, so two issuers cannot invalidate each
other's assertions by choosing colliding identifiers, and it carries the
assertion's own `exp` so the janitor can drop it exactly when it stops mattering.

**`jti` is required**, which is also stricter than the RFC.

An earlier version accepted assertions without one and simply skipped replay
protection for them, documented as a known limit. That was the wrong call: a
protection the documentation claims, silently absent for some inputs, with nothing
telling the operator which issuers are unprotected. Failing closed is the only
version of "replay protected" that is true.

The practical cost is nil — every issuer this grant is for emits `jti` — and an
issuer that does not gets a specific error in the log rather than silent exposure.

## What this grant deliberately does not do

**No refresh token.** A refresh token would outlive the assertion and turn a
short-lived, revocable statement into a long-lived credential — precisely the
property workload identity exists to avoid. The client can get another assertion
whenever it needs one, and that stays revocable at the issuer.

**No `openid` scope, and no ID token.** An ID token states that *we* authenticated
this person. We did not; a third party did. What `acr` and `amr` should then say is
a question RFC 7523 does not answer, so the scope is refused with that reason
rather than answered with invented claims.

**No session.** Nothing was signed in, so nothing can be signed out. The token
carries no `sid`, because inventing one would make logout appear to reach a token
it cannot.

## Key fetching

Provider keys are cached, with three behaviours worth knowing:

- A **rotation** is picked up automatically: an assertion naming a `kid` the cache
  does not hold forces one refresh.
- That refresh is **rate-limited**, so invented `kid`s cannot turn each token
  request into an outbound fetch at the provider.
- A **failed refresh keeps the keys already held**. A provider having a bad minute
  does not invalidate keys that are still theirs.
