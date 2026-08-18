# Rich Authorization Requests (RFC 9396)

`scope` is a list of bare strings, so everything an API needs to say about a
permission has to be encoded into one of them. That works until a permission has
structure — *move £500 from this account to that one*, *sign this document*,
*issue this credential* — at which point deployments invent
`payment:500:GB123:GB456` and every party has to agree how to split it.

`authorization_details` gives the permission a shape instead: a JSON array of
typed objects saying what may be done, where, and to what.

```
GET /oauth2/authorize
  ?response_type=code&client_id=…&redirect_uri=…
  &authorization_details=[{"type":"payment_initiation",
                           "actions":["initiate","status"],
                           "identifier":"acct-1"}]
```

## Why this closed two gaps at once


- **OWASP ASVS 5.0 V10.3.2** requires the resource server to enforce
  `authorization_details` "if present". A parameter that is never issued is
  vacuously enforced, which is not the same as satisfied.
- **OID4VCI §6.2** prefers `authorization_details` over scope for naming which
  credential configurations a token authorises.

## The rule that makes this parser different from every other one here

§5 requires the authorization server to **refuse** an object *"of known type but
containing unknown fields"*.

That is the opposite of the rule this codebase follows elsewhere. AuthZEN
§10.1.1 makes **ignoring** unknown fields a MUST, and `internal/authzen` does
exactly that — a defect fixed earlier in this same review.

Both are right, and the difference is what the fields mean. An unknown field in
an authorization *query* is a hint the decision did not need. An unknown field in
an authorization *detail* is a **permission**: ignoring it either grants access
the resource owner never saw on the consent screen, or withholds one the client
believes it obtained. Neither failure is visible to anybody at the time.

All five of §5's conditions are enforced, each with its own test, because an
implementation that checks four of them refuses four kinds of bad request and
grants the fifth:

| §5 condition | Rejected |
|---|---|
| unknown authorization details type | ✅ |
| known type containing unknown fields | ✅ |
| fields of the wrong type | ✅ |
| fields with invalid values | ✅ (empty values; see the limit below) |
| missing required fields | ✅ |

## Type registration, which the RFC leaves open

§10: *"The registration of authorization details types with the AS is outside the
scope of this specification."* So this is our answer to a question the RFC
deliberately does not settle.

```sh
signari rar register -org <uuid> -type payment_initiation \
  -fields actions,identifier -required actions,identifier \
  -describe "Initiate and check a payment"

signari rar allow -client-id wallet -type payment_initiation
signari rar list
```

Two deliberate constraints:

- **Only §2.2's common data fields** (`locations`, `actions`, `datatypes`,
  `identifier`, `privileges`) may be declared. A field outside that set could
  never be validated, and a registration that cannot be validated is one that
  accepts anything.
- **Registration declares fields, not value schemas.** §2.2 says the allowable
  values "are determined by the API being protected", which this server cannot
  know. Validating emptiness and JSON type is what is honestly checkable;
  pretending to a schema would look stricter than it is.

And a client must be allowed a type explicitly. An allow-list rather than "any
registered type", for the same reason group release is one: a client that can
request every permission a deployment has ever defined is a client whose consent
screen can say anything.

**A type this client may not request is an *unknown* type** (§5's first
condition), not a known one quietly dropped. The distinction is the whole point:
a dropped permission produces a token weaker than the consent screen described,
and nobody finds out until something fails in production.

## Narrowing at the token endpoint

§6 lets a token request ask for less than was granted. §6.1 is unusually candid
that no standard comparison exists — *"the semantics of the fields in the
authorization_details will be implementation specific"* and *"an AS should not
rely on simple object comparison in most cases"*.

So ours implements the one comparison that is safe without knowing the API:
**subset containment**. A requested detail is allowed when a granted detail of the
same type contains every one of its values, field by field, with `identifier`
compared for equality since it is a scalar. That can only ever narrow, never
widen, which is the property §6 protects. Anything cleverer would be this server
guessing at semantics it was explicitly told it does not have.

## What is returned, and from where

§7: *"the AS MUST also return the authorization_details as granted by the
resource owner and assigned to the respective access token."*

They are read back **from the authorization code**, never from a parameter the
client resends at the token endpoint — a client that could resend them is a
client that could change them. They are carried on the refresh family too, so a
refreshed token does not silently differ from the first one.

A grant with no rich permissions omits the field entirely rather than sending an
empty array: a client that never asked should not have to distinguish *"you got
nothing"* from *"this server does not do that"*.

## Advertised only once it works

§10's `authorization_details_types_supported` is populated from what is actually
registered, so a deployment with no types advertises nothing. The same rule this
project applies to `registration_endpoint`: a capability named in a metadata
document is one a client will try to use.

## Limits, stated plainly

- **Value semantics are not validated**, only presence, JSON type and emptiness.
  The RFC says values are the API's business; a resource server still has to
  enforce what the values mean.
- **Enrichment (§7.1)** — the AS adding fields to a granted detail — is not
  implemented.
- **Consent rendering** shows the type, actions and identifier. §3's requirement
  that the AS "MUST present the merged set of requirements" when scope and
  authorization_details are combined is met by showing both, not by merging them
  into one sentence.

---

# Second pass: the lifecycle, not the endpoint

The first pass built RFC 9396 and reviewed it endpoint by endpoint. Every
endpoint was correct. The feature was still broken, and the reason is worth
recording because it generalises: **a per-endpoint review cannot see a defect
that lives between two endpoints.**

Method: extract every normative requirement from RFC 9396 and follow the granted
details through the whole lifecycle — authorize → consent → token → refresh →
resource server — rather than checking each handler in isolation.

## The defect: the constraint expired at the first refresh

The authorization stored the granted details. The token response returned them.
The *refresh* dropped them: `mintFromGrant` never read them back, so the second
access token carried none.

Nothing failed. No error was logged, no test broke, and the client kept working —
because a resource server that sees no `authorization_details` cannot distinguish
*"this grant was never constrained"* from *"the constraint was lost on the way
here"*. The natural fallback is `scope`, which is exactly the coarse permission
RAR exists to replace. A grant for **one payment of a specific amount to a
specific account** silently became **may initiate payments** after one rotation,
with no moment at which anything looked wrong.

Migration 0080 had already added `authorization_details` to
`core.refresh_token_families`, with a comment stating the details

> "have to survive a refresh, or the second token silently carries different
> permissions from the first."

No code ever wrote or read that column. The schema was right, the justification
was right, and the implementation was absent — the inverse of the pattern this
codebase has hit before, where a justification outlived the code it described.
Here the justification arrived before the code and nothing ever checked that the
code caught up. A comment asserting a property is not a test of it.

## Three more requirements, all unmet

**§9 (MUST): "the AS MUST make this data available to the RS."** Neither the
access token nor introspection carried the details. §7's token-response field
goes to the *client* — the party being constrained — while the resource server
that has to do the constraining never sees a token response. Easy to believe §7
discharges §9; it does not. Now a top-level `authorization_details` JWT claim
(§9.1), filtered by `locations` so one RS does not learn what was granted for
another, and a top-level member of the introspection response (§9.2).

**§3.1 (MUST): "the AS MUST present the merged set of requirements."** The
consent screen listed scopes only. A user approving a specific transfer saw
`openid profile` — the single thing RAR exists to make explicit was the one thing
not shown.

**Consent could be pre-approved, which is worse than not showing it.** Consent is
recorded per scope name. A detail carries the particulars of *one transaction*,
so a user who once approved the scope `payments` approved a capability and never
a payment. A stored grant satisfying a detail would auto-approve every later
transfer — any amount, any account — with no screen at all. Details now always
prompt, checked *before* the first-party exemption, since a trusted relationship
cannot vouch for a transaction that did not exist when it was established.

## Mutation results

Every fix was reverted in turn to check the new tests can actually fail:

```
CAUGHT   RS never receives the granted details
CAUGHT   details dropped at refresh (the original defect)
CAUGHT   refresh family never persists the grant
CAUGHT   consent screen hides the transaction
CAUGHT   details satisfied by prior scope consent
CAUGHT   introspection omits the details
CAUGHT   conveyed under the wrong member name
CAUGHT   unlocated detail silently dropped
CAUGHT   another RS's details disclosed
```

The last is the one most likely to have been written wrong. `locations` is
OPTIONAL under §2.2, so an absent value means *unspecified*, not *applies
nowhere*; filtering those out would have reintroduced the original bug through
the door built to fix it.

## What this says about the earlier reviews

The eleven protocol reviews before this one were endpoint-shaped. This defect was
invisible to that shape — every handler was individually correct, and the grant
degraded between them over time. Reviews that follow one grant through its whole
life, including the parts that happen an hour later, find a class of defect that
reading handlers cannot.
