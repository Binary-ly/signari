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
