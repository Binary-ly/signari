# User-Managed Access (UMA 2.0)

**UMA 2.0 Grant for OAuth 2.0 Authorization**, Kantara Recommendation,
7 January 2018.

UMA adds one indirection to OAuth. A client reaches a resource server without
sufficient authorization; the resource server asks *this* server what would be
needed and receives a **permission ticket**; the client presents that ticket at
the token endpoint and, if policy allows, receives an **RPT** scoped to exactly
those permissions.

The value is that the resource server never holds the policy. It says "someone
wants `read` on document 42" and is told yes or no by whoever owns document 42.

```
client → RS                                          (not enough authorization)
RS     → AS   POST /uma2/permission  {resource, scopes}          → ticket
RS     → client  401  WWW-Authenticate: UMA as_uri=…, ticket=…
client → AS   grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
              ticket=…                                            → RPT
client → RS   Authorization: Bearer <RPT>
```

## The decision comes from the existing policy engine

`internal/authzen` — the same policy decision point that answers
`/access/v1/evaluation`. UMA is a way of *asking*; it is not a second opinion
about who may do what. A separate engine behind this endpoint would be a second
answer to the same question, and the two would eventually disagree about
something that matters.

This is the same argument that has CIBA sharing the device flow's polling code.

## What is implemented

- The permission endpoint, `POST /uma2/permission`, authenticated as a
  confidential client
- The `uma-ticket` grant at the token endpoint
- Single-use permission tickets
- `request_denied` (403) when policy refuses, `invalid_grant` (400) when the
  ticket is unknown, expired or spent

## What is not, and is therefore not advertised

Pushed claims (`claim_token`), persisted claims tokens (`pct`), RPT upgrade
(`rpt`), and interactive claims gathering — which means **`need_info` and
`request_submitted` are never returned**. Those need a claims interaction
endpoint and a notion of a pending resource-owner decision; this server answers
from policy alone, immediately.

A client sending `claim_token`, `pct` or `rpt` is **refused rather than
ignored**. A client that pushes claims and receives a token reasonably concludes
the claims were weighed.

## `resource_type` is ours, and it is not in the specification

UMA identifies a resource by an opaque `resource_id` issued by the resource
registration endpoint (Federated Authorization §2), which is not implemented —
so nothing would tell us what *kind* of thing an id refers to, and our
authorization model is typed. `"document 42"` and `"invoice 42"` are different
things.

Requiring the type is the honest bridge. The alternative is a registration
endpoint whose only purpose is to remember a string.

## Single use is a MUST

§3.3.1: *"Permission tickets MUST be single-use. This prevents susceptibility to
a session fixation attack."* And the ticket is invalidated *"when the client
presents the permission ticket to either the token endpoint or the claims
interaction endpoint, or when the permission ticket expires, whichever occurs
first."*

Two consequences implemented deliberately:

1. The `UPDATE … WHERE redeemed_at IS NULL AND expires_at > now() RETURNING` is
   the read. The row is spent by the same statement that discovers it, so two
   concurrent presentations cannot both succeed.
2. **A refused request spends the ticket too.** Presentation invalidates, not
   successful presentation — otherwise a client can grind one ticket against
   policy while claims change underneath it.


What is here is the grant and the ticket, backed by a policy engine that already
existed. Whether the rest is worth building depends on whether anyone asks for
claims gathering, which is the part that makes UMA *user*-managed rather than
merely externalised authorization.
