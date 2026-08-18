# The authorization layer

Answering "may Alice edit document 42?" — the
[OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html),
Final on 12 January 2026.

```
POST /access/v1/evaluation
POST /access/v1/evaluations
POST /access/v1/search/subject
POST /access/v1/search/resource
POST /access/v1/search/action
```

Callers authenticate with a `pdp` outpost token, which is scoped to one
organisation. The organisation comes from the **token**, never from the request —
a body-supplied org id is a body-supplied answer to "whose data may I ask about".

## Why this belongs in the identity provider

A standalone policy decision point is *told* about the subject by the calling
application. It has to be: it has no other source. So an application that says
"this user is in group finance, and they used MFA" is believed, and every
authorization decision is only as trustworthy as the least careful service that
makes one.

We already know. Groups come from our directory. Whether a second factor was
proved comes from the `amr` on the session **we** issued. Device posture comes
from evidence that was actually checked. The application is not asked, so it
cannot inflate them.

That is the difference between a decision about a person and a decision about a
claim, and it is not something a separate PDP can retrofit.

Verified: an application passing a session that proved only a password is
refused for an action requiring MFA; the same subject with a session that proved
`otp` is allowed; a **revoked** session supplies no facts at all.

## The model

```yaml
types:
  document:
    relations:
      owner: []
      editor: [owner]      # an owner is also an editor
      viewer: [editor]     # an editor is also a viewer
    permissions:
      read:   [viewer]
      write:  [editor]
      delete: [owner]
    require:
      delete: {mfa: true}
tests:
  - name: an owner may read, through editor and viewer
    subject: user:alice
    action: read
    resource: document:1
    relations: [owner]
    allow: true
```

```sh
signari authz set-model -org <uuid> -model-file model.yaml
```

**Parsing runs the tests.** A model whose own examples fail does not load, so it
cannot be stored and discovered wrong in production. Same rule as the access
policy: a security control nobody can check is a security control nobody has
checked.

Refused at parse time, each because it would otherwise load and be quietly wrong:

| | |
|---|---|
| A permission granted by no relation | Not a restriction — a permission nobody can ever hold. Almost always a half-finished edit |
| A permission granted to a relation that does not exist | Grants to nobody, reads like it grants to somebody |
| A condition on an action that does not exist | Never runs, reads as a restriction that is in force |
| A relation cycle | Refused rather than bounded: a bound turns a broken model into a slow one instead of a rejected one |
| A misspelled key | `permisions:` silently dropped leaves a type granting nothing, which at a glance looks exactly like one granting everything |

## Conformance review against the Final spec, August 2026

Reviewed against the **full text** of Authorization API 1.0, not a summary. Two
defects found:

| Finding | Section | Status |
|---|---|---|
| **Search results were silently truncated.** Capped at 1000 with no `next_token`. §8.2.2: *"if a response does not contain the entire result set, it MUST include this object"*. A caller with 1001 accessible documents was told about 1000 and had no way to know — for an authorization search that is worse than an error, because a truncated answer looks complete | §8.2.2 | **fixed** |
| **No Policy Decision Point metadata.** §9 defines `/.well-known/authzen-configuration`, whose `policy_decision_point` identifier exists *"to prevent Policy Decision Point mix-up attacks"* | §9 | **added** |

Checked and already correct: the information model (§5), evaluation request and
response (§6), batch defaults and semantics (§7), transitive search through
groups (§8.1 RECOMMENDED — we expand group grants to members), the `type`/`id`
vs `name` item shapes (§8.4–8.6), `X-Request-ID` (§10.1.3), and error status
codes (§10.1.2).

### Pagination

Keyset, not `OFFSET`. `OFFSET` re-reads and re-sorts everything skipped, so the
last page of a large set costs the most and a row inserted mid-walk shifts every
later page. The token is the last id of the previous page, base64url so it is
**opaque** as §8.2 requires — a caller who could construct one by hand could
start walking somebody else's result set from the middle.

One row more than asked for is fetched, which is how "is there another page"
is *known* rather than guessed. Guessing wrong gives either an empty final page
or, far worse, a silent truncation.

Verified live:

```
page 1: doc-1,doc-2,doc-3   next_token=ZG9jLTM…
page 2: doc-4,doc-5,doc-6   next_token=ZG9jLTY…
page 3: doc-7              next_token='' (end)
total 7 across 3 pages
```

### PDP metadata

```
GET /.well-known/authzen-configuration
```

Lists the five endpoints — their presence *is* the capability declaration, since
the spec says "the absence of any of these parameters is sufficient for the PEP
to determine that the PDP is not capable".

`policy_decision_point` is built from the configured issuer, **never from the
request's Host header**. §9.2.3 requires it to match the identifier the
well-known URI was derived from, and a Host an attacker controls is exactly how
a mix-up attack starts.

## Conditions, and a trust boundary you can see

```yaml
require:
  post:
    # Verified by Signari. A caller cannot influence any of these.
    mfa: true
    subject_active: true
    email_verified: true
    any_group: [finance]
    max_risk: 30
    time:
      days: [mon, tue, wed, thu, fri]
      from: "09:00"
      to: "17:00"
      zone: "Europe/London"

    # Asserted by the caller. Worth exactly your trust in that caller.
    asserted:
      resource:
        classification: [internal, restricted]
      networks: ["10.0.0.0/8"]
```


Verified live: with the `owner` relation intact and the caller asserting
`"subject_active": true` in the resource properties, deactivating the account in
our directory flips the decision to deny. The forgery is ignored because the
requirement is never read from the caller's half.

The cost is that this is not a programming language. That is the trade:


### Time windows are on our clock

A time restriction an application can lie about is a comment. `zone` is
**required** whenever `from`/`to` are set — "09:00" without one is nine o'clock
somewhere. Windows may wrap midnight (`22:00`–`06:00` is one window, not none).

A model with a time window **will not load unless its tests pin the clock** with
`at:`. A test that passes or fails depending on when CI runs is worse than no
test.

### An omitted assertion is not a satisfied one

If a policy requires `classification` and the caller simply doesn't send it, the
decision is **deny**. Treating "the caller did not mention it" as "it is fine"
means a caller bypasses any rule by leaving the field out, which is the easiest
bypass there is.

### Refused at parse time

A zone that does not exist, a CIDR that does not parse, a day that is not a day,
a `HH:MM` that is not one, an `asserted:` block requiring nothing, a resource
requirement allowing no values. At evaluation time the only safe response to a
broken condition is to refuse — and a typo that silently denies everything is
worse than one that refuses to deploy.

## Relations, not roles

```sh
signari authz grant  -org <uuid> -principal user:alice@example.com -relation owner -object document:42
signari authz grant  -org <uuid> -principal group:finance -relation viewer -object document:99
signari authz check  -org <uuid> -principal user:alice@example.com -action read -object document:42
signari authz revoke -org <uuid> -principal user:alice@example.com -relation owner -object document:42
signari authz show-model -org <uuid>
```

A relation is `(subject, relation, object)`. Roles are the special case where the
object is the whole application, and they collapse the moment somebody asks "who
can edit **this** document" — which is the question that actually gets asked. The
shape is Zanzibar's because that model has held up.

Relations compose transitively: `owner` grants `read` through editor → viewer,
without anybody writing that edge. Expansion goes **upward only** — `delete:
[owner]` does not become "every viewer may delete".

Grants can expire (`expires_at`), and an expired grant stops working **at the
moment it expires**, because the check is in the query rather than in a sweep. A
janitor-swept expiry means temporary access lasts until the next pass.

Group grants are resolved by us: the caller does not say which groups the subject
is in. `search/subject` expands a group grant to its **members**, because "who can
read this" is a question about people and answering `group:finance` is true and
useless.

## Things the wire format gets wrong elsewhere

**A denial is `200 {"decision": false}`.** Not 403. The HTTP status says whether
the request was processed; the body says what the answer was. A PDP that returns
403 for "no" is indistinguishable from one refusing to talk to the caller at all,
so a client cannot tell an authorization decision from its own credentials having
expired — and either retries, or treats it as a transport error and falls back to
allowing.

**A malformed request is `400`, not a denial.** "No" and "that question was
malformed" are different answers. Returning false for both teaches callers that a
denial might just mean they sent the wrong shape, after which nobody trusts a
denial. Unknown JSON fields are an error for the same reason: a caller who sends
`subjects` is told, rather than receiving a confident denial about a subject we
never saw.

**Action search results carry `name`, not `type`/`id`** (spec §8.6.2), unlike
subject and resource results (§8.5.2). Getting this wrong means a client looking
for `name` finds nothing. Caught by reading the spec's own examples rather than
assuming the shapes were uniform.

**`X-Request-ID` is echoed** when the caller sends one.

## Two reasons, never one

```json
{
  "decision": false,
  "context": {
    "reason_admin": {"403": "the subject holds owner but the action requires a second factor, which this request did not show"},
    "reason_user":  {"403": "You need to sign in again with additional verification."}
  }
}
```

Collapsing them means either the user is told which policy refused them — which
tells an attacker what to change — or the administrator is told "insufficient
privileges", which tells them nothing. Every PDP that logs one string has picked
one of those failures.

## Batch

```json
{
  "subject":  {"type": "user", "id": "alice@example.com"},
  "resource": {"type": "document", "id": "42"},
  "options":  {"evaluations_semantic": "deny_on_first_deny"},
  "evaluations": [{"action": {"name": "read"}}, {"action": {"name": "delete"}}]
}
```

Top-level fields are **defaults**, merged field by field — an entry naming only
`resource.id` still inherits `resource.type`. An all-or-nothing merge would leave
it typeless and produce a confident denial about a resource of no kind.

Short-circuit semantics stop **after** appending the deciding entry, so the answer
that ended the batch is in the response. Bounded at 256 entries: an unbounded
batch is a denial of service with a JSON array in front of it.

One malformed entry does not fail the batch — the others are answerable, and
refusing all of them hides which one was wrong.

## No model means nothing is permitted

An organisation with no model denies everything, with an administrator reason
naming the command to fix it. An unconfigured authorization layer that says *yes*
is worse than no authorization layer at all, because the application believes it
has one.
