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


## Re-review against Authorization API 1.0, August 2026

Version checked first: **1.0, published 11 January 2026, status Final**. Not a
draft, and the same version the implementation was written against.

### The defect: a failure did not short-circuit

§7.1.2.1, defining `deny_on_first_deny`:

> Deny on first denial (or failure). This semantic could be desired if a PEP
> wants to issue a few requests in a particular order, with any denial (**error**,
> or `"decision": false`) "short-circuiting" the evaluations call and returning
> on the first denial. This essentially works like the `&&` operator in
> programming languages.

The parenthetical is load-bearing: an **error** counts as a denial.

The batch loop had two failure branches — a malformed entry, and a decision that
errored. Both appended `"decision": false` and then `continue`d, which skipped
the short-circuit check sitting below them.

So a PEP using `deny_on_first_deny` to express `&&` — check A, then B, then C,
stop at the first no — had an errored A answered `false` and B and C evaluated
anyway. The array it received did not mean what the semantic promised, and the
`&&` analogy the specification offers was wrong for exactly the case a caller is
most likely to care about.

Both branches now assign a response and fall through, so the check is reached on
every path.

### Two tests, and only one of them works

`internal/authzen/semantics_test.go` models the decision rule and checks all
eight semantic/decision combinations. It is good documentation of the rule and
**it does not catch this bug** — it reimplements the logic rather than driving
the handler, so it passes whether or not the `continue` is there.

That is the pattern this review has repeatedly caught in other people's tests and
in its own: an assertion that cannot fail for the reason it was written.

So `internal/httpapi/authzsemantics_test.go` checks the shape of the loop
instead: no `continue` inside it, and the short-circuit still present. Narrow and
somewhat brittle, and it fails on the exact edit that caused the bug.

Demonstrated rather than claimed — with the `continue` restored:

```
--- FAIL: TestTheBatchLoopHasNoContinuePastTheShortCircuit
ok      signari.dev/engine/internal/authzen      (the logic test still passes)
```

Driving the real handler would need a Server with a database, a policy store and
an org — a large fixture to prove a `break` is reached. The shape check is the
cheaper instrument that actually detects the regression, and its own comment says
so.

### What came back clean

| Requirement | Where | Result |
|---|---|---|
| `policy_decision_point` identical to the identifier the well-known URI was derived from | §9.2.3 | built from the configured issuer, never the `Host` header |
| Top-level `subject`/`action`/`resource` inherited by each evaluation | §7.1.1 | field-by-field merge, so an entry setting only `resource.id` still inherits `resource.type` |
| The three semantic values spelled exactly | §7.1.2.1 | pinned by test |
| `execute_all` is the default | §7.1.2.1 | yes |

We are only ever a PDP, never a PEP, so §9.2.3's consumer-side obligation — *"If
these values are not identical, the data contained in the response MUST NOT be
used"* — does not apply to us. Recorded so that it is a decision rather than an
omission if an outbound PDP client is ever added.

---

## Adversarial re-review against AuthZEN 1.0 Final, August 2026

Fourth emerging standard put through the same treatment as Shared Signals and
WebAuthn: the published text re-read for every normative MUST, then hostile input
rather than one-field-wrong variations.

Two defects, both conformance rather than compromise, and one of them with a real
integrity consequence.

### 1. We refused the forward compatibility the specification requires

§10.1.1, verbatim:

> To ensure forward compatibility, receivers **MUST ignore unknown fields**
> present in request or response bodies.

And §4:

> Any updates to this API through subsequent revisions … MAY augment this API …
> Augmentation MAY include additional API methods or **additional parameters to
> existing API methods**.

So the specification both anticipates new parameters and requires receivers to
tolerate them. `Decode` called `json.Decoder.DisallowUnknownFields()` — the exact
inverse. Any PEP speaking a later revision, or sending a vendor extension, had
its request rejected with **400**, so the caller could not even learn whether it
would have been allowed.

**The rationale was sound and the mechanism was wrong.** The comment said a
caller sending `subjects` instead of `subject` "must be told, rather than
receiving a confident denial about a subject we never saw". True — but refusing
the whole body is not what tells them. With the stray field ignored, `subject` is
simply absent, and `Validate` answers with the error §10.1.1 requires for exactly
that case:

> If a required attribute in the information model is omitted, the server MUST
> return a "Bad Request" error

…which names the attribute that is **missing** rather than the one that was
misspelled, and is the more useful of the two messages.

What is given up: a typo in an *optional* field is now silent. That is the trade
the specification makes deliberately.

### 2. Duplicate JSON members — the decision and its audit record could disagree

Found by sweeping hostile bodies for a single invariant: *nothing that fails to
decode or validate may reach policy evaluation as though it were a well-formed
question.* One body got through.

```json
{"subject":{"type":"user","id":"alice"},"subject":{}, …}
```

Go's decoder **merges** a repeated object into the value it already decoded, so
the first occurrence's populated fields survive and this evaluates as `alice`. A
proxy, WAF or audit shipper that takes the **last** occurrence sees an empty
subject.

The PDP is the authority, so this is not a privilege escalation. It is worse in a
different way for this product: the decision and the record of the decision would
describe **different requests**, and proving what was authorised is the property
this system is organised around.

§10.1.1 supplies the principle:

> Implementations **MUST NOT** assume a particular ordering of JSON object
> members.

A body whose meaning depends on that ordering has no reading this server is
entitled to pick, which makes refusing the only correct answer. Duplicates are
now refused at **any depth** — top level, inside an entity, inside `context`,
inside an array element — by a token walk, because a second unmarshal into
`map[string]any` would collapse the duplicates before they could be seen.

This is the same rule, for the same reason, as the duplicate-parameter check the
pushed authorization request endpoint has had since it was written. The principle
was already held in this codebase; it had simply not been applied here.

**And it generalised.** The Security Event Token receiver decoded its payload
with a plain `json.Unmarshal` too. That one is not attacker-craftable — the
payload is signed, so producing an ambiguous SET needs the transmitter's key, and
a transmitter trusted to revoke sessions could do worse things directly. But the
divergence argument is unchanged: we would act on Go's reading of a duplicated
`aud` while a SIEM reading the same bytes recorded another, and disagreeing with
your own audit trail is the failure this product exists to prevent.

The rule now lives in `internal/jsonstrict` and is called from both, rather than
copied. A check this subtle re-implemented per package is one that drifts: one
copy gains a depth limit or loses the array case, and nothing says so.

### What the sweep confirmed

| Hostile body | Outcome |
|---|---|
| Empty, truncated, `[]`, `null`, a bare string or number | refused |
| Entities as scalars or arrays rather than objects | refused |
| Any required attribute missing or empty | 400, **not** a denial |
| Unknown fields, top level and nested | **ignored** (§10.1.1) |
| Duplicate members at any depth | refused |

"400, not a denial" is deliberate and worth keeping visible: *no* and *that
question was malformed* are different answers, and a PDP that returns `false` for
both teaches callers that a denial might just mean they sent the wrong shape.

### Fail-closed, verified rather than asserted

Every path through `decide` that is not an explicit grant returns
`Decision: false`, and every error returns no decision at all — the handler turns
it into a 500. A condition that cannot be evaluated because no live session was
named is refused rather than assumed satisfied: *a rule demanding a second factor
must not be satisfied by the absence of evidence.*

Four mutations were run against the two fixes and the required-attribute check.
All four were caught.


### 3. `resource.id` was not required, though the specification marks it REQUIRED

Found in a later pass, and worth recording precisely because the section above
already claimed to have re-read "every normative MUST". It had not caught this
one.

Authorization API 1.0 (Final, 11 January 2026), Resource:

> `id`: REQUIRED. A string value containing the unique identifier of the
> Resource, scoped to the `type`.

`Request.Validate` checked `subject.type`, `subject.id`, `action.name` and
`resource.type`, and deliberately not `resource.id`. There was a test asserting
the omission, with a stated reason: "a search or a type-level question does not
have one, and demanding it would refuse valid requests."

Half of that reason is answered by our own code — a search arrives as a
`SearchRequest`, a different type that never reaches this validation. The other
half is answered by the specification, which puts type-level questions in the
Resource Search API rather than in an evaluation.

**This was not a security defect, and it would be easy to write it up as one.**
`store.HoldsAny` compares `object_id` for equality, so a request with no resource
id matches no relation and the answer is a denial. Nothing was let through.

What was wrong is narrower and is a rule this codebase states in the handler four
lines above the check:

> 400, not a denial. "No" and "that question was malformed" are different
> answers, and a PDP that returns false for both teaches callers that a denial
> might just mean they sent the wrong shape.

A caller that dropped `resource.id` — a PEP bug, a template that did not
interpolate — received `decision: false` and no indication that it had asked a
malformed question. It would read as "access denied" and be handled as such.

Now a 400 naming the field. Both the general validation test and a dedicated one
fail if the check is removed.

## Currency of the emerging standards, August 2026

Checked against the publishers rather than against notes, because a review is
only as current as the text it was written from:

| | version we implement | published | verdict |
|---|---|---|---|
| AuthZEN Authorization API | 1.0 | **Final, 11 Jan 2026** | current |
| SD-JWT VC | draft-18 | draft-18, 3 Aug 2026 | current |
| Transaction Tokens | draft-11 | draft-11, 30 Jul 2026 (WG Last Call) | current |
| Attestation-Based Client Auth | draft-10 | draft-10, 6 Jul 2026 | current |
| FAPI 2.0 Security Profile | Final 22 Feb 2025 | unchanged, no errata | current |

All five are the current published text. The `internal/authzen` package recorded
no version string at all before this pass, which is how a Final specification
could supersede the Implementer's Draft it was written against without anything
noticing.
