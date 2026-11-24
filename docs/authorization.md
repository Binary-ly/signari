# The authorization layer

## Introduction

Signing in tells an application who somebody is. It does not tell the
application what that person may do. Acme's wiki still has to decide whether
Ada may edit a page, and whether she may delete one.

Signari can answer those questions for an application. The application asks
"may this person take this action on this resource?", and Signari answers yes or
no. It decides from relations you store, such as "Alice is an owner of document
42". It also decides from what Signari knows itself: the person's groups, and the
session they signed in with.

The question and the answer follow the
[OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html),
Final on 12 January 2026. You describe your relations in a model file, install
it with `signari authz set-model`, and grant relations with `signari authz grant`
or through the Admin API.

> [!NOTE]
> The [access policy](policy.md) decides who reaches an application at all. This
> page is about what a person may do inside one.

## Asking a question

An application asks its questions at these five addresses:

```
POST /access/v1/evaluation
POST /access/v1/evaluations
POST /access/v1/search/subject
POST /access/v1/search/resource
POST /access/v1/search/action
```

The first asks one question, and the second asks several at once. The three
searches ask who may do something, what somebody may do it to, and which
actions are allowed.

The specification has a name for each side. The application that asks, and then
acts on the answer, is the "policy enforcement point" (PEP). Signari, which
decides, is the "policy decision point" (PDP).

Callers authenticate with a `pdp` outpost token, which is scoped to one
organisation. You make one with `signari outpost create -kind-outpost pdp`, as
for any [outpost](outposts.md), and give its token to the application that asks.

The organisation comes from the **token**, never from the request. An
organisation ID supplied in the body would be a body-supplied answer to "whose
data may I ask about".

## Why this belongs in the identity provider

A standalone policy decision point is *told* about the subject by the calling
application. It has to be, because it has no other source. So an application
that says "this person is in group finance, and they used multi-factor
authentication (MFA)" is believed. Every authorization decision is then only as
trustworthy as the least careful service that makes one.

Signari already knows. Groups come from its own directory. Whether a second
factor was proved comes from the `amr` on the session **Signari** issued. That
claim lists how the person proved who they are. Device posture comes from
evidence that was actually checked. The application is not asked, so it cannot
inflate them.

That is the difference between a decision about a person and a decision about a
claim. It is not something a separate PDP can retrofit.

This was verified against a running Signari:

- An application passing a session that proved only a password is refused for
  an action requiring MFA.
- The same subject with a session that proved `otp` is allowed.
- A **revoked** session supplies no facts at all.

## The model

A "model" names your kinds of object, the relations a person can hold on each,
and the permissions each relation brings. This model has documents with owners,
editors and viewers, and one test:

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

In this example, a viewer may read, an editor may write, and an owner may
delete. Deleting also requires a second factor. The test says that an owner may
read, because an owner is an editor and an editor is a viewer.

Test the model, then install it for an organisation:

```sh
signari authz test -model-file model.yaml               # no database, for CI
signari authz set-model -org <uuid> -model-file model.yaml
```

**Parsing runs the tests.** A model whose own examples fail does not load, so it
cannot be stored and discovered wrong in production. It is the same rule as the
access policy: a security control nobody can check is a security control nobody
has checked. `authz test` is that parse with nothing behind it, so passing it
and loading are the same statement.

These are refused at parse time, each because it would otherwise load and be
quietly wrong:

| | |
|---|---|
| A permission granted by no relation | Not a restriction — a permission nobody can ever hold. Almost always a half-finished edit |
| A permission granted to a relation that does not exist | Grants to nobody, reads like it grants to somebody |
| A condition on an action that does not exist | Never runs, reads as a restriction that is in force |
| A relation cycle | Refused rather than bounded: a bound turns a broken model into a slow one instead of a rejected one |
| `parent->viewer` through a relation the type does not have, or to one no type has | Would read as an inheritance and carry nothing |
| `also` or `except` on an action that does not exist, or naming a relation that does not | Same as a condition: never runs, reads as in force |
| A misspelled key | `permisions:` silently dropped leaves a type granting nothing, which at a glance looks exactly like one granting everything |

## Relations held through something else

A relation does not have to name the person. A document in a folder, a team and
a deny list all need a relation held through something else. This model shows
the four things the model and the rows can say:

```yaml
types:
  folder:
    relations:
      owner: []
      viewer: [owner]
  document:
    relations:
      parent: []                      # its subject is the folder
      owner: []
      banned: []
      viewer: [owner, parent->viewer] # a viewer of the parent is a viewer here
      cleared: []
    permissions:
      read:   [viewer]
      delete: [owner]
    except:
      read: [banned]                  # whatever else they hold
    also:
      delete: [cleared]               # on top of the permission
  team:
    relations:
      member: []
```

The first two commands put document 42 in the `reports` folder, and make the
`eng` team's members its viewers. The third checks whether Alice may read it:

```sh
signari authz grant -org <uuid> -principal folder:reports -relation parent -object document:42
signari authz grant -org <uuid> -principal team:eng#member -relation viewer -object document:42
signari authz check -org <uuid> -principal user:alice@example.com -action read -object document:42
```

**`parent->viewer`** means whoever holds `viewer` on the document's parent holds it
here. The row with relation `parent` names the folder as its subject, and `viewer`
is looked for on the folder's own type. So a hierarchy is rows, not model.

**`team:eng#member`** as a subject is everybody who holds `member` on `team:eng`.
`group:finance#member` is a directory group's members, read from the groups the
person is in, as `group:finance` always was.

**`also`** asks for one of its relations on top of the permission. **`except`**
refuses anybody holding one of its relations, whatever else they hold. Either
can be reached through something else in the same way, and a model's own tests
see them both.

A direct grant is answered as it always was, in one read, and a batch of a
hundred is still five statements. Only somebody with no row of their own costs a
walk. Even then, it costs one only where the model has a "rewrite" or the object
has a "set" on it. A rewrite is an entry such as `parent->viewer`, and a set is a
subject such as `team:eng#member`.

The walk reads one statement a level, with the whole level in it. So its cost is
the depth of the graph, not the number of paths through it. It visits nothing
twice, which makes a folder that is its own parent an answer rather than a hang.
Only the data can make that loop, so the model cannot refuse one. An expired link
carries nothing, at any depth.

**Past sixteen levels, or two thousand rows in one, is an error and not a no.**
The question was not answered. So the caller is told the decision could not be
made, as for any other failure, rather than told something false about the graph.

A search has to agree with a decision, and a document held through its folder
has no row naming the person. So where a model walks, or an organisation has any
set at all, a search takes every candidate and decides each. It is the same
answer and slower, bounded per page as every search is.

`authz check` and `authorization/explain` show the way a relation was reached:

```
ALLOWED user:bo may read document:42
  via relation: viewer, held by folder:a#owner
  through: document:42#viewer <- folder:reports#viewer <- folder:a#owner
```

## Conformance review against the Final spec, August 2026

This review read the **full text** of Authorization API 1.0, not a summary. It
found two defects:

| Finding | Section | Status |
|---|---|---|
| **Search results were silently truncated.** Capped at 1000 with no `next_token`. §8.2.2: *"if a response does not contain the entire result set, it MUST include this object"*. A caller with 1001 accessible documents was told about 1000 and had no way to know — for an authorization search that is worse than an error, because a truncated answer looks complete | §8.2.2 | **fixed** |
| **No Policy Decision Point metadata.** §9 defines `/.well-known/authzen-configuration`, whose `policy_decision_point` identifier exists *"to prevent Policy Decision Point mix-up attacks"* | §9 | **added** |

These were checked and already correct: the information model (§5), evaluation
request and response (§6), and batch defaults and semantics (§7). So was
transitive search through groups (§8.1 RECOMMENDED; Signari expands group grants
to members). So were the `type`/`id` vs `name` item shapes (§8.4–8.6),
`X-Request-ID` (§10.1.3), and error status codes (§10.1.2).

### Pagination

Search results are paged by keyset, not by `OFFSET`. `OFFSET` re-reads and
re-sorts everything skipped. So the last page of a large set costs the most, and
a row inserted mid-walk shifts every later page.

The token is the last ID of the previous page, in base64url so that it is
**opaque**, as §8.2 requires. A caller who could construct one by hand could
start walking somebody else's result set from the middle.

One row more than asked for is fetched, which is how "is there another page" is
*known* rather than guessed. Guessing wrong gives either an empty final page or,
far worse, a silent truncation.

This was verified against a running Signari, paging through seven documents:

```
page 1: doc-1,doc-2,doc-3   next_token=ZG9jLTM…
page 2: doc-4,doc-5,doc-6   next_token=ZG9jLTY…
page 3: doc-7              next_token='' (end)
total 7 across 3 pages
```

### PDP metadata

Signari publishes its PDP metadata at this address:

```
GET /.well-known/authzen-configuration
```

It lists the five endpoints. Their presence *is* the capability declaration. The
spec says "the absence of any of these parameters is sufficient for the PEP to
determine that the PDP is not capable".

`policy_decision_point` is built from the configured issuer, **never from the
request's Host header**. The spec requires it to match the identifier the
well-known URI was derived from (§9.2.3). A Host an attacker controls is exactly
how a mix-up attack starts.

## Conditions, and a trust boundary you can see

A permission can carry conditions under `require`. Signari checks some of them
itself, and the caller asserts the rest. The file keeps the two apart, so you can
see where the trust boundary is:

```yaml
require:
  post:
    # Verified by Signari. A caller cannot influence any of these.
    mfa: true
    subject_active: true
    email_verified: true
    any_group: [finance]
    user_attributes:           # declared and not personal, as policy.md says
      cost_centre: ["4100", "4200"]
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

This was verified against a running Signari. The `owner` relation was intact, and
the caller asserted `"subject_active": true` in the resource properties.
Deactivating the account in Signari's directory still flipped the decision to
deny. The forgery is ignored because the requirement is never read from the
caller's half.

The cost is that this is not a programming language. That is the trade.

### Time windows are on our clock

A time restriction an application can lie about is a comment. `zone` is
**required** whenever `from`/`to` are set, because "09:00" without one is nine
o'clock somewhere. Windows can wrap midnight: `22:00`–`06:00` is one window, not
none.

A model with a time window **will not load unless its tests pin the clock** with
`at:`. A test that passes or fails depending on when continuous integration (CI)
runs is worse than no test.

### An omitted assertion is not a satisfied one

If a policy requires `classification` and the caller does not send it, the
decision is **deny**. Treating "the caller did not mention it" as "it is fine"
means a caller bypasses any rule by leaving the field out. That is the easiest
bypass there is.

### Refused at parse time

Signari refuses these when it parses the model:

- a zone that does not exist;
- a CIDR (Classless Inter-Domain Routing) range, such as `10.0.0.0/8`, that does
  not parse;
- a day that is not a day;
- a `HH:MM` that is not one;
- an `asserted:` block requiring nothing;
- a resource requirement allowing no values.

At evaluation time, the only safe response to a broken condition is to refuse.
And a typo that silently denies everything is worse than one that refuses to
deploy.

### What the session showed

A condition can also ask what the person's sign-in showed about their device and
their risk:

```yaml
types:
  document:
    require:
      read: {max_risk: 10}
      edit: {device_managed: true}
```

`device_managed`, `device_compliant` and `max_risk` read what a sign-in showed,
kept with the session it made. A decision comes from an application, with no
browser behind it to ask. Pass the session in the request, as for `mfa`:

```json
{"subject": {...}, "action": {...}, "resource": {...}, "context": {"sid": "<sid>"}}
```

With no live session of that subject named, all three refuse. No score is not a
low one, and no device is not a managed one.

The score runs from 0 to 100 and has two rungs today. **50** is the first sign-in
from a country, for a person whose history is elsewhere. **80** is a sign-in that
could not have followed the last one in time, which is
[impossible travel](impossible-travel.md).

Both need a GeoIP source (see [configuration](configuration.md)). Without one, or
with no history, it is 0. A cap below 50 refuses both, and a cap from 50 to 79
refuses only the second.

These are what was true **at sign-in**. A session does not get riskier, and a
device that falls out of compliance afterwards is not noticed until the next
sign-in. For a check on each request, the access policy
[asks the device itself](device-posture.md).

## Relations, not roles

These commands grant, check and revoke relations, show the model, and list and
expand what is stored:

```sh
signari authz grant  -org <uuid> -principal user:alice@example.com -relation owner -object document:42
signari authz grant  -org <uuid> -principal group:finance -relation viewer -object document:99
signari authz grant  -org <uuid> -principal user:bob@example.com -relation viewer -object document:42 -expires-in 72h
signari authz check  -org <uuid> -principal user:alice@example.com -action read -object document:42
signari authz revoke -org <uuid> -principal user:alice@example.com -relation owner -object document:42
signari authz show-model -org <uuid>
signari authz list   -org <uuid> -principal user:alice@example.com
signari authz list   -org <uuid> -object document:42
signari authz expand -org <uuid> -action read -object document:42
```

`check`, `list`, `expand` and the Admin API's `authorization/explain` answer from
relations, the same way a decision walks them. They start from the subject as
asked about, then the person that resolves to, then their groups. They name what
a session would also have to show, rather than guess at it. They do not call a
[provider](glossary.md#provider).

A grant with `-expires-in` stops counting at that moment. The expiry is checked
in the query that reads it, rather than swept up later. So temporary access is
temporary without anyone having to remember it. Granting the same tuple again
replaces the expiry, and granting it without `-expires-in` removes it.

A grant to an address or a username means the person who held it. When they
change it, the grant moves to their ID. So the access stays with them, and
whoever takes the old name up next starts with nothing. Deleting a person, or a
group, takes their grants with them.

The Admin API stores the model, and grants, revokes and lists relations, the
same way. It does so under `/admin/organizations/{orgID}/authorization-model` and
`/admin/organizations/{orgID}/relations`; see [the Admin API](admin-api.md).

An application can keep its own relations, such as writing an owner when
somebody creates a document. It needs a token from an administrator and nothing
else:

```sh
signari admin-token create -name documents -org <uuid> -scopes relations:write

curl -X PUT https://auth.example.com/admin/organizations/<uuid>/relations \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"subject": "user:alice@example.com", "relation": "owner", "object": "document:42"}'
```

The next decision sees it. `relations:write` reaches nothing else about the
organisation. Several writes that must stand or fall together go through
[`POST /admin/batch`](admin-api.md).

A relation is `(subject, relation, object)`. Roles are the special case where the
object is the whole application. They collapse the moment somebody asks "who can
edit **this** document", which is the question that actually gets asked. The
shape is Zanzibar's, because that model has held up.

Relations compose transitively: `owner` grants `read` through editor → viewer,
without anybody writing that edge. Expansion goes **upward only** — `delete:
[owner]` does not become "every viewer may delete".

Grants can expire (`expires_at`). An expired grant stops working **at the moment
it expires**, because the check is in the query rather than in a sweep. An
expiry swept by a janitor means temporary access lasts until the next pass.

**Deleting a person or a group deletes their grants**, in the same statement,
however the deletion happens. That covers the Admin API, `signari apply`, an LDAP
(Lightweight Directory Access Protocol) write, a directory or SCIM (System for
Cross-domain Identity Management) source, and [erasure](erasure.md).

A person's grants go whether they were made to their ID, their address or their
username. So do grants made *on* them as an object. A grant names its
subject by text, so nothing else would remove it. Until October 2026 nothing
did, and a group created later under a deleted group's name held every grant the
old one had.

A grant made to a group that does not exist yet is kept. That is also how access
is granted ahead of the sync that creates the group. `signari doctor`
warns about each one, since a group created under that name receives it.

Signari resolves group grants itself: the caller does not say which groups the
subject is in. `search/subject` expands a group grant to its **members**, because
"who can read this" is a question about people. Answering `group:finance` is
true and useless.

**Every search result is one an evaluation of the same question allows.** Each
candidate the relation graph finds is evaluated in full, through the same
function. That covers the action's `require` condition, `subject_active`, the
administrator's provider veto, and everything `/access/v1/evaluation` checks.

Until October 2026, resource and subject search answered from the relation graph
alone. A document whose `can_edit` required MFA was therefore listed for a
subject with no second factor. A deactivated account was listed under an action
requiring an active one. A PEP renders the list it gets, and then acts on it.

One page evaluates **at most 200 candidates**, because each costs what an
evaluation costs, and a provider veto is a network call. A page can therefore
come back short, or empty, with a `next_token`. The token resumes after the last
candidate *evaluated*, not the last one returned. So following tokens to the end
visits every candidate exactly once.

## Roles in an application

A role in an application is a relation on `application:<client_id>`. It is
granted like any other, to a person or a group, with an expiry if you want one.
These commands give Alice the `admin` role and the `finance` group the `auditor`
role, then name the claim the roles travel in:

```sh
signari authz grant -org <uuid> -principal user:alice@example.com -relation admin -object application:web-app
signari authz grant -org <uuid> -principal group:finance -relation auditor -object application:web-app

signari client set-roles-claim -client-id web-app -claim roles
```

The application's ID tokens, access tokens and userinfo then carry
`"roles": ["admin"]`. The roles are read for each token, so a role taken away is
gone from the next one. Somebody with no role gets no claim, not an empty one.

The claim's name is yours, and it is refused if it is one an application reads
for something else (`sub`, `acr` and the like). A claim mapper that took the same
name for this application keeps it.

To refuse a sign-in without one, say so in the [access policy](policy.md):

```yaml
- name: staff-only
  when: {client: web-app}
  require:
    application_roles: [admin, auditor]   # any of these
```

That holds at every grant the policy is asked about, so a role taken away stops a
refresh too.

## Relations another organisation hands out

A company whose application its customers use owns the objects, and does not
know the customers' people. A "delegation" lets a customer decide who holds what,
for its own people, on what the company owns:

```sh
signari authz delegate -org <owner> -grantee-org <customer> -object application:wiki -relations viewer,editor
signari authz delegations -org <owner>
signari authz undelegate -org <owner> -delegation <id>
```

`-object application:*` covers every object of the type. Only a deployment-wide
caller makes or removes one, through these commands or
`POST /admin/organizations/{orgID}/relation-delegations`. No organisation reaches
another on its own say, the owner included.

Under a delegation, a token of the customer's with `relations:write` writes
through the Admin API:

```sh
curl -X PUT $ADMIN/admin/organizations/$CUSTOMER/relation-delegations/$ID/relations \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"subject": "user:<their user id>", "relation": "viewer", "object": "application:wiki"}'
```

The relation is stored in the owner's relations and nowhere else. So the owner's
decisions read what they always read, and nothing about a decision crosses from
one organisation to another. Everything else is held to what the delegation
says. The relation and the object have to be ones it names.

The subject has to be a person of the customer, by ID. A person of the owner, a
person of a third organisation, or an address is refused with
`403 outside_delegation`. So is a group, because a group is resolved in the
organisation that holds the relation.

The customer reads back what it handed out, and nothing else of the owner's. A
relation the owner gave the same person itself stays the owner's. Neither a
revocation nor removing the delegation takes it away.

Removing the delegation removes everything handed out under it, and a person who
is deleted loses what they held. A person who is deactivated in their own
organisation still has a row in the owner's, as anybody does. What stops them is
their sign-in.

They hold a relation rather than an account. So a decision about them has no
session facts, and a condition that wants one fails. These relations go into no
token. A person signs in to their own organisation's applications, and an
application's `roles` claim is read from the organisation it belongs to.

## Things the wire format gets wrong elsewhere

**A denial is `200 {"decision": false}`.** Not 403. The HTTP status says whether
the request was processed, and the body says what the answer was.

A PDP that returns 403 for "no" is indistinguishable from one refusing to talk to
the caller at all. So a client cannot tell an authorization decision from its own
credentials having expired. It either retries, or treats it as a transport error
and falls back to allowing.

**A malformed request is `400`, not a denial.** "No" and "that question was
malformed" are different answers. Returning false for both teaches callers that a
denial might only mean they sent the wrong shape, after which nobody trusts a
denial. Unknown JSON fields are an error for the same reason. A caller who sends
`subjects` is told, rather than receiving a confident denial about a subject we
never saw.

**Action search results carry `name`, not `type`/`id`** (spec §8.6.2), unlike
subject and resource results (§8.5.2). Getting this wrong means a client looking
for `name` finds nothing. It was caught by reading the spec's own examples,
rather than assuming the shapes were uniform.

**`X-Request-ID` is echoed** when the caller sends one.

## Two reasons, never one

Every denial carries two reasons, one for the administrator and one for the
person:

```json
{
  "decision": false,
  "context": {
    "reason_admin": {"403": "the subject holds owner but the action requires a second factor, which this request did not show"},
    "reason_user":  {"403": "You need to sign in again with additional verification."}
  }
}
```

Collapsing them means one of two failures. Either the person is told which policy
refused them, which tells an attacker what to change. Or the administrator is
told "insufficient privileges", which tells them nothing. Every PDP that logs one
string has picked one of those failures.

## Batch

A batch asks several questions in one request. Its top-level fields apply to
every entry:

```json
{
  "subject":  {"type": "user", "id": "alice@example.com"},
  "resource": {"type": "document", "id": "42"},
  "options":  {"evaluations_semantic": "deny_on_first_deny"},
  "evaluations": [{"action": {"name": "read"}}, {"action": {"name": "delete"}}]
}
```

Top-level fields are **defaults**, merged field by field. An entry naming only
`resource.id` still inherits `resource.type`. An all-or-nothing merge would leave
it typeless, and produce a confident denial about a resource of no kind.

Short-circuit semantics stop **after** appending the deciding entry, so the
answer that ended the batch is in the response. A batch is bounded at 256
entries: an unbounded batch is a denial of service with a JSON array in front of
it.

One malformed entry does not fail the batch. The others are answerable, and
refusing all of them hides which one was wrong.

A batch reads the model, each subject and the relations it could turn on once. So
a hundred questions about one person cost five statements rather than six
hundred.

Walks are shared the same way. One question's walk settles a relation as held
along the path it found, or not held anywhere it looked. That answers the next
question of the same subjects. So a hundred documents in one folder walk the
folders above it once, and not a hundred times.

And the questions a batch has to walk take their first step together, in one
statement. Some questions have nothing behind them at all: no row of their own,
and nothing a rewrite goes through. Such a question is settled there and walks
no further. Take a
hundred questions under a model with a rewrite, half of them about documents
nobody asking holds. That half no longer costs a statement each.

The rest take their first level from the rows that statement read, and ask only
what lies beyond it. So a hundred documents in one deep folder cost that
statement and one walk up the folders.

Nothing read for a request outlives it, so a grant revoked is refused on the next
one. A provider veto is still one call per allowed entry.

## Recording decisions

Changes are always recorded: `admin.relation_granted`, `admin.relation_revoked`,
and `admin.cli_command` for the same thing from the command line.

A decision is a different matter. One can be asked for thousands of times a
second, and each recorded one is a link in the audit chain. So
`SIGNARI_AUTHZ_DECISION_LOG` sets the share of evaluations recorded. They are
recorded as `authz.decision` events, which reach the trail and any sink
streaming it. `0.01` records one in a hundred, and absent or `0` records none.
Searches are left out, since a search is a walk over candidates.

Each record has the decision, the action, the resource and the subject's type.
The trail outlives an erasure. So a person appears only as their ID in
`subject_id`, never as the address the caller may have asked about them with. An
address nobody in Signari holds is left out altogether.

A subject of another type, such as `service:billing`, is named. A resource of
type `user` is left out of a decision the same way, and a relation's own records
follow the same rule.

## No model means nothing is permitted

An organisation with no model denies everything, with an administrator reason
naming the command to fix it. An unconfigured authorization layer that says *yes*
is worse than no authorization layer at all, because the application believes it
has one.

## Re-review against Authorization API 1.0, August 2026

The version was checked first: **1.0, published 11 January 2026, status Final**.
It is not a draft, and it is the same version the implementation was written
against.

### The defect: a failure did not short-circuit

Section 7.1.2.1 defines `deny_on_first_deny`:

> Deny on first denial (or failure). This semantic could be desired if a PEP
> wants to issue a few requests in a particular order, with any denial (**error**,
> or `"decision": false`) "short-circuiting" the evaluations call and returning
> on the first denial. This essentially works like the `&&` operator in
> programming languages.

The parenthetical is load-bearing: an **error** counts as a denial.

The batch loop had two failure branches: a malformed entry, and a decision that
errored. Both appended `"decision": false` and then `continue`d, which skipped
the short-circuit check sitting below them.

So take a PEP using `deny_on_first_deny` to express `&&`: check A, then B, then
C, and stop at the first no. An errored A was answered `false`, and B and C were
evaluated anyway. The array it received did not mean what the semantic promised.
The `&&` analogy the specification offers was wrong for exactly the case a caller
is most likely to care about.

Both branches now assign a response and fall through, so the check is reached on
every path.

### Two tests, and only one of them works

`internal/authzen/semantics_test.go` models the decision rule, and checks all
eight semantic and decision combinations. It is good documentation of the rule,
and **it does not catch this bug**. It reimplements the logic rather than driving
the handler, so it passes whether or not the `continue` is there.

This review has repeatedly caught that pattern, in other people's tests and in
its own. It is an assertion that cannot fail for the reason it was written.

So `internal/httpapi/authzsemantics_test.go` checks the shape of the loop
instead: no `continue` inside it, and the short-circuit still present. It is
narrow and somewhat brittle, and it fails on the exact edit that caused the bug.

This was demonstrated rather than claimed. With the `continue` restored, the
tests report:

```
--- FAIL: TestTheBatchLoopHasNoContinuePastTheShortCircuit
ok      signari.dev/engine/internal/authzen      (the logic test still passes)
```

Driving the real handler would need a Server with a database, a policy store and
an organisation. That is a large fixture to prove a `break` is reached. The shape check
is the cheaper instrument that actually detects the regression, and its own
comment says so.

### What came back clean

These requirements were checked and held:

| Requirement | Where | Result |
|---|---|---|
| `policy_decision_point` identical to the identifier the well-known URI was derived from | §9.2.3 | built from the configured issuer, never the `Host` header |
| Top-level `subject`/`action`/`resource` inherited by each evaluation | §7.1.1 | field-by-field merge, so an entry setting only `resource.id` still inherits `resource.type` |
| The three semantic values spelled exactly | §7.1.2.1 | pinned by test |
| `execute_all` is the default | §7.1.2.1 | yes |

Signari is only ever a PDP, never a PEP. So §9.2.3's consumer-side obligation
does not apply to it: *"If these values are not identical, the data contained in
the response MUST NOT be used"*. That is recorded so that it is a decision rather
than an omission, if an outbound PDP client is ever added.

## Adversarial re-review against AuthZEN 1.0 Final, August 2026

This was the fourth emerging standard put through the same treatment as Shared
Signals and WebAuthn. The published text was re-read for every normative MUST,
and then hostile input was sent, rather than one-field-wrong variations.

It found two defects. Both were about conformance rather than compromise, and
one of them had a real integrity consequence.

### 1. We refused the forward compatibility the specification requires

Section 10.1.1 says, verbatim:

> To ensure forward compatibility, receivers **MUST ignore unknown fields**
> present in request or response bodies.

And §4:

> Any updates to this API through subsequent revisions … MAY augment this API …
> Augmentation MAY include additional API methods or **additional parameters to
> existing API methods**.

So the specification both anticipates new parameters and requires receivers to
tolerate them. `Decode` called `json.Decoder.DisallowUnknownFields()`, the exact
inverse. Any PEP speaking a later revision, or sending a vendor extension, had
its request rejected with **400**. So the caller could not even learn whether it
would have been allowed.

**The rationale was sound and the mechanism was wrong.** The comment was about a
caller sending `subjects` instead of `subject`. It said such a caller "must be
told, rather than receiving a confident denial about a subject we never saw".
That is true, but
refusing the whole body is not what tells them. With the stray field ignored,
`subject` is absent, and `Validate` answers with the error §10.1.1 requires for
exactly that case:

> If a required attribute in the information model is omitted, the server MUST
> return a "Bad Request" error

That error names the attribute that is **missing**, rather than the one that was
misspelled, and is the more useful of the two messages.

What is given up: a typo in an *optional* field is now silent. That is the trade
the specification makes deliberately.

### 2. Duplicate JSON members — the decision and its audit record could disagree

It was found by sweeping hostile bodies for a single invariant: *nothing that
fails to decode or validate may reach policy evaluation as though it were a
well-formed question.* One body got through:

```json
{"subject":{"type":"user","id":"alice"},"subject":{}, …}
```

Go's decoder **merges** a repeated object into the value it already decoded. So
the first occurrence's populated fields survive, and this evaluates as `alice`. A
proxy, web application firewall (WAF) or audit shipper that takes the **last**
occurrence sees an empty subject.

The PDP is the authority, so this is not a privilege escalation. It is worse in a
different way for this product: the decision and the record of the decision would
describe **different requests**. Proving what was authorised is the property this
system is organised around.

§10.1.1 supplies the principle:

> Implementations **MUST NOT** assume a particular ordering of JSON object
> members.

A body whose meaning depends on that ordering has no reading Signari is entitled
to pick, which makes refusing the only correct answer.

Duplicates are now refused at **any depth**: top level, inside an entity, inside
`context`, inside an array element. A token walk finds them, because a second
unmarshal into `map[string]any` would collapse the duplicates before they could
be seen.

This is the same rule, for the same reason, as the duplicate-parameter check the
[pushed authorization request](par.md) endpoint has had since it was written. The
principle was already held in this codebase. It had not been applied here.

**And it generalised.** The Security Event Token receiver decoded its payload
with a plain `json.Unmarshal` too. That one is not attacker-craftable. The
payload is signed, so producing an ambiguous SET needs the transmitter's key, and
a transmitter trusted to revoke sessions could do worse things directly.

But the divergence argument is unchanged. Signari would act on Go's reading of a
duplicated `aud`, while a security information and event management (SIEM)
system reading the same bytes recorded another. Disagreeing with your own audit
trail is the failure this product exists to prevent.

The rule now lives in `internal/jsonstrict`, and is called from both rather than
copied. A check this subtle drifts when each package re-implements it. One copy
gains a depth limit or loses the array case, and nothing says so.

### What the sweep confirmed

The sweep sent these bodies:

| Hostile body | Outcome |
|---|---|
| Empty, truncated, `[]`, `null`, a bare string or number | refused |
| Entities as scalars or arrays rather than objects | refused |
| Any required attribute missing or empty | 400, **not** a denial |
| Unknown fields, top level and nested | **ignored** (§10.1.1) |
| Duplicate members at any depth | refused |

"400, not a denial" is deliberate and worth keeping visible. *No* and *that
question was malformed* are different answers. A PDP that returns `false` for
both teaches callers that a denial might only mean they sent the wrong shape.

### Fail-closed, verified rather than asserted

Every path through `decide` that is not an explicit grant returns
`Decision: false`. Every error returns no decision at all, and the handler turns
it into a 500.

A condition that cannot be evaluated because no live session was named is
refused, rather than assumed satisfied: *a rule demanding a second factor must
not be satisfied by the absence of evidence.*

Four mutations were run against the two fixes and the required-attribute check.
All four were caught.

### 3. `resource.id` was not required, though the specification marks it REQUIRED

This was found in a later pass. It is worth recording precisely because the
section above already claimed to have re-read "every normative MUST", and it had
not caught this one.

Authorization API 1.0 (Final, 11 January 2026), Resource:

> `id`: REQUIRED. A string value containing the unique identifier of the
> Resource, scoped to the `type`.

`Request.Validate` checked `subject.type`, `subject.id`, `action.name` and
`resource.type`, and deliberately not `resource.id`. There was a test asserting
the omission, with a stated reason: "a search or a type-level question does not
have one, and demanding it would refuse valid requests."

Half of that reason is answered by Signari's own code: a search arrives as a
`SearchRequest`, a different type that never reaches this validation. The other
half is answered by the specification, which puts type-level questions in the
Resource Search API rather than in an evaluation.

**This was not a security defect, and it would be tempting to write it up as
one.** `store.HoldsAny` compares `object_id` for equality. So a request with no
resource ID matches no relation, and the answer is a denial. Nothing was let
through.

What was wrong is narrower, and is a rule this codebase states in the handler
four lines above the check:

```go
// 400, not a denial. "No" and "that question was malformed" are
// different answers, and a PDP that returns false for both teaches
// callers that a denial might just mean they sent the wrong shape.
```

Suppose a caller dropped `resource.id`, from a PEP bug or a template that did
not interpolate. It received `decision: false`, and no sign that it had asked a
malformed question. It would read as "access denied" and be handled as such.

It is now a 400 naming the field. Both the general validation test and a
dedicated one fail if the check is removed.

## Currency of the emerging standards, August 2026

These were checked against the publishers rather than against notes, because a
review is only as current as the text it was written from. One row is built on a
JSON Web Token (JWT) with selective disclosure, a Selective Disclosure JWT
([SD-JWT](glossary.md#sd-jwt)). It is SD-JWT VC, SD-JWT-based Verifiable Digital
Credentials:

| | version we implement | published | verdict |
|---|---|---|---|
| AuthZEN Authorization API | 1.0 | **Final, 11 Jan 2026** | current |
| SD-JWT VC | draft-18 | draft-18, 3 Aug 2026 | current |
| Transaction Tokens | draft-11 | draft-11, 30 Jul 2026 (WG Last Call) | current |
| Attestation-Based Client Auth | draft-10 | draft-10, 6 Jul 2026 | current |
| FAPI 2.0 Security Profile | Final 22 Feb 2025 | unchanged, no errata | current |

All five are the current published text. The `internal/authzen` package recorded
no version string at all before this pass. That is how a Final specification
could supersede the Implementer's Draft it was written against without anything
noticing.
