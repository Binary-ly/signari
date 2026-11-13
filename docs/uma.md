# UMA 2.0

User-Managed Access 2.0 Grant for OAuth 2.0 Authorization — Kantara
Recommendation, 7 January 2018 — plus Federated Authorization for the permission
endpoint.

## What it adds to OAuth, in one sentence

A resource server can ask this server what a caller would need, hand the caller
an opaque ticket describing it, and let the caller come back with that ticket for
a token scoped to exactly those permissions — so the resource server never holds
the policy.

    client -> RS        (no token, or not enough)
    RS     -> AS        POST /uma2/permission   {resource, scopes}  -> ticket
    RS     -> client    401 + WWW-Authenticate: UMA as_uri=..., ticket=...
    client -> AS        grant_type=urn:...:uma-ticket, ticket=...   -> RPT
    client -> RS        Authorization: Bearer <RPT>

The client exchanging the ticket needs the grant, which defaults to off:
`signari client set-grants -client-id <id> -grant-types
urn:ietf:params:oauth:grant-type:uma-ticket`. Until October 2026 `set-grants`
refused this grant type, so no client could be given it.

## The decision comes from the existing policy engine

`internal/authzen` — the same policy decision point that answers
`/access/v1/evaluation`. UMA is a way of *asking*; it is not a second opinion
about who may do what. A separate engine behind this endpoint would be a second
answer to the same question, and the two would eventually disagree about
something that matters.

This is the same argument that has CIBA sharing the device flow's polling code.

## The requesting party

Until August 2026 this server answered from policy alone and treated the
**client** as the requesting party. That made the UMA grant a decorated
client-credentials exchange — which works, and is not what UMA is for. The point
of UMA is that a resource owner writes policy about a **person** this server may
never have provisioned.

There are now three ways a request can carry one:

| | |
|---|---|
| nothing | the requesting party is the client itself. Where every flow starts |
| interactive claims gathering (§3.3.2) | the person is redirected here, signs in, and confirms |
| pushed claims (§3.3.1) | the client sends `claim_token`, an ID token this server issued |

Once a requesting party is established, the policy decision is made about
**them** — `subject: {type: "user", id: ...}` — and the RPT's `sub` is theirs.
Leaving the client id in `sub` after going to the trouble of establishing who was
asking would produce a token saying the application asked for itself.

## Pushed claims (§3.3.1)

    claim_token=<id token>
    claim_token_format=http://openid.net/specs/openid-connect-core-1_0.html#IDToken

**Only ID tokens this server issued, to this client.** §3.3.1 notes that "the
client and authorization server together might need to establish proper audience
restrictions for the claim token prior to claims pushing" and provides no
protocol for doing so with a third party. Accepting an assertion from an
arbitrary issuer would mean accepting whoever the client chose to believe — and
the client is the party asking for access.

So the audience check is the restriction, made concrete: an ID token whose `aud`
is a different client is refused. Without that a client could push a token it
picked up from a log, a referrer header, or another application it also operates,
and be treated as acting for that person.

Expiry **is** enforced here, which is worth noting because
`VerifyIDTokenAudience` deliberately does not enforce it — that function exists
for `id_token_hint` at logout, where an expired token is the normal case. Here it
is not: an expired ID token proves somebody authenticated at some point, and this
grant is about who is asking now.

### The encoding

§3.3.1: "It MUST be base64url encoded unless specified otherwise by the claim
token format." The ID Token format specifies nothing, so strictly the value is a
base64url-encoded JWT. In practice clients send the raw compact serialisation.

Both are accepted, and they are **distinguishable rather than guessed at**: a
compact JWS has exactly two dots and base64url has no dot in its alphabet, so no
input is validly both. A parser that tried one and fell back to the other on
failure would be a different and worse thing.

## Interactive claims gathering (§3.3.2, §3.3.3)

    GET  /uma2/claims?client_id=&ticket=&claims_redirect_uri=&state=
    POST /uma2/claims        (the confirmation)

### Why it is two requests

§5.1 is unusually specific:

> The authorization server **MUST** implement CSRF protection for its claims
> interaction endpoint **and ensure that a malicious client cannot obtain
> authorization without the awareness and involvement of the requesting party.**

Read the second half. A token alone does not satisfy it. If the `GET` redeemed
the ticket and redirected, then

    <img src="https://as.example/uma2/claims?client_id=...&ticket=...">

in an email spends the victim's identity while the page is loading. Their only
evidence is a broken image.

So the `GET` renders what is being asked and the `POST` acts on it. That is the
"awareness and involvement" half; the CSRF token is the other half, and neither
substitutes for the other.

The ticket is **read** on the `GET`, not redeemed. §3.3.1 spends a ticket when
the client "presents" it here, and the presentation that counts is the one the
person acts on — spending it on the `GET` means a page reload, or a browser
prefetching the link, destroys the request before anybody decided anything.

The confirmation form carries only a **handle** and the CSRF token. The ticket
and the redirect URI come from the interaction row, so a submission cannot carry
values the person was never shown.

### `claims_redirect_uris` are not `redirect_uris`

§3.3.2:

> Claims redirection URIs are different from the redirection URIs defined in
> [RFC6749] ... Therefore, authorization servers **MUST NOT** redirect requesting
> parties to pre-registered redirection URIs defined in [RFC6749] unless such
> URIs are also pre-registered specifically as claims redirection URIs.

    signari client set-claims-redirects -client-id web \
      -claims-redirect-uris https://app.example/uma/return

They are a separate column and a separate list, even when they are the same host.
An RFC 6749 redirect URI carries a resource **owner** back from authorizing their
own resources; this one carries a **requesting party** — a stranger to the
resource owner — back to a client that may be nobody's.

**Every client must pre-register.** §3.3.2 makes that a SHOULD for all clients
and a MUST for public ones; this server takes the SHOULD, with no configuration
to relax it. The specification's "REQUIRED if the client has pre-registered no
claims redirection URI" describes a server that will accept an unregistered URI,
and that server has an open redirect whose payload is a permission ticket bound
to whoever just signed in.

Matching is RFC 3986 §6.2.1 Simple String Comparison, as §3.3.2 names — no
normalisation, and **no loopback exception**. RFC 8252's ephemeral-port allowance
is about native apps receiving an authorization code and has nothing to say about
this parameter; adding it "for consistency" would widen a redirect target on the
strength of a rule that does not apply.

Omitting `claims_redirect_uri` is permitted only when exactly one is registered.
Registering a second changes that, and `set-claims-redirects` says so — a client
relying on the single-URI default starts being refused the moment a second is
added.

### Errors before the redirect

§3.3.3: if the request fails "due to a missing, invalid, or mismatching claims
redirection URI, or if the client identifier is missing or invalid, the
authorization server SHOULD inform the requesting party of the error and **MUST
NOT** automatically redirect the user agent to the invalid redirection URI."

Both faults render a page on this origin. Nothing is redirected.

The person is also asked to sign in **after** those checks, not before: somebody
who signs in and is then told the request was invalid has typed their password
for an attacker's benefit.

### `state`

§3.3.3: it "MUST be present if and only if the client provided it". So a client
that sent an empty `state` gets an empty one back, and one that sent none gets
none — which is why the interaction row records *whether* there was a state, not
only its value.

## The three refusals (§3.3.6)

§3.3.4 leaves the choice to the implementation. The rule here:

| situation | answer |
|---|---|
| nobody identified, and this client **can** identify somebody | `need_info` — gathering claims could change the answer |
| nobody identified, and it **cannot** | `request_denied` |
| identified, and this org offers owner intervention | `request_submitted` — a human can still say yes |
| identified, and it does not | `request_denied` — **final**, and honestly so |

`request_denied` is final by design. Asking the same question again cannot
produce a different answer, and telling a client to poll for a decision nobody
will be asked to make is worse than a refusal it can act on.

### "Can identify somebody" is a per-client fact

The obvious rule — *unidentified always means `need_info`* — is wrong for the
machine-to-machine deployments this grant served before claims gathering existed,
where policy is written about **clients** and the client genuinely is the
requesting party. Sending one of those a `redirect_user` hint invites it to
redirect a user that does not exist, and §3.3.6 says so itself:

> If the requesting party is not an end-user, then no client action is possible
> on receiving the hint.

**Registered claims redirection URIs are the switch.** They are the deployment
saying, per client, "this one acts for people" — set explicitly with
`signari client set-claims-redirects`, not inferred. Every client that existed
before this feature keeps the answer it used to get.

### Both hints, when there are hints at all

`need_info` carries **both** `required_claims` and `redirect_user`. §3.3.6
requires "either ... or both", and this server cannot tell whether a client with
claims redirection registered has a browser in front of it right now — so
sending only the redirect would leave a headless retry with nothing to act on.

### A bad claim token is `need_info`, not `invalid_grant`

§3.3.6's own definition:

> The authorization server needs additional information in order for a request to
> succeed, for example, **a provided claim token was invalid or expired, or had an
> incorrect format**.

So an expired or wrongly-formatted `claim_token` is answered with a fresh ticket
and `required_claims` naming what would work. `invalid_grant` would tell the
client its **ticket** was bad, when the ticket was fine.

Two faults deliberately do **not** get that treatment: a token whose signature
does not verify, and one whose audience is another client. Those are not "we need
more information" — they are a client presenting a credential it should not have,
and answering with an invitation to retry dresses that up as a recoverable
mistake.

### Ticket chaining and single use

§3.3.6 says every `need_info` and `request_submitted` response carries a ticket
whose "value MUST NOT be the same as the one the client used to make its
request", while §3.3.1 says tickets are single-use.

Those are not in tension. Each poll **spends** its ticket and receives the next
one; the chain is what makes polling possible without ever replaying a ticket.
Successors carry the predecessor's permissions **verbatim** — re-deriving them
would let what is being asked for change between a refusal and the retry it
invites, so a client told "you need X" could return and be granted Y.

A ticket that carries an identity is also **bound to the client that gathered
it**. The interaction proved who the requesting party is *to one client*; letting
a second present the successor would hand it somebody else's proof.

## Resource-owner intervention

    signari uma settings -org <id> -owner-intervention -poll-interval 30s
    signari uma requests -org <id>
    signari uma approve -uma-request <id> -relation viewer
    signari uma deny    -uma-request <id>

**Off by default.** §3.3.4 makes `request_submitted` conditional on capability,
not preference: a server may answer it only "if [it] has a way to notify the
resource owner about the ... resource request and seek an added policy covering
it". With nobody being asked, a refusal stays `request_denied`.

### Approval grants a relation

The obvious implementation records "request 7 is approved" and lets the next poll
find it. That builds a second, parallel authorization store: access invisible to
`signari authz check`, absent from every policy graph, and revocable only through
a mechanism nobody else uses.

So approving **grants a relation in the authorization model**, and the next poll
passes policy on its own with no special case anywhere. The pending row records
that a decision was made and what was granted; the access itself lives where all
the other access lives.

`uma requests` prints which relations would satisfy each request, because the
compiled model is the only place that answer exists and reading one is not a
reasonable thing to ask of somebody approving a request.

`uma approve` **refuses** a relation that would not satisfy *every* scope asked
for. Granting one that covers three of four leaves the client polling forever
against a decision somebody believes they made, and the pending row would say
`approved`.

`-expires-in 720h` grants it for thirty days instead of until revoked. Access
someone needed for a project then ends without anyone having to remember it.

Denial reaches the client on its next poll, as `request_denied`. There is no way
to tell it sooner — the ticket flow is the only channel the protocol has.

Pending requests expire after seven days and the janitor sweeps them. Unlike
everything else it sweeps, a lingering row here is a liability rather than
clutter: a pending request is a standing offer to grant access, and somebody
approving a month-old one is approving a context they cannot remember.

## Discovery

    GET /.well-known/uma2-configuration

§2 requires the document at that exact path and requires it to conform to RFC
8414. It is built from the **same builder** that answers
`/.well-known/openid-configuration`, plus:

- `claims_interaction_endpoint` — §2's static value. §3.3.2 assumes it is
  declared, because that is what lets a client redirect a requesting party
  *before* being told to.
- `permission_endpoint` and `resource_registration_endpoint`, Federated
  Authorization §2's two required values, from the shared builder, so the OpenID
  document carries them too.
- `uma_profiles_supported` — the one claim token format this server acts on.

## Single use is a MUST

§3.3.1: *"Permission tickets MUST be single-use. This prevents susceptibility to
a session fixation attack."* And the ticket is invalidated *"when the client
presents the permission ticket to either the token endpoint or the claims
interaction endpoint, or when the permission ticket expires, whichever occurs
first."*

Three consequences implemented deliberately:

1. The `UPDATE … WHERE redeemed_at IS NULL AND expires_at > now() RETURNING` is
   the read. The row is spent by the same statement that discovers it, so two
   concurrent presentations cannot both succeed.
2. **A refused request spends the ticket too.** Presentation invalidates, not
   *successful* presentation — otherwise a client can grind one ticket against
   policy while claims change underneath it.
3. The claims interaction endpoint spends it as well, which is the clause's
   other half — and it spends it on the `POST`, not the `GET`. See above.

Tickets are stored as SHA-256, like every other credential here. A ticket is a
bearer credential from the moment the resource server receives it until the
client spends it, travelling through a 401 header and back through a token
request, so it passes any number of proxies and logs.

## Registering resources (Federated Authorization §3)

A resource server puts a resource under this server's protection at the resource
registration endpoint, and a permission then names it by the id it was given alone:

    POST   /uma2/resource_set        {"resource_scopes": ["read"], "type": "document", "name": "Q3 report"}
                                      -> 201, Location, {"_id": "...", "user_access_policy_uri": "..."}
    GET    /uma2/resource_set        -> ["_id", ...]
    GET    /uma2/resource_set/{id}   -> the description, with _id
    PUT    /uma2/resource_set/{id}   the whole description again -> {"_id": "..."}
    DELETE /uma2/resource_set/{id}   -> 204
    POST   /uma2/permission          {"resource_id": "<_id>", "resource_scopes": ["read"]}

Each needs a **protection API access token** (PAT): an access token with the scope
`uma_protection`, issued to the resource server. Who granted it is the **resource
owner**. A person who signed in to the resource server and agreed owns what it
registers with their PAT; a PAT by the client credentials grant registers for the
organisation. A resource server reads, replaces and deletes only what it registered
for that owner, and anything else is a 404, as a resource that is not there is. The
client needs the `uma_protection` scope among its scopes, and the client credentials
grant for an organisation's PAT.

**`type` is required here**, and names a type of the organisation's authorization
model, because the model is what decides who may reach a resource: `"document 42"`
and `"invoice 42"` are different things. Every scope must be an action the model
defines for that type, or no permission on it could ever be given and nothing would
say why. A registered resource keeps its type, since what it has been shared as is
relations on an object of that type; deregistering it removes those relations with
it. Other HTTP methods are answered `405` with `unsupported_method_type`.

At the permission endpoint, a `resource_id` with no `resource_type` must be one this
resource server registered, each scope one it registered for it, or the answer is
`invalid_resource_id` or `invalid_scope` (§4.3). One request names one owner's
resources (§4). The endpoint takes a PAT, and still takes the client's own
credentials as it did before it had registration, which §1.3's "MUST ... require a
valid PAT" does not allow: a resource server that sends credentials is held to the
same resource server's registrations, the first named deciding the owner.

`resource_type` is ours, and not in the specification. Given, it names an object of
the model that was never registered, which is how this server answered before it had
registration, and still does for a resource server that keeps its resources to
itself.

### What a person shares

A person's registered resources are listed at `/account/resources`, the
`user_access_policy_uri` a registration answers. Each can be shared with somebody
by address, as one of the relations the model gives its type, and the sharing
stopped; a share is a relation on the resource's object, so the requesting party's
decision at the token endpoint is the model's, as for anything else. The model's
author decides what each relation lets somebody do; the owner decides who holds one.
A share made by an administrator to a group or a client is listed nowhere on that
page and is not the owner's to remove. Each share and its removal are audited
(`uma.resource_shared`, `uma.resource_unshared`).

## Upgrading an RPT (§3.3.5.1)

A client holding an RPT can send it along with a new ticket as `rpt`, and the token it
gets holds both. The response says `"upgraded": true` when that happened. Without it the
client treats the new RPT as not holding the old one's permissions, as §3.3.5 requires,
so a token that cannot be upgraded is not an error: the client gets its new RPT and is
told nothing was carried.

§3.3.1 says the RPT presented "MAY be expired", which is what makes this worth care. An
upgrade gives everything it carries a new lifetime, so copying permissions forward would
let one that was taken away go on being renewed for as long as the client kept asking.
**So each is decided again**, by the same decision point as the ticket's, and if any is
refused nothing is upgraded: §3.3.5.1 has the server add the previous RPT's permissions,
and part of them is not that.

It has to be this client's RPT, for this requesting party and this resource server,
bound to the same key if it is bound to one, and not revoked. §1.2 has an RPT unique to
all of those, and a token moved between them has proved nothing to the second. The
RPT replaced is revoked, as §3.3.5.1 says it SHOULD be.

## Binding an RPT with DPoP

§5.3 leaves proof of possession to a profile. A [DPoP](dpop.md) proof on the token
request binds an RPT as it binds any other token: `cnf.jkt`, and `token_type` `DPoP`.

## Remembering a person (§3.3.5)

The claims interaction has a box: remember this for the application for a month. A person
who ticks it gets a **persisted claims token** issued to the client alongside the next
RPT, and the client can send it as `pct` to say who is asking without sending them through
the screen again. A person who does not tick it gets none, which is what §6.2 recommends:
ask before keeping anything across authorization processes.

A PCT works as a refresh token works, with no interaction behind the next token, so it is
kept the same way. It is stored as a hash and holds no claims, only who it was about,
because those are this server's own records and are read when it is used. It is good for
the client it was issued to and no other, as §5.2 requires. It stops at its month, when
the client revokes it (`token_type_hint=pct`, §3.7), when the person is deactivated, and
when they are signed out everywhere, which is a thing they are told happened and would not
be true with one of these left over. The person sees the application on their connected
applications page (`/account/connected`), with the day it stops acting for them, and
removing it there ends its PCTs with its other grants; an administrator sees the same as
`persisted_claims_until` from the Admin API, and can remove it the same way.

It says who is asking and nothing else: every permission is still decided, and the
resource owner's policy applies to a remembered person as to anybody. A request that
gathers one identity and presents a PCT for another is refused, because it has named two
people and this server will not pick. §5.2 has the client make a best effort that the
person using it now is the person the token was issued for, which only the client can do.

## Still not implemented

- **`claim_token` formats** beyond an ID token this server issued.
- **A link to `/account/resources` from the account page.** A person reaches it from
  the `user_access_policy_uri` a resource server shows them, or by its address.
