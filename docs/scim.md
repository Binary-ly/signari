# SCIM provisioning

Push users into downstream applications so they exist there before first
sign-in — and, more importantly, stop existing there when they leave.

```sh
signari scim add -org <uuid> -slug slack \
  -base-url https://api.slack.com/scim/v2 -token <bearer>

signari scim sync            # preview: shows what would change, sends nothing
signari scim sync -apply     # converge the target on this directory
signari scim verify          # read the target back and check it agrees
```

The Admin API registers targets, changes their settings, provisions groups and
syncs the same way under `/admin/organizations/{orgID}/scim-targets`, running
the same pass as the command; see [admin-api.md](admin-api.md).

## Which half actually matters

Provisioning failing is a support ticket. Somebody cannot get into Slack and
says so within the hour.

**Deprovisioning failing is a security incident nobody reports**, because the
person it affects has left and the administrator who deactivated them saw a
success message. Months later an audit finds a live account for someone who
resigned last spring.

Everything here is shaped by that asymmetry.

## Reconciliation, not a queue

The obvious design is an event queue: user deactivated → enqueue a deprovision.
It is also exactly how deprovisioning silently fails. An event dropped during a
restart, exhausted after its last retry, or enqueued while the target was
misconfigured leaves a live account for someone who has left — and nothing will
ever try again, because the event is gone.

`signari scim sync` reconciles from **desired state** instead. Whatever went
wrong last time, the next pass sees the same disagreement and fixes it.

## `scim verify` — the part that makes it checkable

Everything else records what we *meant*. A row saying `should_be_active = false`
means an administrator pressed deactivate and the request did not return an
error. It does not mean the account is gone.

Between those two sit: a target that answered `200` and ignored the patch, a
change that failed after its last retry, an account recreated by a local
administrator at the target, an integration disabled months ago that nobody
re-enabled. Each leaves a live account, and **none is visible from our own
tables**.

So verify asks the target. Demonstrated against a target that accepts the
deactivation and does nothing:

```
sync:   slackish: did create 0, deactivate 1, delete 0, failed 0
verify: slackish: 1 user(s) retain access they should not have
          [CRITICAL] alice   was deactivated here and is STILL ACTIVE at the target
                     -> Deactivate them at the target now, then find out why the
                        change did not arrive.
exit status 1
```

Non-zero exit, so it can gate a deploy or run from cron and be noticed.

Findings are ranked, and the ranking is load-bearing:

| severity | meaning |
|---|---|
| **CRITICAL** | deactivated here, still active there — someone has access they should not |
| warning | should have access and does not; or deactivated at the target but active here |
| info | linked but never confirmed; or an account at the target we did not create |

A checker that always finds something gets muted, and then the real finding is
muted too. So a clean run says so, and unrecognised remote accounts are reported
as **info and left alone** — a target legitimately holds service accounts and
people who predate the integration, and a provisioning tool that deletes what it
does not recognise is a way to destroy a production service account.

`"I could not check"` and `"everything is fine"` are never the same answer: an
unreachable target is reported as `UNREACHABLE` and exits non-zero.

## Details that are decisions

**Deactivation uses PATCH, never PUT.** A PUT replaces the whole resource, so it
erases every attribute the target holds that we did not send — group
memberships, profile fields, anything a local administrator set. Turning someone
off must not also wipe their record.

**Deprovisioning is by the id the target assigned**, recorded at creation.
Deleting by username or email is how the wrong account gets removed after
somebody changes their address — or how the right one is missed and left active.

**A 409 on create is distinguished from a failure.** It means the account already
exists, so its id is looked up and recorded rather than retried forever.

**Permanent failures are not retried.** A 400 from a target that rejects an
attribute will not start working on the fifth try, and retrying hides the real
problem behind a growing backlog. Only 429 and 5xx are retryable.

**Deleting an account that is already gone succeeds.** Already-gone is the
desired state; treating it as failure retries against nothing, forever.

**`-on-deactivate`** is `deactivate` (reversible, keeps history), `delete`, or
`nothing`.

**Dry run** records what would be sent without sending it, because the first
thing anyone wants to know about a new integration is what it is about to do to
their production Slack.

**`SIGNARI_SCIM_CA_BUNDLE`** adds a certificate authority for these requests.
Internal targets often sit behind a private CA, and the alternative operators
reach for is disabling verification entirely. It *adds* to the system pool, so
trusting an internal CA does not stop public targets from verifying.

## Groups at Entra and Google

A group is provisioned to an Entra or Google target exactly as to a SCIM one: created
when you ask, its members followed by every sync, and only ever a group this
deployment made, never one matched by name. Both need more than user provisioning:

| Target | Needs | Created as |
|---|---|---|
| Entra | `Group.ReadWrite.All` on the application registration | A security group, not mail-enabled. Its description names it as managed here |
| Google | The `admin.directory.group` scope on the service account's delegation, asked for only by group calls, so user provisioning keeps working where it is not granted | `<name>@<domain>`, the group's name made fit for an address |

A group whose name has nothing an address can hold, such as one written wholly in
another script, is refused rather than sent. Group members are added one request at
a time, so a first sync of a large group takes a request a person.

This has been run against faithful fakes of both APIs and not against a real tenant.

## A target that issues its own tokens

A target that takes OAuth 2.0 client credentials instead of a long-lived bearer
token is registered with where to ask, and `-token` is then the client secret:

```sh
signari scim add -org <uuid> -slug billing \
  -base-url https://billing.example.com/scim/v2 \
  -oauth-token-url https://billing.example.com/oauth/token \
  -oauth-client-id signari -oauth-scope scim.write -token <client secret>
```

The token URL is held to what the base URL is: `https`, and refused if it points
inside this network, because the secret goes there. The secret is sealed at rest
like a bearer token, and never read back. It is sent by HTTP Basic, which RFC 6749
requires every token endpoint to accept. A token endpoint that refuses Basic and
takes the id and secret only in the form gets `-oauth-client-auth
client_secret_post`, or `oauth_client_auth` through the Admin API or a
configuration file. The secret then goes in the form and nothing goes in a
header, since a client uses one way to authenticate a request. The RFC calls the
form NOT RECOMMENDED, so use it only where Basic is refused. A token is asked for when
a pass first needs one, kept in memory for that pass, replaced 30 seconds before it
expires, and asked for once more if the target answers 401 anyway. Changing the
grant through a configuration file needs the secret in the same file, for the
reason a new base URL does.

## A target that asks a person to agree

Some targets issue tokens only to somebody who has signed in there and agreed,
the authorization code grant, and not to a client alone. Register one with where
to send that person, from the same client:

```sh
signari scim add -org <uuid> -slug billing \
  -base-url https://billing.example.com/scim/v2 \
  -oauth-token-url https://billing.example.com/oauth/token \
  -oauth-authorize-url https://billing.example.com/oauth/authorize \
  -oauth-client-id signari -oauth-scope 'scim.write offline_access' -token <client secret>

signari scim authorize -org <uuid> -slug billing
```

`scim authorize` prints an address to open in a browser. Sign in there as somebody
who may administer the target and agree. The target sends the browser back to a
loopback port the command opens for that one request, and the command redeems the
code with a PKCE verifier that never left it and keeps the refresh token, sealed
under the root key. A target that allows only fixed addresses is given one with
`-redirect`: a loopback address with its port is listened on, and anything else is
the address to copy from the browser back into the terminal, whatever the page
there shows. The authorization waits ten minutes.

Each sync asks for an access token with the refresh token and keeps the one it is
given back. An authorization server that rotates refresh tokens treats a spent one
coming back as stolen and ends the grant, so two syncs of one target at once take
turns: the second waits for the first's new token rather than spending the old
one. A response carrying a new refresh token that is lost on the way leaves the
spent one kept; the target refuses it with `invalid_grant`, the sync says so, and
the target is authorized again. The same happens when somebody revokes the grant
at the target, or it expires unused.

A target that answers the sign-in with no refresh token is refused there rather
than working for an hour: ask for the scope it gives one for, often
`offline_access`. A new grant or base URL forgets the authorization, since it was
given for the old one, and a configuration file's plan (`oauth_authorize_url`)
says so. The Admin API does the same in two steps, for a console that sends the
browser itself; see [admin-api.md](admin-api.md).

This has been run against another deployment of this engine as the target's
authorization server, which rotates refresh tokens and ends a grant whose spent
token comes back, behind a SCIM API that checked every token there, and not against
a commercial target.

## A target that does not quite speak SCIM

`-compatibility`, or `compatibility` through the Admin API or a configuration file,
names what a target needs that the protocol does not say it should. They are named
for what they do rather than which product needs them, because that changes with
the product's version and a target can need several: a target that answers PATCH
with a 405 is `no-patch`, whatever it is.

| | What changes |
|---|---|
| `no-patch` | A change reads the resource and puts it back whole, changed only where it had to be: `active`, or exactly the members that moved. An attribute this engine knows nothing about, and a member added at the target by hand, go back as they came. Somebody else's change between the read and the write is lost, which no PUT can avoid. |
| `no-filter` | Finding an account after a 409 walks the target's list instead of asking `userName eq`, about a page per hundred accounts. |
| `typed-members` | A group member carries `"type": "user"`. |

## An account that vanished at the target

By default `sync` leaves it alone. Verify reports it as a warning (*"should have
access and the remote account does not exist"*), because re-creating an account
somebody deliberately deleted at the target is not obviously the right thing to
do without being asked.

To be asked once, set `-recreate-missing` on `scim add` or `provision add`,
`recreate_missing` through the Admin API or a configuration file. Each sync then
lists the target, and somebody active here whose linked account is not on the list
gets a new one, which a preview counts as `recreated` without sending anything. A
list that came back wrong looks exactly like everybody having been deleted, so when
five or more accounts and over a quarter of those linked are missing, nobody is
recreated and the sync reports it as a failure for an operator to look at.

Somebody deactivated here whose account has already gone needs nothing done: the
target's 404 ends the link, rather than failing on every sync.
