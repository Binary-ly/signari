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

## Known limitation

`sync` does not yet re-create an account that vanished at the target. If a
remote account is deleted out from under us, verify reports it as a warning
(*"should have access and the remote account does not exist"*) and the fix is
manual: clear the link row and re-run sync. Repair is not automatic because
re-creating an account somebody deliberately deleted at the target is not
obviously the right thing to do without being asked.
