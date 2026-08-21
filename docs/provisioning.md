# Provisioning users out

Signari writes accounts into three kinds of target: any SCIM 2.0 server, Google
Workspace, and Microsoft Entra ID.

**Google Workspace and Entra are the paid tier elsewhere in this field.** They
are free here, and the reason is not generosity — the hard part is the
reconciliation, and that was already written for SCIM. Adding two more targets
was implementing one small interface twice.

## Registering

```sh
# Any SCIM 2.0 server

# Google Workspace
signari provision add -org <uuid> -slug workspace -kind-outpost google \
  -credentials ./service-account.json \
  -impersonate admin@acme.com -target-domain acme.com

# Microsoft Entra ID
signari provision add -org <uuid> -slug entra -kind-outpost entra \
  -credentials ./entra-credentials.json -target-domain acme.com
```

Credentials are sealed with the root key. A service account JSON file is a
credential to somebody's entire directory, and a database read must not yield
one.

## Why Google and Entra are not SCIM

Neither accepts SCIM as a server.

Entra is a SCIM **client** — it pushes users out to other systems and does not
accept pushes in. Google has no SCIM surface at all. Both are written through
their own APIs: the Admin SDK Directory API and Microsoft Graph.

What sits above them is unchanged. One `Provisioner` interface with five
methods, one reconciliation, one deactivation policy, one dry run. A second sync
engine per target is how "deactivate" comes to mean something slightly different
for Google than it does for everything else.

## It is a dry run until you say otherwise

```
gw: would create 3, deactivate 0, delete 0, failed 0

Nothing was sent. Re-run with -apply to make these changes.
```

## Suspend, not delete

Deleting a Workspace account destroys the mailbox, the Drive files it owns, and
the calendar. Deleting an Entra user recycles it for thirty days and then does
the same.

`-on-deactivate deactivate` is the default and means suspend. Deletion is
available for deployments that genuinely want it, and it is a choice somebody
has to make rather than a default they inherit.

## The safety limit

A run that would deactivate more than **25%** of managed accounts is refused:

```
this would deactivate 60 of 100 managed accounts (60%), over the 25% limit.
That is what a filter matching nothing looks like, and it is indistinguishable
from a company that has genuinely all left. Re-run with -force if it is really
what you want
```

A filter that accidentally matches nothing produces a plan to deprovision
everybody, and that plan is identical to a correct plan for a company that has
genuinely all left. Nothing in the data distinguishes them, so the limit does.

## Accounts we did not create are never touched

A directory always contains accounts this system did not create — service
accounts, contractors, the founder's original login. They are reported as
`unmanaged` and left alone. A sync that removes what it does not recognise is a
sync that removes those.

## Passwords at creation

Both providers require one. A long random password is generated and **discarded
without being recorded**: sign-in happens through Signari, and an account whose
password nobody knows is safer than one with a placeholder somebody reuses
across a tenant.

## What is tested, and what is not

The API shapes are tested against fake Google and Graph servers: the verbs and
fields each provider actually requires (`PUT` with `suspended` for Google,
`PATCH` with `accountEnabled` for Graph), paging across multiple pages, and that
a provider's error message survives into ours.

**Nothing has run against a real Google or Entra tenant.** That needs
credentials nobody should hand to a test suite, and it is listed in
the open-decisions list rather than implied to be done.
