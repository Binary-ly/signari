# Provisioning to other services

## Introduction

When Acme hires Ada, she needs an account in the tools her team uses. When she
leaves, those accounts must stop working. Creating and removing accounts in other
systems as people join and leave is called "provisioning".

Signari writes accounts into three kinds of target: any System for Cross-domain
Identity Management ([SCIM](glossary.md#scim)) 2.0 server, Google Workspace, and
Microsoft Entra ID. SCIM is a standard for creating and removing accounts in
other applications. Every change is planned first, and nothing is
sent until you say so.

You register a Google Workspace or Entra target with `signari provision add`, or
through the [Admin API](admin-api.md).

> [!NOTE]
> To provision into a SCIM 2.0 server, see [SCIM provisioning](scim.md).

**Google Workspace and Entra targets are part of Signari, not an add-on.** The
hard part of provisioning is the "reconciliation", which compares what a target
holds with what it should hold, and that was already written for SCIM. Adding two
more targets was implementing one small interface twice.

## Registering

These commands register a Google Workspace target and a Microsoft Entra ID
target:

```sh
# Google Workspace
signari provision add -org <uuid> -slug workspace -kind-outpost google \
  -credentials ./service-account.json \
  -impersonate admin@acme.com -target-domain acme.com

# Microsoft Entra ID
signari provision add -org <uuid> -slug entra -kind-outpost entra \
  -credentials ./entra-credentials.json -target-domain acme.com
```

In this example, `-credentials` is the Google service account's JSON file or the
Entra client credentials. `-impersonate` names the administrator the service
account acts as, and `-target-domain` is the domain new accounts are created
under.

Credentials are sealed with the [root key](glossary.md#root-key). A service
account's JSON file is a credential to somebody's entire directory, and a
database read must not yield one.

The Admin API registers these targets too, at
`POST /admin/organizations/{orgID}/scim-targets`. It takes `"kind": "google"` or
`"entra"`, and the file's contents as `credentials`. See
[the Admin API](admin-api.md).

## Why Google and Entra are not SCIM

Neither Google nor Entra accepts SCIM as a server.

Entra is a SCIM **client**: it pushes accounts out to other systems, and does not
accept pushes in. Google has no SCIM surface at all. Signari writes to both
through their own APIs: the Admin SDK Directory API and Microsoft Graph.

What sits above them is unchanged: one `Provisioner` interface with five
methods, one reconciliation, one deactivation policy and one dry run. A second
sync engine for each target is how "deactivate" comes to mean something slightly
different for Google than it does for everything else.

## It is a dry run until you say otherwise

Without `-apply`, a sync prints what it would do and sends nothing:

```
gw: would create 3, deactivate 0, delete 0, failed 0

Nothing was sent. Re-run with -apply to make these changes.
```

## Suspend, not delete

Deleting a Workspace account destroys the mailbox, the Drive files it owns, and
the calendar. Deleting an Entra account recycles it for thirty days, and then
does the same.

`-on-deactivate deactivate` is the default, and means suspend. Deletion is
available for deployments that genuinely want it. It is a choice somebody has to
make, rather than a default they inherit.

## The safety limit

A run that would deactivate more than **25%** of managed accounts is refused:

```
this would deactivate 60 of 100 managed accounts (60%), over the 25% limit.
That is what a filter matching nothing looks like, and it is indistinguishable
from a company that has genuinely all left. Re-run with -force if it is really
what you want
```

A filter that accidentally matches nothing produces a plan to deprovision
everybody. That plan is identical to a correct plan for a company that has
genuinely all left. Nothing in the data distinguishes them, so the limit does.

## Accounts Signari did not create are never touched

A directory always contains accounts that Signari did not create, such as
service accounts, contractors and the founder's original account. They are
reported as `unmanaged` and left alone. A sync that removes what it does not
recognise is a sync that removes those.

## Passwords at creation

Both providers require a password when an account is created. A long random
password is generated and **discarded without being recorded**. Sign-in happens
through Signari, and an account whose password nobody knows is safer than one
with a placeholder. Somebody would reuse that placeholder across a "tenant", the
provider's word for an organisation's whole directory.

## What is tested, and what is not

The API shapes are tested against fake Google and Graph servers. The tests cover
the verbs and fields each provider actually requires: `PUT` with `suspended` for
Google, and `PATCH` with `accountEnabled` for Graph. They also cover paging
across multiple pages, and check that a provider's error message survives into
ours.

**Nothing has run against a real Google or Entra organisation.** That needs
credentials nobody should hand to a test suite. It is listed in the
open-decisions list, rather than implied to be done.
