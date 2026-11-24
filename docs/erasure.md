# Erasing a person

## Introduction

A person can ask for their data to be erased, or an organisation can decide to
remove someone for good. [Deactivating](glossary.md#deactivate) them stops them
signing in, but keeps their account and everything Signari holds about them.

Erasing goes further. Signari destroys the key the person's data is encrypted
with, and removes their account, in one transaction. Nobody can undo it.

You erase a person with `signari erase subject`, or through the Admin API. A
person can also erase their own account, unless the organisation has closed
that.

## Erase a person

This command erases one person, and ends their account in the same transaction:

```sh
signari erase subject -subject-id <uuid> -confirm <uuid> -deactivate
```

In this example, `<uuid>` is the person's subject ID, the identifier their
account and their encryption key are kept under. You give it twice, to
`-subject-id` and to `-confirm`. `-deactivate` ends an account that is still
active, as part of the erasure.

Signari erases a person in two parts, in one transaction.

First, it destroys the key their data is encrypted with. Everything sealed with
it becomes permanently unreadable, including in every backup taken before the
erasure, which is the part row deletion cannot give you. Destroying the key this
way is called a "shred".

Second, it removes their account. They are signed out everywhere, and each
application they used is told. Then the account, and every row keyed by it, is
deleted. The address, the username and the names are in the account in the
clear, and a key shred does not reach them.

Notices still waiting to be sent to the person go too. One about a changed
address carries the old address, and there is nobody left to tell.

A person can also erase their own account at `/account/delete`, through the
organisation's [unenrolment flow](flows.md). It is the same erasure, from a
recent sign-in, confirmed by typing their address. It is audited as
`account.deleted`, with one last message to the address. An organisation closes
it with `stages: [deny]`.

Until October 2026, an erasure only destroyed the key and deactivated the
account, so it left all of those behind. A person who had never enrolled a
second factor had no key at all, and was refused as unknown, with nothing
erased.

**It cannot be undone by anyone**, including the people who make Signari. An
erased subject can never hold a key again. `LoadOrCreateSubjectKey` refuses to
mint a replacement, deliberately. Minting one would make new data readable under
the same subject identifier, and quietly undo an erasure somebody is entitled to
rely on.

## The confirmation is the subject ID, not a `-yes`

You repeat the UUID, and that is on purpose. A `-force` or `-yes` flag is
satisfied by muscle memory, and by copying and pasting from a runbook. *Which
subject* is the only mistake this command can make that nobody can reverse.

The account's email address is printed before anything is destroyed, so the
confirmation can be checked against a person rather than against a UUID.

## Why an active account is refused

Erasure removes the account, so it signs the person out of everything they are
using. That is not done to an active account by omission. The command refuses
one unless you say so:

```sh
# either: end the account and erase in one transaction
signari erase subject -subject-id <uuid> -confirm <uuid> -deactivate

# or: deactivate first, then erase — the same thing in two deliberate steps
```

Every session the account holds ends in the same transaction. Before the account
is deleted, each application it signed in to is sent a
[back-channel logout](glossary.md#back-channel-logout) notice.

## A person who never enrolled a second factor

Such a person has no key, because nothing of theirs was sealed. They are erased
all the same. Their account is removed, and they are given a `core.subject_keys`
row already marked erased.

That row is the same evidence a shred leaves, and it makes the engine refuse ever
to mint them a key. Only an identifier with neither a key nor an account is
refused, as unknown.

This is a guard, not a policy. What erasure should *mean* is the administrator's
decision, and there are three defensible answers: immediate, delay-and-notify
like account recovery, or two-person. The engine implements immediate and makes
you state the account's fate. It does not choose the rest for you.

## What survives, and why

The `core.subject_keys` row stays, with `erased_at` set and `wrapped_dek` NULL. A
database constraint enforces that pairing, so a half-erasure cannot commit.

The account does not survive. A test erases a person, and then searches every
text column of every table in `core` for their address, username and names. It
fails on any it finds.

The row that stays is the evidence the erasure happened, and when. A deleted row
proves nothing, and *"we did erase them, but we cannot show you"* is not a
position to be in during an audit.

The audit chain also survives. A shred destroys the subject's key and rewrites no
audit row. Audit rows name people by subject ID only, never by address. So there
is nothing personal in them for a shred to remove, and no link it breaks.

The chain hashes the plaintext `detail`. An earlier version of this page said it
hashed ciphertext, from a `detail_enc` column that nothing ever wrote and that
was dropped in October 2026. Anything personal written into `detail` would
therefore survive a shred, which is why nothing personal is written there.

A test follows a person through the Admin API from creation, through a change of
name and address and deactivation, to erasure. It fails if any of their
identifiers is left in the trail.

## Erasing a subject with no account

This is supported, and it is the reason erasure is keyed on the subject rather
than on the account. A subject key outlives the account it was made for. If the
account is gone and the key is not, the ciphertext it protects is still
readable, and still worth destroying.

## Over the Admin API

The Admin API erases a person with one request, made with a token that holds the
[`subjects:erase` scope](admin-tokens.md#scopes):

```
POST /admin/subjects/{subjectID}/erase
Authorization: Bearer <token with subjects:erase>
Content-Type: application/json

{"confirm_subject_id": "<the same uuid>", "deactivate": true}
```

The confirmation works the same way, and for the same reason. The body must
repeat the identifier in the path, so a request replayed against a different
path erases nothing.

`subjects:erase` is its own scope. It is not folded into `users:write`, because a
token that may rename a person should not thereby be able to destroy one
irreversibly. Most tokens that need the first do not need the second.
