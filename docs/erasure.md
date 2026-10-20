# Erasing a subject

```sh
signari erase subject -subject-id <uuid> -confirm <uuid> -deactivate
```

Signari erases a person in two parts, in one transaction. It destroys the key their
data is encrypted with, so everything sealed with it becomes permanently unreadable,
including in every backup taken before the erasure, which is the part row deletion
cannot give you. And it removes their account: signed out everywhere, each
application they used told, then the account and every row keyed by it deleted.
The address, the username and the names are in the account in the clear, and a
key shred does not reach them.

Until October 2026 an erasure only destroyed the key and deactivated the account,
so it left all of those behind. A person who had never enrolled a second factor had
no key at all, and was refused as unknown, with nothing erased.

**It cannot be undone by anyone**, including us. An erased subject can never hold a
key again: `LoadOrCreateSubjectKey` refuses to mint a replacement, deliberately,
because minting one would make new data readable under the same subject identifier
and quietly undo an erasure somebody is entitled to rely on.

## The confirmation is the subject id, not a `-yes`

You repeat the uuid. That is on purpose: a `-force` or `-yes` flag is satisfied by
muscle memory and by copy-paste from a runbook, and *which subject* is the only
mistake this command can make that nobody can reverse.

The account's email address is printed before anything is destroyed, so the
confirmation can be checked against a person rather than against a uuid.

## Why an active account is refused

Erasure removes the account, so it signs the person out of everything they are
using. That is not done to an active account by omission. The command refuses one
unless you say so:

```sh
# either: end the account and erase in one transaction
signari erase subject -subject-id <uuid> -confirm <uuid> -deactivate

# or: deactivate first, then erase — the same thing in two deliberate steps
```

Every session the account holds ends in the same transaction, and each application
it signed in to is sent a back-channel logout notice, before the account is deleted.

## A person who never enrolled a second factor

They have no key: nothing of theirs was sealed. They are erased all the same, their
account removed, and are given a `core.subject_keys` row already marked erased. That
row is the same evidence a shred leaves, and it makes the engine refuse ever to mint
them a key. Only an identifier with neither a key nor an account is refused, as
unknown.

This is a guard, not a policy. What erasure should *mean* is the operator's
decision, and there are three defensible answers — immediate, delay-and-notify
like account recovery, or two-person. The engine implements immediate and makes
you state the account's fate; it does not choose the rest for you.

## What survives, and why

The `core.subject_keys` row stays, with `erased_at` set and `wrapped_dek` NULL. A
database constraint enforces that pairing, so a half-erasure cannot commit. The
account does not survive. A test erases a person and then searches every text column
of every table in `core` for their address, username and names, and fails on any it
finds.

That row is the evidence the erasure happened and when. A deleted row proves
nothing, and *"we did erase them, we just cannot show you"* is not a position to be
in during an audit.

The audit chain also survives. A shred destroys the subject's key and rewrites no
audit row, and audit rows name people by subject id only, never by address, so
there is nothing personal in them for a shred to remove and no link it breaks.
The chain hashes the plaintext `detail`: an earlier version of this page said it
hashed ciphertext, from a `detail_enc` column that nothing ever wrote and that was
dropped in October 2026. Anything personal written into `detail` would therefore
survive a shred, which is why nothing is. A test follows a person through the
admin API from creation, through a change of name and address and deactivation,
to erasure, and fails if any of their identifiers is left in the trail.

## Erasing a subject with no account

Supported, and the reason erasure is keyed on the subject rather than on the user:
a subject key outlives the account it was made for. If the account is gone and the
key is not, the ciphertext it protects is still readable and still worth
destroying.

## Over the admin API

```
POST /admin/subjects/{subjectID}/erase
Authorization: Bearer <token with subjects:erase>
Content-Type: application/json

{"confirm_subject_id": "<the same uuid>", "deactivate": true}
```

The confirmation works the same way and for the same reason: the body must repeat
the identifier in the path, so a request replayed against a different path erases
nothing.

`subjects:erase` is its own scope. It is not folded into `users:write`, because a
token that may rename a user should not thereby be able to destroy one
irreversibly — and most tokens that need the former do not need the latter.
